//! Bounded, path-sensitive x86/x64 control-flow exploration and intraprocedural constant tracking.
//! These are candidate observations, never proof of runtime behavior.
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const EXECUTE: u32 = 0x2000_0000;
const MAX_STATES: usize = 20_000;
const MAX_SECTION_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone,Debug,PartialEq,Eq,PartialOrd,Ord)]
enum Symbol {
    Constant(u64),
    Address(u64),
    LoadedFrom(u64),
}
impl Symbol {
    fn describe(&self)->Value{
        match self {
            Self::Constant(v)=>json!({"type":"constant","value":format!("0x{v:X}")}),
            Self::Address(v)=>json!({"type":"address","value":format!("0x{v:X}")}),
            Self::LoadedFrom(v)=>json!({"type":"loaded_from_memory","address":format!("0x{v:X}")}),
        }
    }
    fn known(&self)->Option<u64> {
        match self {Self::Constant(v)|Self::Address(v)=>Some(*v),Self::LoadedFrom(_)=>None}
    }
}

#[derive(Clone,Default,Debug,PartialEq,Eq,PartialOrd,Ord)]
struct State {
    regs: BTreeMap<&'static str,Symbol>,
    pushed: Vec<Option<Symbol>>,
}
fn reg_name(reg:Register)->Option<&'static str>{
    let r=format!("{reg:?}");
    Some(match r.as_str(){
        "RAX"|"EAX"|"AX"|"AL"|"AH"=>"rax",
        "RBX"|"EBX"|"BX"|"BL"|"BH"=>"rbx",
        "RCX"|"ECX"|"CX"|"CL"|"CH"=>"rcx",
        "RDX"|"EDX"|"DX"|"DL"|"DH"=>"rdx",
        "RSI"|"ESI"|"SI"|"SIL"=>"rsi",
        "RDI"|"EDI"|"DI"|"DIL"=>"rdi",
        "RBP"|"EBP"|"BP"|"BPL"=>"rbp",
        "RSP"|"ESP"|"SP"|"SPL"=>"rsp",
        "R8"|"R8D"|"R8W"|"R8L"=>"r8",
        "R9"|"R9D"|"R9W"|"R9L"=>"r9",
        "R10"|"R10D"|"R10W"|"R10L"=>"r10",
        "R11"|"R11D"|"R11W"|"R11L"=>"r11",
        "R12"|"R12D"|"R12W"|"R12L"=>"r12",
        "R13"|"R13D"|"R13W"|"R13L"=>"r13",
        "R14"|"R14D"|"R14W"|"R14L"=>"r14",
        "R15"|"R15D"|"R15W"|"R15L"=>"r15",
        _=>return None,
    })
}
fn reg_symbol(s:&State,reg:Register)->Option<Symbol>{
    reg_name(reg).and_then(|n|s.regs.get(n).cloned())
}
fn op_symbol(ins:&Instruction,index:u32,s:&State)->Option<Symbol>{
    match ins.op_kind(index){
        OpKind::Register=>reg_symbol(s,ins.op_register(index)),
        OpKind::Immediate8|OpKind::Immediate16|OpKind::Immediate32|OpKind::Immediate64|
        OpKind::Immediate8to16|OpKind::Immediate8to32|OpKind::Immediate8to64|OpKind::Immediate32to64
            =>ins.try_immediate(index).ok().map(Symbol::Constant),
        OpKind::Memory=>effective_address(ins,s).map(Symbol::LoadedFrom),
        _=>None
    }
}
fn effective_address(ins:&Instruction,s:&State)->Option<u64>{
    if ins.is_ip_rel_memory_operand(){return Some(ins.ip_rel_memory_address())}
    let base=ins.memory_base();
    let index=ins.memory_index();
    // The displacement is sign extended by iced-x86 for 64-bit addressing.
    let d=ins.memory_displacement64();
    let b=if base==Register::None{0}else{reg_symbol(s,base)?.known()?};
    let ix=if index==Register::None{0}else{
        reg_symbol(s,index)?.known()?.wrapping_mul(ins.memory_index_scale() as u64)
    };
    Some(b.wrapping_add(ix).wrapping_add(d))
}
fn branch_target(ins:&Instruction)->Option<u64>{
    match ins.op0_kind(){
        OpKind::NearBranch16|OpKind::NearBranch32|OpKind::NearBranch64=>Some(ins.near_branch_target()),
        _=>None
    }
}
fn rva_to_file(pe:&PE<'_>,bytes:&[u8],rva:u64)->Option<usize>{
    for sec in &pe.sections{
        if sec.characteristics & EXECUTE == 0 {continue}
        let begin=sec.virtual_address as u64;
        let raw=sec.size_of_raw_data as u64;
        if rva>=begin && rva<begin.checked_add(raw)? {
            let delta=usize::try_from(rva-begin).ok()?;
            let file=(sec.pointer_to_raw_data as usize).checked_add(delta)?;
            if file < bytes.len(){return Some(file)}
        }
    }
    None
}
fn decode(pe:&PE<'_>,bytes:&[u8],rva:u64)->Option<(Instruction,usize)>{
    let pos=rva_to_file(pe,bytes,rva)?;
    let (end,ip)=pe.sections.iter().find_map(|s|{
        if s.characteristics&EXECUTE==0{return None}
        let start=s.virtual_address as u64;
        let end=start.checked_add(s.size_of_raw_data as u64)?;
        if rva<start||rva>=end{return None}
        let remain=usize::try_from(end-rva).ok()?;
        let bound=pos.checked_add(remain.min(MAX_SECTION_BYTES))?.min(bytes.len());
        let ip=(pe.image_base as u64).checked_add(rva)?;
        Some((bound,ip))
    })?;
    if end<=pos{return None}
    let mut decoder=Decoder::with_ip(if pe.is_64{64}else{32},
        &bytes[pos..end],ip,DecoderOptions::NONE);
    let i=decoder.decode();
    if i.is_invalid(){None}else{Some((i,pos))}
}
fn import_slot(pe:&PE<'_>,address:u64)->Option<(String,String)>{
    let base=pe.image_base as u64;
    pe.imports.iter()
        .find(|i|base.checked_add(i.rva as u64)==Some(address))
        .map(|i|(i.dll.to_owned(),i.name.to_string()))
}
fn call_target(ins:&Instruction,s:&State)->Option<(u64,&'static str)>{
    if let Some(va)=branch_target(ins){return Some((va,"direct_call"))}
    if ins.op0_kind()==OpKind::Memory{
        return effective_address(ins,s).map(|va|(va,"indirect_memory_slot"));
    }
    if ins.op0_kind()==OpKind::Register{
        return match reg_symbol(s,ins.op0_register()){
            Some(Symbol::LoadedFrom(va))=>Some((va,"register_loaded_from_memory")),
            Some(Symbol::Address(va))|Some(Symbol::Constant(va))=>Some((va,"register_target_candidate")),
            _=>None,
        };
    }
    None
}
fn track_instruction(ins:&Instruction,state:&mut State)->Option<Value>{
    let kind=ins.mnemonic();
    let dest=if ins.op0_kind()==OpKind::Register{reg_name(ins.op0_register())}else{None};
    let before=dest.and_then(|r|state.regs.get(r).cloned());
    let source=if ins.op_count()>1{op_symbol(ins,1,state)}else{None};
    let mut observation=None;
    match kind{
        Mnemonic::Mov|Mnemonic::Movzx|Mnemonic::Movsxd|Mnemonic::Movsx => {
            if let Some(r)=dest{
                if let Some(sym)=source{state.regs.insert(r,sym);}
                else{state.regs.remove(r);}
            }else if ins.op0_kind()==OpKind::Memory {
                let displacement=if ins.memory_displ_size()>0 {
                    Some(format!("0x{:X}",ins.memory_displacement64()))
                }else{None};
                observation=Some(json!({"type":"memory_write","rva":format!("0x{:X}",ins.ip()),
                    "base_register":format!("{:?}",ins.memory_base()),
                    "displacement":displacement,
                    "resolved_address":effective_address(ins,state).map(|a|format!("0x{a:X}")),
                    "source":source.map(|v|v.describe()),
                    "instruction":format!("{ins:?}"),
                    "evidence":"decoded instruction; memory destination and source tracked heuristically"}));
            }
        },
        Mnemonic::Lea => {
            if let Some(r)=dest{
                if let Some(va)=effective_address(ins,state){
                    state.regs.insert(r,Symbol::Address(va));
                }else{state.regs.remove(r);}
            }
        },
        Mnemonic::Xor if ins.op0_kind()==OpKind::Register => {
            if let Some(r)=dest {
                let sym=if ins.op1_kind()==OpKind::Register
                    &&reg_name(ins.op0_register())==reg_name(ins.op1_register()){
                        Some(Symbol::Constant(0))
                    }else{match (before,source){
                        (Some(a),Some(b))=>a.known().zip(b.known()).map(|(x,y)|Symbol::Constant(x^y)),
                        _=>None
                    }};
                if let Some(v)=sym{state.regs.insert(r,v);}
                else{state.regs.remove(r);}
            }
        },
        Mnemonic::Add|Mnemonic::Sub|Mnemonic::And|Mnemonic::Or|
        Mnemonic::Rol|Mnemonic::Ror if dest.is_some() => {
            let r=dest.unwrap();
            let value=before.and_then(|x|x.known()).zip(source.and_then(|x|x.known()))
                .map(|(x,y)|match kind{
                    Mnemonic::Add=>x.wrapping_add(y),Mnemonic::Sub=>x.wrapping_sub(y),
                    Mnemonic::And=>x&y,Mnemonic::Or=>x|y,
                    Mnemonic::Rol=>x.rotate_left((y&63)as u32),
                    Mnemonic::Ror=>x.rotate_right((y&63)as u32),_=>unreachable!()});
            if let Some(v)=value{state.regs.insert(r,Symbol::Constant(v));}
            else{state.regs.remove(r);}
        },
        Mnemonic::Push=>{
            if state.pushed.len()<12 {
                state.pushed.push(op_symbol(ins,0,state));
            }
        },
        Mnemonic::Pop=>{
            let value=state.pushed.pop().flatten();
            if let Some(r)=dest{
                if let Some(v)=value{state.regs.insert(r,v);}else{state.regs.remove(r);}
            }
        },
        Mnemonic::Cmp|Mnemonic::Test=>{
            let a=op_symbol(ins,0,state);
            let b=if ins.op_count()>1{op_symbol(ins,1,state)}else{None};
            if a.is_some()||b.is_some(){
                observation=Some(json!({"type":"condition","rva":format!("0x{:X}",ins.ip()),
                    "mnemonic":format!("{kind:?}"),
                    "left":a.map(|v|v.describe()),
                    "right":b.map(|v|v.describe()),
                    "status":"operand_evidence_not_branch_outcome"}));
            }
        },
        Mnemonic::Nop|Mnemonic::Int3=>{},
        _=>{
            // Do not retain stale values through instructions that might overwrite a register.
            if ins.flow_control()==FlowControl::Next {
                if let Some(r)=dest{state.regs.remove(r);}
            }
        },
    }
    observation
}
fn call_evidence(pe:&PE<'_>,ins:&Instruction,s:&State)->Value{
    let target=call_target(ins,s);
    let matched=target.and_then(|(va,_)|import_slot(pe,va));
    let mut args=Vec::new();
    if pe.is_64{
        for (index,name) in ["rcx","rdx","r8","r9"].iter().enumerate(){
            args.push(json!({"position":index+1,"register":name,
                "value":s.regs.get(name).map(|v|v.describe())}));
        }
    }else{
        for (index,value) in s.pushed.iter().rev().take(8).enumerate(){
            args.push(json!({"position":index+1,"value":value.as_ref().map(|v|v.describe())}));
        }
    }
    json!({"callsite_va":format!("0x{:X}",ins.ip()),
        "callsite_rva":format!("0x{:X}",ins.ip()-(pe.image_base as u64)),
        "target":target.map(|(a,t)|json!({"address":format!("0x{a:X}"),"kind":t})),
        "imported_api":matched.map(|(dll,name)|json!({"dll":dll,"name":name})),
        "argument_candidates":args,
        "confidence":"static_intra_basic_block_tracking",
        "limitations":"Arguments can be overwritten on alternative paths; stack layout and interprocedural effects are not fully modeled"})
}
fn clobber_after_call(s:&mut State,is64:bool){
    for name in if is64{
        &["rax","rcx","rdx","r8","r9","r10","r11"][..]
    }else{
        &["rax","rcx","rdx"][..]
    }{s.regs.remove(name);}
    s.pushed.clear();
}
fn key(state:&State,rva:u64)->String{
    // Bounded path sensitivity; equivalent abstract register states converge.
    format!("{rva:x}:{state:?}")
}

pub fn trace(bytes:&[u8],start_rva:Option<u64>,max_insns:usize,max_blocks:usize)->Result<Value,String>{
    if max_insns==0||max_insns>50_000{return Err("--max-insns must be 1..=50000".into())}
    if max_blocks==0||max_blocks>5000{return Err("--max-blocks must be 1..=5000".into())}
    let pe=PE::parse(bytes).map_err(|e|format!("Not a valid PE: {e}"))?;
    let entry=start_rva.unwrap_or(pe.entry as u64);
    if rva_to_file(&pe,bytes,entry).is_none(){
        return Err(format!("Start RVA 0x{entry:X} is not in an executable section"))}
    let mut queue=VecDeque::new();
    queue.push_back((entry,State::default()));
    let mut seen=BTreeSet::new();
    let mut blocks=BTreeSet::new();
    let mut edges=BTreeSet::new();
    let mut observations=BTreeMap::<String,Value>::new();
    let mut callsites=BTreeMap::<String,Value>::new();
    let mut visited_insns=0usize;
    let mut stopped=false;
    while let Some((block_start,mut state))=queue.pop_front(){
        if seen.len()>=MAX_STATES||blocks.len()>=max_blocks||visited_insns>=max_insns{
            stopped=true;break;
        }
        if !seen.insert(key(&state,block_start)){continue}
        blocks.insert(block_start);
        let mut rva=block_start;
        for _ in 0..max_insns {
            if visited_insns>=max_insns{stopped=true;break}
            let Some((ins,_))=decode(&pe,bytes,rva) else{break};
            visited_insns+=1;
            let next=rva.checked_add(ins.len()as u64).ok_or("Instruction address overflow")?;
            let flow=ins.flow_control();
            let va=format!("0x{:X}",ins.ip());
            if flow==FlowControl::Call||flow==FlowControl::IndirectCall{
                callsites.insert(va,call_evidence(&pe,&ins,&state));
                clobber_after_call(&mut state,pe.is_64);
                if rva_to_file(&pe,bytes,next).is_none(){break}
                rva=next;continue
            }
            if let Some(v)=track_instruction(&ins,&mut state){
                observations.insert(format!("0x{:X}:{}",ins.ip(),v["type"].as_str().unwrap_or("?")),v);
            }
            if flow==FlowControl::ConditionalBranch{
                if let Some(target_va)=branch_target(&ins){
                    if let Some(target)=target_va.checked_sub(pe.image_base as u64){
                        if rva_to_file(&pe,bytes,target).is_some(){
                            edges.insert((rva,target,"conditional_true"));
                            queue.push_back((target,state.clone()));
                        }
                    }
                }
                if rva_to_file(&pe,bytes,next).is_some(){
                    edges.insert((rva,next,"conditional_false"));
                    queue.push_back((next,state));
                }
                break
            }
            if flow==FlowControl::UnconditionalBranch{
                if let Some(target_va)=branch_target(&ins){
                    if let Some(target)=target_va.checked_sub(pe.image_base as u64){
                        if rva_to_file(&pe,bytes,target).is_some(){
                            edges.insert((rva,target,"jump"));
                            queue.push_back((target,state));
                        }
                    }
                }
                break
            }
            if flow!=FlowControl::Next{break}
            if rva_to_file(&pe,bytes,next).is_none(){break}
            rva=next;
        }
        if stopped{break}
    }
    Ok(json!({
        "architecture":if pe.is_64{"x64"}else{"x86"},
        "start_rva":format!("0x{entry:X}"),
        "max_insns":max_insns,"max_blocks":max_blocks,
        "instructions_processed":visited_insns,"unique_blocks":blocks.len(),
        "path_states_visited":seen.len(),"analysis_truncated":stopped,
        "block_starts":blocks.iter().take(300).map(|x|format!("0x{x:X}")).collect::<Vec<_>>(),
        "edges":edges.iter().take(1000).map(|(src,dst,kind)|json!({
            "from_rva":format!("0x{src:X}"),"to_rva":format!("0x{dst:X}"),"type":kind
        })).collect::<Vec<_>>(),
        "call_sites":callsites.values().take(2000).cloned().collect::<Vec<_>>(),
        "instruction_evidence":observations.values().take(2000).cloned().collect::<Vec<_>>(),
        "limitations":["Intraprocedural and bounded; calls are not followed",
            "Indirect branches are not recovered; obfuscated instructions may be missed",
            "Register constants are approximate; memory loads are not dereferenced except to resolve IAT addresses",
            "A resolved API call and its argument candidates are evidence, not confirmed malware behavior",
            "Exploration begins at one RVA; analyze other function RVAs separately"]
    }))
}

#[cfg(test)]
mod tests{
    use super::*;
    fn put_u16(b:&mut[u8],i:usize,v:u16){b[i..i+2].copy_from_slice(&v.to_le_bytes());}
    fn put_u32(b:&mut[u8],i:usize,v:u32){b[i..i+4].copy_from_slice(&v.to_le_bytes());}
    fn put_u64(b:&mut[u8],i:usize,v:u64){b[i..i+8].copy_from_slice(&v.to_le_bytes());}
    fn fixture(code:&[u8])->Vec<u8>{
        let mut b=vec![0u8;0x600];
        b[0..2].copy_from_slice(b"MZ");put_u32(&mut b,0x3c,0x80);
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        put_u16(&mut b,0x84,0x8664);put_u16(&mut b,0x86,1);
        put_u16(&mut b,0x94,0xF0);put_u16(&mut b,0x96,0x22);
        let opt=0x98;put_u16(&mut b,opt,0x20b);
        put_u32(&mut b,opt+0x10,0x1000);put_u32(&mut b,opt+0x14,0x1000);
        put_u64(&mut b,opt+0x18,0x140000000);put_u32(&mut b,opt+0x20,0x1000);
        put_u32(&mut b,opt+0x24,0x200);put_u32(&mut b,opt+0x38,0x2000);
        put_u32(&mut b,opt+0x3c,0x200);put_u16(&mut b,opt+0x44,3);
        put_u32(&mut b,opt+0x6c,16);
        let sec=0x188;b[sec..sec+5].copy_from_slice(b".text");
        put_u32(&mut b,sec+8,0x400);put_u32(&mut b,sec+12,0x1000);
        put_u32(&mut b,sec+16,0x400);put_u32(&mut b,sec+20,0x200);
        put_u32(&mut b,sec+36,0x60000020);
        b[0x200..].fill(0xCC);
        b[0x200..0x200+code.len()].copy_from_slice(code);
        b
    }
    #[test]
    fn register_propagation_handles_xor_and_arithmetic(){
        let mut decoder=Decoder::with_ip(64,&[
            0xB9,0x14,0,0,0,      // mov ecx,14h
            0x83,0xF1,0x24,       // xor ecx,24h
            0x83,0xC1,0x02,       // add ecx,2
        ],0x140001000,DecoderOptions::NONE);
        let mut s=State::default();
        for _ in 0..3{track_instruction(&decoder.decode(),&mut s);}
        assert_eq!(s.regs.get("rcx"),Some(&Symbol::Constant(0x32)));
    }
    #[test]
    fn finds_direct_call_and_tracked_argument(){
        // mov ecx,14h; call +0; ret
        let b=fixture(&[0xB9,0x14,0,0,0,0xE8,0,0,0,0,0xC3]);
        let result=trace(&b,None,20,10).unwrap();
        assert_eq!(result["call_sites"].as_array().unwrap().len(),1);
        assert_eq!(result["call_sites"][0]["argument_candidates"][0]["value"]["value"],"0x14");
    }
    #[test]
    fn follows_both_conditional_edges(){
        // cmp eax,14h; je +2; nop; ret; nop; ret
        let b=fixture(&[0x83,0xF8,0x14,0x74,0x02,0x90,0xC3,0x90,0xC3]);
        let result=trace(&b,None,50,10).unwrap();
        assert_eq!(result["edges"].as_array().unwrap().len(),2);
        assert!(result["unique_blocks"].as_u64().unwrap()>=3);
    }
    #[test]
    fn rejects_non_pe_and_bad_bounds(){
        assert!(trace(b"not PE",None,100,10).is_err());
        assert!(trace(&fixture(&[0xC3]),None,0,10).is_err());
    }
}
