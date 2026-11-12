//! Conservative PE disassembly helpers. Results are evidence candidates, not proven behavior.
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, OpKind};
use serde_json::{json, Value};
use std::collections::BTreeSet;

const MAX_SCAN_INSTRUCTIONS: usize = 300_000;
const MAX_SECTION_BYTES: usize = 8 * 1024 * 1024;
const EXECUTABLE: u32 = 0x2000_0000;

fn pe(bytes: &[u8]) -> Result<PE<'_>, String> {
    PE::parse(bytes).map_err(|e|format!("PE parsing failed: {e}"))
}

fn bitness(p: &PE<'_>) -> u32 { if p.is_64 {64} else {32} }

fn entry_rva(p:&PE<'_>)->u64 { p.entry as u64 }

/// Only maps backed bytes; virtual zero-fill is deliberately excluded.
fn raw_at_rva(p: &PE<'_>, bytes:&[u8], rva:u64, executable_only:bool) -> Option<(usize,usize)> {
    for s in &p.sections {
        if executable_only && s.characteristics & EXECUTABLE == 0 {continue}
        let start=s.virtual_address as u64;
        let raw_size=s.size_of_raw_data as u64;
        let end=start.checked_add(raw_size)?;
        if rva>=start && rva<end {
            let delta=usize::try_from(rva-start).ok()?;
            let offset=(s.pointer_to_raw_data as usize).checked_add(delta)?;
            if offset>=bytes.len(){return None}
            let available=bytes.len().saturating_sub(offset).min(raw_size as usize-delta);
            return Some((offset,available));
        }
    }
    None
}

fn fmt_instruction(instr:&Instruction)->String{
    let mut formatter=IntelFormatter::new();
    let mut text=String::new();
    formatter.format(instr,&mut text);
    text
}

fn branch_target(i:&Instruction)->Option<u64>{
    match i.op0_kind(){
        OpKind::NearBranch16|OpKind::NearBranch32|OpKind::NearBranch64=>Some(i.near_branch_target()),
        _=>None
    }
}

fn row(instr:&Instruction, image_base:u64, file_offset:usize)->Value{
    let va=instr.ip();
    let rva=va.checked_sub(image_base);
    json!({"rva":rva.map(|x|format!("0x{x:X}")),
           "va":format!("0x{va:X}"),"file_offset":format!("0x{file_offset:X}"),
           "bytes_length":instr.len(),
           "instruction":fmt_instruction(instr),
           "flow":format!("{:?}",instr.flow_control()),
           "direct_branch_target_va":branch_target(instr).map(|t|format!("0x{t:X}")),
           "rip_relative_memory_va":if instr.is_ip_rel_memory_operand(){Some(format!("0x{:X}",instr.ip_rel_memory_address()))}else{None}})
}

pub fn disasm(bytes:&[u8],rva:Option<u64>,count:usize)->Result<Value,String>{
    let p=pe(bytes)?;
    let start=rva.unwrap_or_else(||entry_rva(&p));
    let (offset,available)=raw_at_rva(&p,bytes,start,true).ok_or("RVA not backed by an executable PE section")?;
    let take=available.min(MAX_SECTION_BYTES);
    let ip=(p.image_base as u64).checked_add(start).ok_or("VA overflow")?;
    let mut dec=Decoder::with_ip(bitness(&p),&bytes[offset..offset+take],ip,DecoderOptions::NONE);
    let mut rows=Vec::new();
    while dec.can_decode()&&rows.len()<count.min(500){
        let at=offset+dec.position();
        let ins=dec.decode();
        if ins.is_invalid(){break}
        rows.push(row(&ins,(p.image_base as u64),at));
    }
    Ok(json!({"starting_rva":format!("0x{start:X}"),
              "image_base":format!("0x{:X}",(p.image_base as u64)),
              "architecture":bitness(&p),
              "evidence":rows,
              "limitations":"Linear disassembly only; instructions may contain inline data, and no function semantics are inferred"}))
}

fn walk_exec<F>(bytes:&[u8],p:&PE<'_>,mut visit:F)
where F:FnMut(&Instruction,usize)->bool{
    let mut visited=0usize;
    for sec in &p.sections{
        if sec.characteristics&EXECUTABLE==0{continue}
        let off=sec.pointer_to_raw_data as usize;
        if off>=bytes.len(){continue}
        let len=(sec.size_of_raw_data as usize).min(MAX_SECTION_BYTES).min(bytes.len()-off);
        let Some(ip)=(p.image_base as u64).checked_add(sec.virtual_address as u64) else{continue};
        let mut dec=Decoder::with_ip(bitness(p),&bytes[off..off+len],ip,DecoderOptions::NONE);
        while dec.can_decode()&&visited<MAX_SCAN_INSTRUCTIONS{
            let at=off+dec.position();
            let ins=dec.decode();
            visited+=1;
            if ins.is_invalid(){continue}
            if !visit(&ins,at){return}
        }
    }
}

pub fn function_candidates(bytes:&[u8],limit:usize)->Result<Value,String>{
    let p=pe(bytes)?;
    let mut found=BTreeSet::new();
    found.insert(entry_rva(&p));
    walk_exec(bytes,&p,|ins,_|{
        if ins.flow_control()==FlowControl::Call{
            if let Some(target)=branch_target(ins){
                if let Some(rva)=target.checked_sub((p.image_base as u64)){
                    if raw_at_rva(&p,bytes,rva,true).is_some(){found.insert(rva);}
                }
            }
        }
        found.len()<MAX_SCAN_INSTRUCTIONS
    });
    let total=found.len();
    let results:Vec<Value>=found.into_iter().take(limit.min(500)).map(|rva|
        json!({"rva":format!("0x{rva:X}"),
               "kind":if rva==entry_rva(&p){"entrypoint"}else{"direct_call_target"},
               "confidence":if rva==entry_rva(&p){"high"}else{"low"},
               "note":"Heuristic function start candidate; bounds and parameters not proven"})).collect();
    Ok(json!({"candidates":results,"total_candidates":total,"method":"PE entrypoint + direct call targets in executable sections"}))
}

pub fn xrefs(bytes:&[u8],target_rva:Option<u64>,api:Option<&str>,limit:usize)->Result<Value,String>{
    let p=pe(bytes)?;
    if target_rva.is_none()&&api.is_none(){return Err("Use --target-rva or --api".into())}
    let mut targets=Vec::<(u64,String)>::new();
    if let Some(rva)=target_rva{targets.push(((p.image_base as u64).checked_add(rva).ok_or("VA overflow")?,format!("RVA 0x{rva:X}")));}
    if let Some(name)=api {
        for i in &p.imports{
            if i.name.eq_ignore_ascii_case(name){
                targets.push(((p.image_base as u64).checked_add(i.rva as u64).ok_or("IAT VA overflow")?,format!("{}!{}",i.dll,i.name)));
            }
        }
        if targets.is_empty(){return Err(format!("API '{name}' not found in PE import table; dynamically resolved calls are not yet tracked"));}
    }
    let mut results=Vec::new();
    walk_exec(bytes,&p,|ins,offset|{
        let direct=branch_target(ins);
        let indirect=if ins.is_ip_rel_memory_operand(){Some(ins.ip_rel_memory_address())}else{None};
        for (dest,label) in &targets{
            if direct==Some(*dest)||indirect==Some(*dest){
                results.push(json!({"target":label,"reference_kind":if direct==Some(*dest){"direct_branch"}else{"ip_relative_memory"},
                  "evidence":row(ins,(p.image_base as u64),offset)}));
                break
            }
        }
        results.len()<limit.min(500)
    });
    Ok(json!({"references":results,"candidate_matches":results.len(),
      "limitations":"Linear scan of executable sections; indirect register calls and dynamic API resolution are not recovered"}))
}

pub fn constants(bytes:&[u8],value:Option<u64>,mnemonic:Option<&str>,limit:usize)->Result<Value,String>{
    let p=pe(bytes)?;
    let mut results=Vec::new();
    walk_exec(bytes,&p,|ins,offset|{
        if let Some(m)=mnemonic{
            if !format!("{:?}",ins.mnemonic()).eq_ignore_ascii_case(m){return true}
        }
        let immediate:Vec<u64>=(0..ins.op_count()).filter_map(|n|ins.try_immediate(n).ok()).collect();
        let mem=if ins.memory_displ_size()>0{Some(ins.memory_displacement64())}else{None};
        if value.is_some_and(|v|!immediate.contains(&v)&&mem!=Some(v)){return true}
        if immediate.is_empty()&&mem.is_none(){return true}
        results.push(json!({"immediates":immediate.iter().map(|v|format!("0x{v:X}")).collect::<Vec<_>>(),
             "memory_displacement":mem.map(|v|format!("0x{v:X}")),
             "evidence":row(ins,(p.image_base as u64),offset)}));
        results.len()<limit.min(500)
    });
    Ok(json!({"matches":results,"candidate_matches":results.len(),
       "limitations":"Raw decoded operands; memory displacement may be absolute or relative; XOR is not necessarily encryption"}))
}

pub fn compiler(bytes:&[u8])->Result<Value,String>{
    let p=pe(bytes)?;
    let e_lfanew=if bytes.len()>=0x40{u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize}else{0};
    let dos_end=e_lfanew.min(bytes.len());
    let has_rich=dos_end>0x40 && bytes[0x40..dos_end].windows(4).any(|x|x==b"Rich");
    let import_dlls:Vec<String>=p.imports.iter().map(|i|i.dll.to_ascii_lowercase()).collect();
    let msvc_runtime=import_dlls.iter().any(|s|s.contains("vcruntime")||s.contains("msvcp"));
    let mut observations=Vec::new();
    if has_rich{observations.push("Rich signature in DOS stub (suggests Microsoft linker toolchain)");}
    if msvc_runtime{observations.push("MSVC runtime DLL import (does not prove compiler identity)");}
    if bytes.windows(12).any(|s|s==b"Go build ID:"){observations.push("Go build ID marker");}
    Ok(json!({"compiler":"INCONCLUSIVE","observations":observations,
      "note":"Metadata heuristics only; compiler attribution needs multiple corroborating artifacts"}))
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn decodes_xor_and_relative_call(){
        let bytes=[0x31,0xC0,0xE8,0x02,0,0,0,0x90,0x90,0xC3];
        let mut dec=Decoder::with_ip(64,&bytes,0x140001000,DecoderOptions::NONE);
        let first=dec.decode();
        assert_eq!(format!("{:?}",first.mnemonic()),"Xor");
        let call=dec.decode();
        assert_eq!(call.flow_control(),FlowControl::Call);
        assert_eq!(branch_target(&call),Some(0x140001009));
    }
    #[test]
    fn immediate_values_are_inspectable(){
        let mut decoder=Decoder::with_ip(64,&[0xB8,0x14,0,0,0],0,DecoderOptions::NONE);
        let inst=decoder.decode();
        assert_eq!(inst.try_immediate(1).unwrap(),0x14);
    }
    #[test]
    fn non_pe_is_rejected(){
        assert!(disasm(b"test",None,5).is_err());
    }
}
