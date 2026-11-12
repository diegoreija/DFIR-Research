//! End-to-end CLI tests using synthetic, benign PE bytes. No malware execution.
use std::{fs, path::PathBuf, process::{Command, Output}, time::{SystemTime, UNIX_EPOCH}};
use serde_json::{json,Value};

fn bin() -> &'static str { env!("CARGO_BIN_EXE_keydis-inspector") }
fn temp_path(extension:&str)->PathBuf{
    let nanos=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("kid-cli-{}-{nanos}.{extension}",std::process::id()))
}
fn put_u16(b:&mut[u8],i:usize,v:u16){b[i..i+2].copy_from_slice(&v.to_le_bytes());}
fn put_u32(b:&mut[u8],i:usize,v:u32){b[i..i+4].copy_from_slice(&v.to_le_bytes());}
fn put_u64(b:&mut[u8],i:usize,v:u64){b[i..i+8].copy_from_slice(&v.to_le_bytes());}
fn benign_pe()->Vec<u8>{
    let mut b=vec![0u8;0x400];
    b[0..2].copy_from_slice(b"MZ");
    put_u32(&mut b,0x3c,0x80);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    put_u16(&mut b,0x84,0x8664);
    put_u16(&mut b,0x86,1);
    put_u32(&mut b,0x88,1_760_000_000); // COFF timestamp
    put_u16(&mut b,0x94,0xF0);
    put_u16(&mut b,0x96,0x22);
    let opt=0x98;
    put_u16(&mut b,opt,0x20b);
    put_u32(&mut b,opt+0x10,0x1000);
    put_u32(&mut b,opt+0x14,0x1000);
    put_u64(&mut b,opt+0x18,0x140000000);
    put_u32(&mut b,opt+0x20,0x1000);
    put_u32(&mut b,opt+0x24,0x200);
    put_u32(&mut b,opt+0x38,0x2000);
    put_u32(&mut b,opt+0x3c,0x200);
    put_u16(&mut b,opt+0x44,3);
    put_u32(&mut b,opt+0x6c,16);
    let sec=0x188;
    b[sec..sec+5].copy_from_slice(b".text");
    put_u32(&mut b,sec+8,0x200);
    put_u32(&mut b,sec+12,0x1000);
    put_u32(&mut b,sec+16,0x200);
    put_u32(&mut b,sec+20,0x200);
    put_u32(&mut b,sec+36,0x60000020);
    b[0x200..].fill(0x90);
    b[0x200..0x20A].copy_from_slice(&[0xB8,0x14,0,0,0,0xE8,5,0,0,0]);
    b[0x20F]=0xC3;
    b[0x260..0x278].copy_from_slice(b"https://api.telegram.org");
    b
}
fn invoke(args:&[&str],path:&PathBuf)->Output{
    Command::new(bin()).args(args).arg("--input").arg(path).output().expect("CLI must spawn")
}
fn parse(output:&Output)->Value{
    assert!(output.status.success(),"stdout={} stderr={}",String::from_utf8_lossy(&output.stdout),String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).expect("valid JSON")
}
#[test]
fn worksheet_has_19_fields_and_safe_states(){
    let path=temp_path("exe");fs::write(&path,benign_pe()).unwrap();
    let v=parse(&invoke(&["tasks"],&path));
    assert_eq!(v["tasks"].as_array().unwrap().len(),19);
    assert_eq!(v["tasks"][0]["status"],"verified_file_value");
    assert_eq!(v["tasks"][7]["answer"],"VK_CAPITAL");
    assert_eq!(v["tasks"][16]["status"],"inconclusive");
    fs::remove_file(path).unwrap();
}
#[test]
fn disasm_and_constant_search_are_real(){
    let path=temp_path("exe");fs::write(&path,benign_pe()).unwrap();
    let d=parse(&invoke(&["disasm","--count","2"],&path));
    assert_eq!(d["evidence"][0]["rva"],"0x1000");
    assert_eq!(d["evidence"][1]["rva"],"0x1005");
    let c=parse(&invoke(&["constants","--value","0x14"],&path));
    assert_eq!(c["candidate_matches"],1);
    fs::remove_file(path).unwrap();
}
#[test]
fn decoder_is_recoverable_from_xor_crib(){
    let path=temp_path("bin");
    let crib=b"https://api.telegram.org";
    let encrypted:Vec<u8>=crib.iter().enumerate().map(|(i,&v)|v^b"AB"[i%2]).collect();
    fs::write(&path,encrypted).unwrap();
    let v=parse(&invoke(&["xor-crib","--known","https://api.telegram.org","--max-keylen","2","--show-secrets"],&path));
    assert!(v["candidates"].as_array().unwrap().iter().any(|c|c["xor_key_hex"]=="4142"));
    fs::remove_file(path).unwrap();
}
#[test]
fn non_pe_does_not_fabricate_worksheet(){
    let path=temp_path("bin");fs::write(&path,b"plain text").unwrap();
    let out=invoke(&["tasks"],&path);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("PE"));
    fs::remove_file(path).unwrap();
}
#[test]
fn deep_find_works_without_ghidra_installed(){
    let path=temp_path("json");let report=json!({"schema_version":1,"functions":[
        {"name":"routineA","entry_address":"0x1000","pseudocode":"abc 0x104 here"},
        {"name":"routineB","entry_address":"0x2000","pseudocode":"just nothing"}]});
    fs::write(&path,serde_json::to_vec(&report).unwrap()).unwrap();
    let out=Command::new(bin()).args(["deep-find","--report"]).arg(&path)
        .args(["--contains","0x104"]).output().unwrap();
    let v=parse(&out);assert_eq!(v["matched_functions"],1);
    fs::remove_file(path).unwrap();
}

#[test]
fn new_trace_returns_call_arguments_and_edges(){
    let path=temp_path("exe");fs::write(&path,benign_pe()).unwrap();
    let v=parse(&invoke(&["trace","--max-insns","30","--max-blocks","10"],&path));
    assert_eq!(v["start_rva"],"0x1000");
    assert!(v["call_sites"].as_array().unwrap().len()>=1);
    fs::remove_file(path).unwrap();
}
#[test]
fn generic_capability_command_does_not_hardcode_a_malware_label(){
    let path=temp_path("exe");fs::write(&path,benign_pe()).unwrap();
    let v=parse(&invoke(&["capabilities","--max-functions","10"],&path));
    assert_eq!(v["matched_calls"],0);
    assert!(v["correlations"].as_array().unwrap().is_empty());
    fs::remove_file(path).unwrap();
}
#[test]
fn analyze_now_contains_general_evidence(){
    let path=temp_path("exe");fs::write(&path,benign_pe()).unwrap();
    let v=parse(&invoke(&["analyze"],&path));
    assert!(v["compiler_evidence"].is_object());
    assert!(v["capability_evidence"].is_object());
    assert!(v["inventory"].is_object());
    fs::remove_file(path).unwrap();
}

#[test]
fn decoded_config_is_evidence_and_does_not_expose_secrets(){
    let path=temp_path("bin");
    let token="123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
    // Known test token shape only, not a credential. Base64 string generated in this test.
    let data=base64::Engine::encode(&base64::engine::general_purpose::STANDARD,token);
    fs::write(&path,data).unwrap();
    let v=parse(&invoke(&["decode-config","--limit","10"],&path));
    assert!(v["findings"].as_array().unwrap().iter().any(|f|f["indicator_type"]=="possible_bot_token"
        && f["decoded_preview"]=="[REDACTED: possible secret]"));
    fs::remove_file(path).unwrap();
}
