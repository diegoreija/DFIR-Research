//! Static evidence inventory and evidence-backed task worksheet.
//! Values marked "candidate" are not answers confirmed from execution paths.
use chrono::{TimeZone,Utc};
use goblin::pe::PE;
use regex::Regex;
use serde_json::{json,Value};
use sha2::{Sha256,Digest};
use std::collections::BTreeSet;

const MAX_SCAN:usize=32*1024*1024;
const MAX_FINDINGS:usize=100;

#[derive(Debug,Clone)]
pub struct TextEvidence{
    pub offset:usize,
    pub encoding:&'static str,
    pub text:String,
}

pub fn extract_text(bytes:&[u8])->Vec<TextEvidence>{
    let bytes=&bytes[..bytes.len().min(MAX_SCAN)];
    let mut out=Vec::new();
    let mut i=0;
    while i<bytes.len(){
        if (32..=126).contains(&bytes[i]) {
            let start=i;
            while i<bytes.len()&&(32..=126).contains(&bytes[i]){i+=1}
            if i-start>=4 && i-start<=4096 {
                out.push(TextEvidence{offset:start,encoding:"ascii",
                    text:String::from_utf8_lossy(&bytes[start..i]).into_owned()});
            }
        }else{i+=1}
    }
    i=0;
    while i+1<bytes.len(){
        if (32..=126).contains(&bytes[i])&&bytes[i+1]==0 {
            let start=i;
            let mut s=String::new();
            while i+1<bytes.len()&&(32..=126).contains(&bytes[i])&&bytes[i+1]==0 {
                s.push(bytes[i] as char); i+=2;
            }
            if s.len()>=4&&s.len()<=4096 {
                out.push(TextEvidence{offset:start,encoding:"utf16le",text:s});
            }
        }else{i+=1}
    }
    out.sort_by_key(|x|x.offset);out
}

pub fn urls(strings:&[TextEvidence])->Vec<Value>{
    let re=Regex::new(r#"(?i)https?://[a-z0-9][a-z0-9._:/?&=%#@+~-]*"#).unwrap();
    let mut seen=BTreeSet::new();
    let mut findings=Vec::new();
    for item in strings {
        for m in re.find_iter(&item.text){
            let value=m.as_str();
            if seen.insert((item.offset+m.start(),value.to_string())){
                findings.push(json!({"value":value,
                    "file_offset":format!("0x{:X}",item.offset+m.start()),
                    "encoding":item.encoding,"confidence":"candidate"}));
                if findings.len()>=MAX_FINDINGS{return findings}
            }
        }
    }
    findings
}

fn token_hits(strings:&[TextEvidence],show_secrets:bool)->Vec<Value>{
    let tg=Regex::new(r"\b[0-9]{6,12}:[A-Za-z0-9_-]{30,60}\b").unwrap();
    let discord=Regex::new(r"\bmfa\.[A-Za-z0-9_-]{20,}\b").unwrap();
    let mut results=Vec::new();
    for item in strings{
        for (platform,re) in [("telegram_bot",&tg),("discord_user",&discord)]{
            for m in re.find_iter(&item.text){
                results.push(json!({
                    "platform":platform,
                    "file_offset":format!("0x{:X}",item.offset+m.start()),
                    "encoding":item.encoding,
                    "token":if show_secrets{m.as_str().to_string()}else{"[REDACTED]".into()},
                    "length":m.as_str().len(),
                    "status":"candidate_plaintext_not_verified_used"}));
                if results.len()>=MAX_FINDINGS{return results}
            }
        }
    }
    results
}

fn import_names(pe:&PE<'_>)->Vec<String>{
    pe.imports.iter().map(|i|i.name.to_string()).collect()
}

fn evidence_imports(pe:&PE<'_>,patterns:&[&str])->Vec<Value>{
    pe.imports.iter()
        .filter(|i|{
            let name=i.name.to_ascii_lowercase();
            patterns.iter().any(|p|name.contains(p))
        })
        .take(MAX_FINDINGS)
        .map(|i|json!({"api":i.name,"dll":i.dll,"iat_rva":format!("0x{:X}",i.rva),
            "evidence":"PE import table","confidence":"observed_import"}))
        .collect()
}

fn platform_candidates(url_list:&[Value],strings:&[TextEvidence])->Vec<Value>{
    let mut result=Vec::new();
    let services=[
        ("Telegram",["api.telegram.org","telegram.org","t.me"].as_slice()),
        ("Discord",["discord.com/api","discordapp.com/api","discord.com"].as_slice()),
        ("Slack",["hooks.slack.com","slack.com/api","slack.com"].as_slice()),
    ];
    for (service,patterns) in services{
        for u in url_list {
            let val=u["value"].as_str().unwrap_or("");
            if patterns.iter().any(|p|val.to_ascii_lowercase().contains(p)){
                result.push(json!({"platform":service,"evidence":u,
                    "confidence":"candidate_url_reference_not_verified_exfiltration"}));
            }
        }
    }
    if result.is_empty(){
        for s in strings {
            let lower=s.text.to_ascii_lowercase();
            for (service,patterns) in services {
                if patterns.iter().any(|p|lower.contains(p)){
                    result.push(json!({"platform":service,"evidence":{"file_offset":format!("0x{:X}",s.offset),
                         "encoding":s.encoding,"text_excerpt":s.text.chars().take(100).collect::<String>()},
                         "confidence":"weak_string_reference"}));
                    if result.len()>=10{return result}
                }
            }
        }
    }
    result
}

fn crypto_artifacts(bytes:&[u8],pe:&PE<'_>,strings:&[TextEvidence])->Vec<Value>{
    let mut out=Vec::new();
    for p in evidence_imports(pe,&["cryptencrypt","bcryptencrypt","cryptdecrypt","bcryptdecrypt",
        "cryptimportkey","bcryptgenerate","rtlencodememory"]){
        out.push(json!({"type":"win32_crypto_api","evidence":p,"confidence":"import_only"}));
    }
    let signature=[0x63u8,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76];
    let search_len=bytes.len().min(MAX_SCAN);
    if let Some(pos)=bytes[..search_len].windows(signature.len()).position(|w|w==signature){
        out.push(json!({"type":"AES_SBOX_PREFIX","file_offset":format!("0x{pos:X}"),
            "confidence":"signature_only_not_algorithm_confirmation"}));
    }
    for (label,needle) in [("CHACHA_CONSTANT",b"expand 32-byte k".as_slice()),
        ("TEA_DELTA", &[0xB9u8,0x79,0x37,0x9E][..])] {
        if let Some(pos)=bytes[..search_len].windows(needle.len()).position(|w|w==needle){
            out.push(json!({"type":label,"file_offset":format!("0x{pos:X}"),
                "confidence":"signature_only_not_algorithm_confirmation"}));
        }
    }
    let names=["aes","rc4","chacha20","xor","cryptencrypt","rijndael"];
    for s in strings {
        if names.iter().any(|n|s.text.to_ascii_lowercase().contains(n)){
            out.push(json!({"type":"string_reference","file_offset":format!("0x{:X}",s.offset),
                "text_excerpt":s.text.chars().take(100).collect::<String>(),
                "confidence":"weak_string_reference"}));
        }
        if out.len()>=MAX_FINDINGS{break}
    }
    out.truncate(MAX_FINDINGS);out
}

pub fn inventory(bytes:&[u8],show_secrets:bool)->Result<Value,String>{
    let pe=PE::parse(bytes).map_err(|e|format!("Not a parseable PE executable: {e}"))?;
    let texts=extract_text(bytes);
    let endpoints=urls(&texts);
    let tokens=token_hits(&texts,show_secrets);
    let platform=platform_candidates(&endpoints,&texts);
    let keyboard=evidence_imports(&pe,&["getasynckeystate","getkeystate","getkeyboardstate","setwindowshookex",
        "getrawinputdata","tounicode","mapvirtualkey"]);
    let net=evidence_imports(&pe,&["httpsendrequest","winhttpsendrequest","internetconnect","httpsendrequest",
        "connect","wsasend","send","internetopen","winhttpopen"]);
    let crypto=crypto_artifacts(bytes,&pe,&texts);
    let stamp=Utc.timestamp_opt(pe.header.coff_header.time_date_stamp as i64,0).single()
        .map(|t|t.format("%Y-%m-%d %H:%M:%S").to_string());
    let sha256=format!("{:x}",Sha256::digest(bytes));
    Ok(json!({"metadata":{
        "sha256":sha256,
        "timestamp_pe_utc":stamp,
        "timestamp_note":"This is the untrusted COFF TimeDateStamp, not independently verified build time",
        "architecture":if pe.is_64{"x64"}else{"x86"},
        "entrypoint_rva":format!("0x{:X}",pe.entry),
        "size_bytes":bytes.len()},
        "keyboard_api_imports":keyboard,
        "network_api_imports":net,
        "crypto_indicators":crypto,
        "endpoints":endpoints,
        "platform_candidates":platform,
        "plaintext_token_candidates":tokens,
        "notes":["Static triage only; presence of an import or URL does not prove behavior",
                 "No cross-function data-flow or runtime execution",
                 "All sensitive candidate values are redacted unless explicitly requested"]}))
}

fn item(task:u8,question:&str,answer:Option<String>,status:&str,evidence:Vec<Value>,reason:&str)->Value{
    json!({"task":task,"question":question,"status":status,"answer":answer,
        "evidence":evidence,"reason":reason})
}
fn evidence_slice(v:&Value,key:&str,limit:usize)->Vec<Value>{
    v[key].as_array().map(|a|a.iter().take(limit).cloned().collect()).unwrap_or_default()
}
fn field_answer(v:&Value,key:&str)->Option<String>{
    v[key].as_str().map(str::to_string)
}

/// Worksheet deliberately does not conflate a candidate indicator with a proven answer.
pub fn worksheet(bytes:&[u8],specific:Option<u8>,show_secrets:bool)->Result<Value,String>{
    if specific.is_some_and(|n|!(1..=19).contains(&n)){return Err("Task must be 1..19".into());}
    let report=inventory(bytes,show_secrets)?;
    let meta=&report["metadata"];
    let imports=PE::parse(bytes).map_err(|e|e.to_string())?;
    let names=import_names(&imports);
    let mut q=Vec::with_capacity(19);
    q.push(item(1,"SHA-256 of the sample",field_answer(meta,"sha256"),"verified_file_value",
        vec![json!({"source":"bytes of input file"})],"Hash calculated over the complete input file."));
    q.push(item(2,"Compilation timestamp (UTC)",field_answer(meta,"timestamp_pe_utc"),"observed_untrusted_header",
        vec![json!({"source":"PE COFF TimeDateStamp"})],"Timestamp was read from PE headers; it can be forged."));
    q.push(item(3,"Compiler used",None,"inconclusive",vec![],"Rich/header/toolchain evidence cannot reliably identify the compiler by itself."));
    q.push(item(4,"Primary Win32 execution API",None,"inconclusive",evidence_slice(&report,"keyboard_api_imports",5),
        "Need call graph and primary execution path analysis."));
    q.push(item(5,"Hash of primary execution API",None,"inconclusive",vec![],
        "Need to recover the dynamic API-hash routine and trace its call site."));
    let disp=crate::reverse::constants(bytes,Some(0x104),None,10).ok();
    q.push(item(6,"Assigned value at function offset 0x104",None,"inconclusive",
        disp.into_iter().collect(),"These are binary operand candidates; they do not identify a specific function's assignment."));
    q.push(item(7,"Win32 API corresponding to target hash",None,"inconclusive",vec![],
        "Hash 0x28331FE9 cannot be interpreted without knowing the malware's hashing algorithm; use api-hash with a dictionary."));
    q.push(item(8,"VK 0x14",Some("VK_CAPITAL".into()),"verified_windows_mapping",
        vec![json!({"source":"Windows virtual-key standard","value":"0x14"})],
        "This mapping is defined by Windows, not recovered from runtime malware behavior."));
    let xor=crate::reverse::constants(bytes,None,Some("xor"),20).ok();
    q.push(item(9,"XOR operand for extended key identification",None,"inconclusive",
        xor.into_iter().collect(),"XOR instructions are candidates; the keyboard-related routine and actual operands must be traced."));
    let unicode:Vec<_>=names.iter().filter(|n|n.eq_ignore_ascii_case("ToUnicodeEx")||n.eq_ignore_ascii_case("ToUnicode"))
        .cloned().collect();
    let unicode_answer=if unicode.len()==1{Some(unicode[0].clone())}else{None};
    q.push(item(10,"Virtual-key to Unicode Win32 API",unicode_answer,
        if unicode.len()==1{"candidate_import"}else{"inconclusive"},
        unicode.iter().map(|n|json!({"imported_api":n})).collect(),
        "Import does not prove a specific call in the keyboard handling routine."));
    q.push(item(11,"VK transmission trigger",None,"inconclusive",vec![],
        "Need to trace VK comparisons through the send routine."));
    q.push(item(12,"Encryption algorithm for captured data",None,"inconclusive",
        evidence_slice(&report,"crypto_indicators",10),
        "Crypto signatures/imports do not prove which algorithm transforms captured data."));
    q.push(item(13,"Encryption key for captured data",None,"inconclusive",vec![],
        "Need to trace the key into the captured-data encryption routine."));
    let platforms=evidence_slice(&report,"platform_candidates",5);
    let application=platforms.first().and_then(|p|p["platform"].as_str()).map(str::to_string);
    q.push(item(14,"Legitimate service used for exfiltration",application,
        if platforms.len()==1{"candidate"}else{"inconclusive"},
        platforms,"Service references must be linked to the transmission routine."));
    let endpoints=evidence_slice(&report,"endpoints",10);
    let mut protocol=BTreeSet::new();
    for endpoint in &endpoints {
        if let Some(u)=endpoint["value"].as_str(){
            if u.to_ascii_lowercase().starts_with("https://"){protocol.insert("HTTPS");}
            else if u.to_ascii_lowercase().starts_with("http://"){protocol.insert("HTTP");}
        }
    }
    let proto=if protocol.len()==1{protocol.iter().next().map(|p|p.to_string())}else{None};
    q.push(item(15,"Exfiltration protocol",proto,if protocol.len()==1{"candidate"}else{"inconclusive"},
        endpoints,"Observed URL scheme alone does not confirm actual network transmission."));
    let tokens=evidence_slice(&report,"plaintext_token_candidates",5);
    let token_value=if tokens.len()==1{
        tokens[0]["token"].as_str().map(str::to_string)
    }else{None};
    q.push(item(16,"Bot token",token_value,if tokens.len()==1{"candidate"}else{"inconclusive"},tokens,
        "Only plaintext token-shaped strings are matched. Encoded or encrypted tokens require deobfuscation and call-site tracing."));
    q.push(item(17,"Hardcoded token decryption key",None,"inconclusive",vec![],
        "Recover key source and verify decryption against actual encrypted token bytes."));
    q.push(item(18,"Token encryption algorithm",None,"inconclusive",
        evidence_slice(&report,"crypto_indicators",6),
        "Cannot attribute a crypto primitive to the token without tracing configuration decryption."));
    let keyboard=evidence_slice(&report,"keyboard_api_imports",10);
    let behavior=if keyboard.len()>=2{Some("Possible keylogging capability".into())}else{None};
    q.push(item(19,"Primary malware functionality",behavior,
        if keyboard.len()>=2{"candidate"}else{"inconclusive"},keyboard,
        "API imports are indicators, not confirmation of primary functionality."));
    let all=q.len();
    if let Some(n)=specific{q.retain(|x|x["task"].as_u64()==Some(n as u64));}
    Ok(json!({"worksheet_version":1,"sample_sha256":meta["sha256"],"tasks":q,"total_defined":all,
        "note":"Only verified_file_value and verified_windows_mapping are deterministic. Candidate answers require manual confirmation."}))
}

/// Try a known plaintext against repeating XOR, without making algorithm attribution.
/// Result candidates require validation by decompilation or decoding more content.
pub fn xor_crib(bytes:&[u8],known:&str,max_keylen:usize,limit:usize,show_secrets:bool)->Result<Value,String>{
    let plain=known.as_bytes();
    if plain.len()<6||plain.len()>128{return Err("Known plaintext length must be 6..128".into())}
    if max_keylen==0||max_keylen>16{return Err("--max-keylen must be 1..16".into())}
    let bytes=&bytes[..bytes.len().min(MAX_SCAN)];
    if bytes.len()<plain.len(){return Ok(json!({"candidates":[],"scanned_bytes":bytes.len()}))}
    let mut results=Vec::new();
    let mut seen=BTreeSet::new();
    for keylen in 1..=max_keylen.min(plain.len()){
        for offset in 0..=(bytes.len()-plain.len()){
            let mut key=vec![0u8;keylen];
            for (i,&b) in plain.iter().take(keylen).enumerate(){
                key[i]=bytes[offset+i]^b;
            }
            if key.iter().all(|&k|k==0){continue}
            if !(0..plain.len()).all(|i|bytes[offset+i]^key[i%keylen]==plain[i]){continue}
            // Validate at least 8 bytes beyond the crib whenever available.
            let span=(plain.len()+32).min(bytes.len()-offset);
            let decoded:Vec<u8>=(0..span).map(|i|bytes[offset+i]^key[i%keylen]).collect();
            let extra=&decoded[plain.len()..];
            if extra.len()>=8 && extra.iter().filter(|&&b|(32..=126).contains(&b)||b==0).count()*100 < extra.len()*75{continue}
            let keyhex=hex::encode(&key);
            if !seen.insert((offset,keyhex.clone())){continue}
            results.push(json!({"file_offset":format!("0x{offset:X}"),"key_length":keylen,
                "xor_key_hex":if show_secrets{keyhex}else{"[REDACTED]".into()},
                "decoded_preview":if show_secrets{
                    String::from_utf8_lossy(&decoded).into_owned()
                }else{"[REDACTED]".into()},
                "confidence":"known_plaintext_candidate_not_verified",
                "note":"Coincidence does not establish key use or malware behavior"}));
            if results.len()>=limit.min(50){
                return Ok(json!({"candidates":results,"scanned_bytes":bytes.len(),"truncated":true}))
            }
        }
    }
    Ok(json!({"candidates":results,"scanned_bytes":bytes.len(),"truncated":false}))
}

pub fn xor_decode(bytes:&[u8],offset:usize,length:usize,key:&str,show_secrets:bool)->Result<Value,String>{
    let key=hex::decode(key.trim_start_matches("0x")).map_err(|e|format!("Key must be hex: {e}"))?;
    if key.is_empty()||key.len()>64{return Err("XOR key must contain 1..64 bytes".into());}
    if offset>bytes.len(){return Err("Offset exceeds input file".into());}
    let end=offset.checked_add(length).ok_or("Length overflow")?.min(bytes.len());
    let plain:Vec<u8>=bytes[offset..end].iter().enumerate().map(|(i,b)|b^key[i%key.len()]).collect();
    Ok(json!({"file_offset":format!("0x{offset:X}"),"length":plain.len(),"mode":"repeating-xor",
        "plaintext_utf8":if show_secrets{Some(String::from_utf8_lossy(&plain).into_owned())}else{None},
        "plaintext_hex":if show_secrets{Some(hex::encode(plain))}else{None},
        "status":"manually_supplied_key_not_algorithm_attribution"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn extracts_offsets_ascii_utf16(){
        let b=b"\0hello\0\0W\0o\0r\0l\0d\0";
        let x=extract_text(b);
        assert!(x.iter().any(|e|e.text=="hello"&&e.offset==1));
        assert!(x.iter().any(|e|e.text=="World"&&e.encoding=="utf16le"));
    }
    #[test] fn detects_https_and_platform(){
        let v=extract_text(b"https://api.telegram.org/bot123 \0");
        let u=urls(&v);
        assert_eq!(u.len(),1);
        assert_eq!(platform_candidates(&u,&v)[0]["platform"],"Telegram");
    }
    #[test]fn token_redaction(){
        let v=extract_text(b"bot 123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi \0");
        assert_eq!(token_hits(&v,false)[0]["token"],"[REDACTED]");
    }
    #[test]fn known_xor_key(){
        let known="https://api.telegram.org";
        let key=b"AB";
        let encrypted:Vec<u8>=known.as_bytes().iter().enumerate().map(|(i,&b)|b^key[i%2]).collect();
        let results=xor_crib(&encrypted,known,2,10,true).unwrap();
        assert!(results["candidates"].as_array().unwrap().iter().any(|x|x["xor_key_hex"]=="4142"));
        let raw=xor_decode(&encrypted,0,encrypted.len(),"4142",true).unwrap();
        assert_eq!(raw["plaintext_utf8"],known);
    }
    #[test]fn bounds_are_enforced(){
        assert!(xor_crib(b"1234567890","a",3,1,false).is_err());
        assert!(xor_decode(b"test",999,2,"aa",true).is_err());
    }
}
