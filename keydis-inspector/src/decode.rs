//! Bounded recovery of encoded strings and simple single-byte XOR URLs.
//! These are candidates: decoding a string does not establish execution or exfiltration.
use base64::{engine::general_purpose::{STANDARD,URL_SAFE},Engine as _};
use regex::Regex;
use serde_json::{json,Value};
use sha2::{Sha256,Digest};
use std::collections::BTreeSet;

const MAX_INPUT:usize=16*1024*1024;
const MAX_SEGMENT:usize=4096;
const MAX_RESULTS:usize=100;
fn url_re()->Regex{Regex::new(r"(?i)https?://[a-z0-9][a-z0-9._-]{2,}(?::[0-9]{2,5})?(?:/[^[:space:]\"'<>]*)?").unwrap()}
fn token_re()->Regex{Regex::new(r"\b[0-9]{6,12}:[A-Za-z0-9_-]{30,60}\b").unwrap()}

#[derive(Clone)]
struct Finding {offset:usize,method:String,key:Option<String>,decoded:Vec<u8>,indicator:String}
fn inspect(buf:&[u8])->Option<String>{
    if buf.len()<8||buf.len()>MAX_SEGMENT{return None}
    let decoded=String::from_utf8(buf).ok()?;
    if decoded.chars().any(|c|c=='\u{FFFD}'){return None}
    if token_re().is_match(&decoded){return Some("possible_bot_token".into())}
    if url_re().is_match(&decoded){return Some("decoded_url".into())}
    if decoded.trim().starts_with('{') {
        if let Ok(Value::Object(obj))=serde_json::from_str::<Value>(&decoded){
            if !obj.is_empty(){return Some("json_object".into())}
        }
    }
    None
}
fn collect_string_encoded(bytes:&[u8],findings:&mut Vec<Finding>){
    let text=crate::intelligence::extract_text(bytes);
    let base64_re=Regex::new(r"[A-Za-z0-9+/]{16,}={0,2}").unwrap();
    let base64_url_re=Regex::new(r"[A-Za-z0-9_-]{16,}={0,2}").unwrap();
    let hex_re=Regex::new(r"(?i)(?:[0-9a-f]{2}){10,}").unwrap();
    for item in text{
        for (method,re) in [("base64",&base64_re),("base64url",&base64_url_re),("hex",&hex_re)]{
            for mat in re.find_iter(&item.text){
                if mat.len()>MAX_SEGMENT*2{continue}
                let decoded=match method{
                    "hex"=>hex::decode(mat.as_str()).ok(),
                    "base64"=>STANDARD.decode(mat.as_str()).ok(),
                    "base64url"=>URL_SAFE.decode(mat.as_str()).ok(),
                    _=>None,
                };
                let Some(plain)=decoded else{continue};
                let Some(indicator)=inspect(&plain)else{continue};
                findings.push(Finding{offset:item.offset+mat.start(),method:method.into(),
                    key:None,decoded:plain,indicator});
                if findings.len()>=MAX_RESULTS*10{return}
            }
        }
    }
}
fn collect_single_byte_xor(bytes:&[u8],findings:&mut Vec<Finding>){
    // Derive the key from the four-byte HTTP prefix; O(n), without executing the sample.
    let prefix=b"http";
    for i in 0..bytes.len().saturating_sub(8){
        let key=bytes[i]^prefix[0];
        if key==0||!(1..4).all(|j|bytes[i+j]^key==prefix[j]){continue}
        let max=(bytes.len()-i).min(512);
        let mut plain=Vec::new();
        for &byte in &bytes[i..i+max]{
            let decoded=byte^key;
            if decoded==0{break}
            if !(32..=126).contains(&decoded){break}
            plain.push(decoded);
        }
        if plain.len()<12{continue}
        let Some(indicator)=inspect(&plain)else{continue};
        findings.push(Finding{offset:i,method:"xor_single_byte".into(),
            key:Some(format!("{key:02X}")),decoded:plain,indicator});
        if findings.len()>=MAX_RESULTS*10{return}
    }
}
fn public_preview(f:&Finding,show_secrets:bool)->String{
    if !show_secrets && (
        f.indicator=="possible_bot_token" ||
        token_re().is_match(&String::from_utf8_lossy(&f.decoded)) ||
        String::from_utf8_lossy(&f.decoded).to_ascii_lowercase().contains("/bot")
    ){
        return "[REDACTED: possible secret]".into();
    }
    String::from_utf8_lossy(&f.decoded).chars().take(512).collect()
}

pub fn scan(bytes:&[u8],limit:usize,show_secrets:bool)->Value{
    let examined=bytes.len().min(MAX_INPUT);
    let buf=&bytes[..examined];
    let mut candidates=Vec::new();
    collect_string_encoded(buf,&mut candidates);
    collect_single_byte_xor(buf,&mut candidates);
    candidates.sort_by_key(|r|r.offset);
    let mut seen=BTreeSet::new();
    let mut out=Vec::new();
    let mut total=0usize;
    for candidate in candidates{
        let key=(candidate.offset,candidate.method.clone(),candidate.decoded.clone());
        if !seen.insert(key){continue}
        total+=1;
        if out.len()>=limit.min(MAX_RESULTS){continue}
        let sha=format!("{:x}",Sha256::digest(&candidate.decoded));
        out.push(json!({
            "file_offset":format!("0x{:X}",candidate.offset),
            "method":candidate.method,
            "xor_key_hex":if show_secrets{candidate.key}else{None},
            "indicator_type":candidate.indicator,
            "decoded_preview":public_preview(&candidate,show_secrets),
            "decoded_sha256":sha,
            "confidence":"validated_format_candidate_not_verified_use"
        }));
    }
    json!({"bytes_scanned":examined,"total_candidates":total,
        "findings":out,"truncated":bytes.len()>examined||total>limit.min(MAX_RESULTS),
        "limitations":["Supports Base64, Base64URL, hex and single-byte XOR URLs only",
          "Not a general decryption engine; repeating-key XOR and custom crypto may require a known key or reversed routine",
          "A decoded URL or token does not establish that the sample actually uses it",
          "Possible secrets are redacted unless --show-secrets was explicitly provided"]})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovers_encoded_url_as_evidence(){
        let url=b"https://incident.example.com/ingest";
        let b64=STANDARD.encode(url);
        let r=scan(format!("AA\0{}\0",b64).as_bytes(),10,false);
        assert!(r["findings"].as_array().unwrap().iter().any(|f|f["method"]=="base64"
            && f["decoded_preview"]=="https://incident.example.com/ingest"));
    }
    #[test]
    fn recovers_single_byte_xor_url_without_an_existing_key(){
        let text=b"https://c2.example.com/api";
        let encrypted:Vec<u8>=text.iter().map(|b|b^0x5a).chain([0x5a]).collect();
        let r=scan(&encrypted,10,true);
        assert!(r["findings"].as_array().unwrap().iter().any(|f|
            f["method"]=="xor_single_byte"&&f["xor_key_hex"]=="5A"));
    }
    #[test]
    fn detects_encoded_token_but_redacts(){
        let token=b"123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
        let b64=STANDARD.encode(token);
        let r=scan(b64.as_bytes(),10,false);
        assert!(r["findings"].as_array().unwrap().iter().any(|f|
            f["indicator_type"]=="possible_bot_token" &&
            f["decoded_preview"]=="[REDACTED: possible secret]"));
    }
    #[test]
    fn unsupported_or_random_bytes_do_not_produce_assertions(){
        assert_eq!(scan(b"123456789\0NONSENSE",10,false)["total_candidates"],0);
    }
}
