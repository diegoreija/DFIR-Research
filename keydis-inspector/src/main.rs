use clap::{Args, Parser, Subcommand};
use chrono::{DateTime, TimeZone, Utc};
use goblin::Object;
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sha1::Sha1;
use md5::Md5;
use std::{fs, path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(name="keydis-inspector", version, about="Evidence-first DFIR command line utility")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Args)]
struct Input {
    #[arg(short, long)]
    input: PathBuf,
}
#[derive(Subcommand)]
enum Command {
    /// Summary of supported static analysis, without invented conclusions
    Analyze { #[command(flatten)] file: Input, #[arg(long)] task: Option<u8>, #[arg(long)] profile: Option<String> },
    /// File hashes
    Hash { #[command(flatten)] file: Input, #[arg(long, default_value="all")] algorithm: String },
    /// PE metadata and imported APIs
    Pe { #[command(flatten)] file: Input, #[arg(long, default_value="summary")] view: String },
    /// Inspect compiler evidence (not inferred from timestamp)
    Compiler { #[command(flatten)] file: Input },
    /// Imported Win32 APIs and name filtering
    Api { #[command(flatten)] file: Input, #[arg(long)] contains: Option<String>, #[arg(long)] category: Option<String>, #[arg(long, default_value_t=50)] limit: usize },
    /// Read bytes at a FILE offset, not a virtual address
    Offset { #[command(flatten)] file: Input, #[arg(long, value_parser=parse_num)] offset: usize, #[arg(long, default_value_t=32)] length: usize },
    /// Extract printable ASCII and UTF-16LE strings
    Strings { #[command(flatten)] file: Input, #[arg(long)] contains: Option<String>, #[arg(long)] regex: Option<String>, #[arg(long)] ignore_case: bool, #[arg(long, default_value_t=4)] min_length: usize, #[arg(long, default_value_t=100)] limit: usize },
    /// Hexadecimal bytes at a file offset
    Hex { #[command(flatten)] file: Input, #[arg(long, value_parser=parse_num)] offset: usize, #[arg(long, default_value_t=64)] length: usize },
    /// Candidate URLs, IP addresses and domains from extracted strings
    Ioc { #[command(flatten)] file: Input, #[arg(long, default_value_t=50)] limit: usize },
    /// Inspect keyboard-related imports (not behavioral proof)
    Keylogger { #[command(flatten)] file: Input, #[arg(long)] vk_code: Option<String> },
    /// Report potential crypto-related imports and strings
    Crypto { #[command(flatten)] file: Input },
    /// Report potential network/exfil-related imports and URLs
    Exfil { #[command(flatten)] file: Input },
    /// Extract candidate configuration strings, redact secrets by default
    Config { #[command(flatten)] file: Input, #[arg(long)] show_secrets: bool },
    /// Write structured static triage report
    Report { #[command(flatten)] file: Input, #[arg(long)] output: PathBuf },
    /// Timeline from JSONL events (EVTX not yet supported)
    Timeline { #[command(flatten)] file: Input, #[command(flatten)] filter: TimeFilter },
    /// Filter JSONL forensic events
    Events { #[command(flatten)] file: Input, #[command(flatten)] filter: TimeFilter },
    /// Compare two files by hashes and PE import names
    Compare { #[arg(long)] file_a: PathBuf, #[arg(long)] file_b: PathBuf },
}
#[derive(Args)]
struct TimeFilter {
    #[arg(long)]
    start_time: Option<DateTime<Utc>>,
    #[arg(long)]
    end_time: Option<DateTime<Utc>>,
    #[arg(long, conflicts_with_all=["start_time","end_time"])]
    around: Option<DateTime<Utc>>,
    #[arg(long, default_value="10m")]
    window: String,
    #[arg(long)]
    event_id: Option<u64>,
    #[arg(long)]
    process: Option<String>,
    #[arg(long, default_value_t=100)]
    limit: usize,
    #[arg(long, default_value="asc")]
    sort: String,
}
fn parse_num(s: &str) -> Result<usize,String> {
    if let Some(x)=s.strip_prefix("0x").or_else(||s.strip_prefix("0X")) {
        usize::from_str_radix(x,16).map_err(|e|e.to_string())
    } else { s.parse().map_err(|e:std::num::ParseIntError|e.to_string()) }
}
fn read(p:&PathBuf)->Result<Vec<u8>,String>{fs::read(p).map_err(|e|format!("{}: {}",p.display(),e))}
fn hashes(b:&[u8])->Value {
    json!({"sha256":format!("{:x}",Sha256::digest(b)),"sha1":format!("{:x}",Sha1::digest(b)),"md5":format!("{:x}",Md5::digest(b))})
}
fn pe_data(b:&[u8])->Result<Value,String>{
    let pe=match Object::parse(b).map_err(|e|e.to_string())? {
        Object::PE(p)=>p, _=>return Err("Not a Windows PE file".into())
    };
    let raw=pe.header.coff_header.time_date_stamp;
    let stamp=Utc.timestamp_opt(raw as i64,0).single().map(|d|d.to_rfc3339());
    let imports:Vec<Value>=pe.imports.iter().map(|i|json!({"dll":i.dll,"name":i.name,"rva":i.rva})).collect();
    let sections:Vec<Value>=pe.sections.iter().map(|s|json!({"name":s.name().unwrap_or("?"),"raw_offset":s.pointer_to_raw_data,"raw_size":s.size_of_raw_data,"virtual_address":s.virtual_address})).collect();
    Ok(json!({"format":"PE","is_64":pe.is_64,"entry_rva":pe.entry,"timestamp_utc":stamp,"timestamp_untrusted":true,"imports":imports,"sections":sections}))
}
fn strings(b:&[u8],min:usize)->Vec<(usize,String)> {
    let mut out=Vec::new();let mut i=0;
    while i<b.len() {
        if (32..=126).contains(&b[i]) {
            let start=i;
            while i<b.len()&&(32..=126).contains(&b[i]) {i+=1;}
            if i-start>=min {out.push((start,String::from_utf8_lossy(&b[start..i]).into_owned()));}
        }else{i+=1;}
    }
    let mut i=0;
    while i+1<b.len(){
        if (32..=126).contains(&b[i])&&b[i+1]==0 {
            let start=i;let mut chars=String::new();
            while i+1<b.len()&&(32..=126).contains(&b[i])&&b[i+1]==0 {
                chars.push(b[i] as char);i+=2;
            }
            if chars.len()>=min {out.push((start,chars));}
        }else{i+=1;}
    }
    out.sort_by_key(|x|x.0);out
}
fn iocs(b:&[u8],limit:usize)->Vec<Value>{
    let url=Regex::new(r#"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+"#).unwrap();
    let mut out=Vec::new();
    for (offset,s) in strings(b,4) {
        for m in url.find_iter(&s){
            out.push(json!({"offset":offset+m.start(),"type":"url_candidate","value":m.as_str(),"confidence":"unverified"}));
            if out.len()>=limit{return out}
        }
    }out
}
fn print(v:&Value){println!("{}",serde_json::to_string_pretty(v).unwrap());}
fn imports_matching(b:&[u8],keywords:&[&str])->Vec<Value>{
    let Ok(pe)=pe_data(b) else{return vec![]};
    pe["imports"].as_array().unwrap().iter().filter(|v|{
        let n=v["name"].as_str().unwrap_or("").to_ascii_lowercase();
        keywords.iter().any(|k|n.contains(*k))
    }).cloned().collect()
}
fn timeline(path:&PathBuf,f:&TimeFilter)->Result<Value,String>{
    let raw=fs::read_to_string(path).map_err(|e|e.to_string())?;
    if f.sort!="asc"&&f.sort!="desc"{return Err("--sort must be asc or desc".into())}
    let window_secs=if let Some(m)=f.window.strip_suffix('m'){m.parse::<i64>().map_err(|e|format!("window: {e}"))?*60}
        else if let Some(h)=f.window.strip_suffix('h'){h.parse::<i64>().map_err(|e|format!("window: {e}"))?*3600}
        else{return Err("--window must use m or h (e.g. 10m)".into())};
    let mut out:Vec<(DateTime<Utc>,Value)>=Vec::new();
    for (idx,line) in raw.lines().enumerate(){
        if line.trim().is_empty(){continue}
        let v:Value=serde_json::from_str(line).map_err(|e|format!("JSONL line {}: {}",idx+1,e))?;
        let ts=v["timestamp"].as_str().ok_or(format!("line {} missing timestamp",idx+1))?;
        let t=DateTime::parse_from_rfc3339(ts).map_err(|e|format!("line {}: {}",idx+1,e))?.with_timezone(&Utc);
        if f.start_time.is_some_and(|s|t<s)||f.end_time.is_some_and(|e|t>e){continue}
        if f.around.is_some_and(|a|(t-a).num_seconds().abs()>window_secs){continue}
        if f.event_id.is_some_and(|id|v["event_id"].as_u64()!=Some(id)){continue}
        if f.process.as_ref().is_some_and(|p|!v["process"].as_str().unwrap_or("").eq_ignore_ascii_case(p)){continue}
        out.push((t,v));
    }
    out.sort_by_key(|(t,_)|*t);if f.sort=="desc"{out.reverse()}
    let total=out.len();
    Ok(json!({"source":path,"total_matches":total,"events":out.into_iter().take(f.limit).map(|(_,v)|v).collect::<Vec<_>>()}))
}
fn run(cmd:Command)->Result<(),String>{
    match cmd {
        Command::Hash{file,algorithm}=>{
            let h=hashes(&read(&file.input)?);
            if algorithm=="all"{print(&h)}else if let Some(v)=h.get(&algorithm){println!("{}",v.as_str().unwrap())}else{return Err("algorithm: sha256, sha1, md5, all".into())}
        }
        Command::Pe{file,view}=>{
            let p=pe_data(&read(&file.input)?)?;
            match view.as_str(){
                "summary"=>print(&json!({"entry_rva":p["entry_rva"],"timestamp_utc":p["timestamp_utc"],"timestamp_untrusted":true,"is_64":p["is_64"],"sections_count":p["sections"].as_array().unwrap().len(),"imports_count":p["imports"].as_array().unwrap().len()})),
                "imports"|"sections"=>print(&p[view.as_str()]),
                _=>return Err("--view must be summary, imports or sections".into())
            }
        }
        Command::Compiler{file}=>{
            let b=read(&file.input)?;pe_data(&b)?;
            print(&json!({"compiler":"INCONCLUSIVE","reason":"Rich Header / compiler fingerprinting not implemented; timestamp alone is insufficient"}));
        }
        Command::Api{file,contains,category,limit}=>{
            let p=pe_data(&read(&file.input)?)?;
            let keywords=match category.as_deref(){Some("keyboard")=>vec!["key","hook","unicode"],Some("network")=>vec!["http","internet","socket","connect","send"],Some("crypto")=>vec!["crypt","bcrypt"],Some(x)=>return Err(format!("unknown category: {x}")),None=>vec![]};
            let filtered:Vec<Value>=p["imports"].as_array().unwrap().iter().filter(|v|{
                let n=v["name"].as_str().unwrap_or("").to_ascii_lowercase();
                contains.as_ref().is_none_or(|s|n.contains(&s.to_ascii_lowercase()))&&
                (keywords.is_empty()||keywords.iter().any(|k|n.contains(*k)))
            }).take(limit).cloned().collect();print(&json!(filtered));
        }
        Command::Offset{file,offset,length}|Command::Hex{file,offset,length}=>{
            let b=read(&file.input)?;
            let end=offset.checked_add(length).ok_or("offset overflow")?.min(b.len());
            if offset>b.len(){return Err("offset exceeds file size".into())}
            print(&json!({"file_offset":format!("0x{offset:X}"),"length":end-offset,"hex":hex::encode(&b[offset..end])}));
        }
        Command::Strings{file,contains,regex,ignore_case,min_length,limit}=>{
            let b=read(&file.input)?;
            let re=regex.map(|r|Regex::new(&if ignore_case{format!("(?i:{r})")}else{r}).map_err(|e|e.to_string())).transpose()?;
            let out:Vec<Value>=strings(&b,min_length).into_iter().filter(|(_,s)|{
                contains.as_ref().is_none_or(|needle|if ignore_case{s.to_lowercase().contains(&needle.to_lowercase())}else{s.contains(needle)})&&
                re.as_ref().is_none_or(|r|r.is_match(s))
            }).take(limit).map(|(o,s)|json!({"offset":format!("0x{o:X}"),"value":s})).collect();print(&json!(out));
        }
        Command::Ioc{file,limit}=>print(&json!(iocs(&read(&file.input)?,limit))),
        Command::Keylogger{file,vk_code}=>{
            let b=read(&file.input)?;
            let vk=vk_code.as_deref().map(|v|match v.to_ascii_lowercase().as_str(){"0x14"=> "VK_CAPITAL","0x0d"=>"VK_RETURN","0x1b"=>"VK_ESCAPE",_=>"UNKNOWN"});
            print(&json!({"vk_lookup":vk,"keyboard_related_imports":imports_matching(&b,&["key","hook","unicode"]),"behavior":"NOT CONFIRMED by imports alone"}));
        }
        Command::Crypto{file}=>{
            let b=read(&file.input)?;
            print(&json!({"crypto_related_imports":imports_matching(&b,&["crypt","bcrypt"]),"algorithm":"INCONCLUSIVE","key":"INCONCLUSIVE"}));
        }
        Command::Exfil{file}=>{
            let b=read(&file.input)?;
            print(&json!({"network_related_imports":imports_matching(&b,&["http","internet","socket","connect","send"]),"url_candidates":iocs(&b,50),"exfiltration":"NOT CONFIRMED"}));
        }
        Command::Config{file,show_secrets}=>{
            let b=read(&file.input)?;
            let re=Regex::new(r"(?i)(token|secret|api[_-]?key|bot)").unwrap();
            let out:Vec<Value>=strings(&b,4).into_iter().filter(|(_,s)|re.is_match(s)).take(50).map(|(o,s)|{
                json!({"offset":format!("0x{o:X}"),"candidate":if show_secrets{s}else{"[REDACTED]".into()},"status":"UNVERIFIED"})
            }).collect();print(&json!(out));
        }
        Command::Analyze{file,task,profile}=>{
            let b=read(&file.input)?;
            if task.is_some_and(|t|t<1||t>19){return Err("--task must be 1..19".into())}
            let pe=pe_data(&b).ok();
            let result=json!({"file":file.input.display().to_string(),"profile":profile,"task_requested":task,"hashes":hashes(&b),"pe":pe,"url_candidates":iocs(&b,30),"task_answers":"Only evidence-supported fields above; reverse-engineering tasks remain INCONCLUSIVE"});
            if task==Some(1){println!("{}",result["hashes"]["sha256"].as_str().unwrap())}
            else if task==Some(2){print(&result["pe"]["timestamp_utc"])}
            else {print(&result)}
        }
        Command::Report{file,output}=>{
            let b=read(&file.input)?;
            let r=json!({"schema_version":1,"input":file.input.display().to_string(),"hashes":hashes(&b),"pe":pe_data(&b).ok(),"ioc_candidates":iocs(&b,100),"limitations":["Static analysis only","No behavioral execution","No keydis-specific decryption or API hash algorithm"]});
            fs::write(&output,serde_json::to_vec_pretty(&r).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
            println!("Saved {}",output.display());
        }
        Command::Timeline{file,filter}|Command::Events{file,filter}=>print(&timeline(&file.input,&filter)?),
        Command::Compare{file_a,file_b}=>{
            let a=read(&file_a)?;let b=read(&file_b)?;
            let pa=pe_data(&a).ok();let pb=pe_data(&b).ok();
            print(&json!({"a":{"file":file_a,"hashes":hashes(&a),"pe":pa},"b":{"file":file_b,"hashes":hashes(&b),"pe":pb},"identical":a==b}));
        }
    }Ok(())
}
fn main()->ExitCode{
    match run(Cli::parse().command){
        Ok(())=>ExitCode::SUCCESS,
        Err(e)=>{eprintln!("error: {e}");ExitCode::FAILURE}
    }
}
