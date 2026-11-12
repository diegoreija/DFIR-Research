//! Optional Ghidra headless backend. Imports executables as data; never executes the sample.
use serde_json::{json,Value};
use std::{fs, path::{Path,PathBuf}, process::Command, time::{SystemTime,UNIX_EPOCH}};

const EXPORTER:&str=include_str!("ghidra/ExportEvidence.py");

pub fn ghidra_analyze(input:&Path,output:&Path,analyze_headless:Option<&Path>,
                      max_functions:usize,timeout_secs:u64)->Result<Value,String>{
    if max_functions==0||max_functions>500{return Err("max-functions must be in 1..=500".into())}
    if !(10..=3600).contains(&timeout_secs){return Err("analysis-timeout must be 10..=3600 seconds".into())}
    let target=fs::canonicalize(input).map_err(|e|format!("Input: {e}"))?;
    let destination=if output.is_absolute(){output.to_path_buf()}
                    else{std::env::current_dir().map_err(|e|e.to_string())?.join(output)};
    // Do not invoke a dynamic analyzer on a non-PE, unsupported file by accident.
    let input_bytes=fs::read(&target).map_err(|e|e.to_string())?;
    goblin::pe::PE::parse(&input_bytes).map_err(|e|format!("Input is not a valid PE: {e}"))?;

    let nonce=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_nanos();
    let working=std::env::temp_dir().join(format!("keydis-ghidra-{}-{nonce}",std::process::id()));
    fs::create_dir(&working).map_err(|e|format!("Temp directory: {e}"))?;
    let script=working.join("ExportEvidence.py");
    let operation=(||->Result<Value,String>{
        fs::write(&script,EXPORTER).map_err(|e|e.to_string())?;
        let tool=analyze_headless.unwrap_or_else(||Path::new("analyzeHeadless"));
        let output_data=Command::new(tool)
            .arg(&working).arg("KeydisInspect")
            .arg("-import").arg(&target)
            .arg("-scriptPath").arg(&working)
            .arg("-postScript").arg("ExportEvidence.py")
            .arg(&destination).arg(max_functions.to_string())
            .arg("-analysisTimeoutPerFile").arg(timeout_secs.to_string())
            .arg("-deleteProject").arg("-max-cpu").arg("2")
            .output().map_err(|e|format!("Cannot launch Ghidra analyzeHeadless: {e}. Use --analyze-headless /path/to/ghidra/support/analyzeHeadless"))?;
        if !output_data.status.success(){
            let stderr=String::from_utf8_lossy(&output_data.stderr);
            let stdout=String::from_utf8_lossy(&output_data.stdout);
            return Err(format!("Ghidra failed ({}). stderr: {} stdout: {}",
                output_data.status,stderr.chars().rev().take(1000).collect::<String>().chars().rev().collect::<String>(),
                stdout.chars().rev().take(1000).collect::<String>().chars().rev().collect::<String>()));
        }
        let raw=fs::read(&destination).map_err(|e|format!("Ghidra did not produce output JSON at {}: {e}",destination.display()))?;
        let report:Value=serde_json::from_slice(&raw).map_err(|e|format!("Invalid exported Ghidra JSON: {e}"))?;
        if report["schema_version"]!=1 || !report["functions"].is_array(){
            return Err("Unsupported or incomplete Ghidra output".into())
        }
        Ok(json!({"status":"success","report_path":destination,
            "functions_processed":report["functions_processed"],
            "note":"Report contains pseudocode which may include credentials; keep it private."}))
    })();
    let _=fs::remove_dir_all(&working);
    operation
}

pub fn deep_find(report_file:&Path,query:&str,before:usize,after:usize,limit:usize)->Result<Value,String>{
    if query.trim().is_empty(){return Err("Search query cannot be empty".into())}
    let bytes=fs::read(report_file).map_err(|e|e.to_string())?;
    let report:Value=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;
    let functions=report["functions"].as_array().ok_or("Not a recognized deep evidence report")?;
    let needle=query.to_ascii_lowercase();
    let mut results=Vec::new();
    let mut total=0usize;
    for func in functions{
        let name=func["name"].as_str().unwrap_or("");
        let code=func["pseudocode"].as_str().unwrap_or("");
        let mut matched=Vec::new();
        if name.to_ascii_lowercase().contains(&needle){
            matched.push((0,format!("FUNCTION NAME: {name}")));
        }
        let lines:Vec<&str>=code.lines().collect();
        for (i,line) in lines.iter().enumerate(){
            if line.to_ascii_lowercase().contains(&needle){
                let start=i.saturating_sub(before.min(20));
                let end=(i+after.min(20)+1).min(lines.len());
                matched.push((i+1,lines[start..end].join("\n")));
                if matched.len()>=10{break}
            }
        }
        if !matched.is_empty(){
            total+=1;
            if results.len()<limit.min(100){
                results.push(json!({"function_name":name,
                    "entry_address":func["entry_address"],
                    "matches":matched.iter().map(|(line,ctx)|json!({"line":line,"context":ctx})).collect::<Vec<_>>()}));
            }
        }
    }
    Ok(json!({"query":query,"matched_functions":total,"results":results,
        "note":"Decompiler text is heuristic; inspect the associated assembly before accepting conclusions."}))
}


/// Attach relevant decompiled *function references* to an investigation worksheet.
/// Keyword hits never become confirmed answers.
pub fn enrich_worksheet(worksheet:&mut Value,path:&Path)->Result<(),String>{
    let raw=fs::read(path).map_err(|e|format!("Deep report: {e}"))?;
    let report:Value=serde_json::from_slice(&raw).map_err(|e|format!("Deep report JSON: {e}"))?;
    let funcs=report["functions"].as_array().ok_or("Deep report lacks functions")?;
    let tasks=worksheet["tasks"].as_array_mut().ok_or("Worksheet lacks tasks")?;
    for task in tasks{
        let number=task["task"].as_u64().unwrap_or(0);
        let terms: &[&str]=match number {
            3=>&["vcruntime","msvc","mingw","gcc","rustc"],
            4=>&["getprocaddress","winmain","getasynckeystate","setwindowshookex"],
            5=>&["getprocaddress","getmodulehandle","hash"],
            6=>&["0x104"],
            7=>&["0x28331fe9","28331fe9"],
            8=>&["0x14","vk_capital"],
            9=>&["xor","extended"],
            10=>&["tounicodeex","tounicode"],
            11=>&["getasynckeystate","send","transmit"],
            12|13=>&["encrypt","crypt","xor","rc4","aes"],
            14|15=>&["telegram","discord","slack","https","socket","send"],
            16=>&["token","telegram","bot"],
            17=>&["decrypt","xor","key"],
            18=>&["encrypt","crypt","xor","rc4","aes"],
            19=>&["getasynckeystate","setwindowshookex","tounicode"],
            _=>&[],
        };
        if terms.is_empty(){continue}
        let mut matches=Vec::new();
        for func in funcs{
            let name=func["name"].as_str().unwrap_or("");
            let code=func["pseudocode"].as_str().unwrap_or("");
            let lower=format!("{} {}",name,code).to_ascii_lowercase();
            let observed:Vec<&str>=terms.iter().copied().filter(|term|lower.contains(term)).collect();
            if !observed.is_empty(){
                matches.push(json!({"function":name,
                    "entry_address":func["entry_address"],"matched_terms":observed,
                    "confidence":"keyword_context_only_not_proof"}));
                if matches.len()>=15{break}
            }
        }
        task["decompiled_function_candidates"]=json!(matches);
    }
    Ok(())
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn reports_matching_function_and_context(){
        let dir=std::env::temp_dir().join(format!("keydis-deep-find-test-{}",std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path=dir.join("evidence.json");
        let fixture=json!({"schema_version":1,"functions":[
            {"name":"process_input","entry_address":"0x14001000",
             "pseudocode":"void process_input() {\n  int v = 0x104;\n  return;\n}"},
            {"name":"not_relevant","entry_address":"0x14002000","pseudocode":"void x() {}"}
        ]});
        fs::write(&path,serde_json::to_vec(&fixture).unwrap()).unwrap();
        let r=deep_find(&path,"0x104",1,1,10).unwrap();
        assert_eq!(r["matched_functions"],1);
        assert_eq!(r["results"][0]["function_name"],"process_input");
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
