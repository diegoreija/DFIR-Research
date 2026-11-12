//! Rules over resolved, statically observed call sites.
//! A referenced API is not enough to prove execution or malicious intent.
use goblin::pe::PE;
use serde_json::{json,Value};
use std::collections::{BTreeMap,BTreeSet};

const RULES: &[(&str,&[&str])]=&[
    ("keyboard_capture",&["getasynckeystate","getkeystate","getkeyboardstate","setwindowshookexa","setwindowshookexw","getrawinputdata"]),
    ("keyboard_text_conversion",&["tounicode","tounicodeex","mapvirtualkeya","mapvirtualkeyw","mapvirtualkeyexa","mapvirtualkeyexw"]),
    ("network_io",&["httpsendrequesta","httpsendrequestw","winhttpsendrequest","internetwritefile","wsasend","send","sendto","connect","wsaconnect","winhttpconnect","internetconnecta","internetconnectw"]),
    ("cryptography",&["cryptencrypt","cryptdecrypt","bcryptencrypt","bcryptdecrypt","cryptimportkey","bcryptgeneratekey","cryptacquirecontexta","cryptacquirecontextw"]),
    ("persistence",&["regsetvalueexa","regsetvalueexw","createservicea","createservicew","startservicea","startservicew","movefileexa","movefileexw"]),
    ("process_injection",&["writeprocessmemory","virtualallocex","createremotethread","ntwritevirtualmemory","queueuserapc","ntcreatethreadex"]),
    ("process_launch",&["createprocessa","createprocessw","shellexecutea","shellexecutew","shellexecuteexa","shellexecuteexw","winexec"]),
    ("clipboard_access",&["getclipboarddata","openclipboard"]),
    ("screen_capture",&["bitblt","printwindow","getdc"]),
    ("file_operations",&["createfilea","createfilew","writefile","readfile","deletefilea","deletefilew"]),
    ("anti_debugging",&["isdebuggerpresent","checkremotedebuggerpresent","ntqueryinformationprocess"]),
    ("dynamic_api_loading",&["getprocaddress","loadlibrarya","loadlibraryw","loadlibraryexa","loadlibraryexw","ldrgetprocedureaddress"]),
];
fn matching_categories(api:&str)->Vec<&'static str>{
    RULES.iter().filter_map(|(cat,list)|{
        if list.iter().any(|name|name.eq_ignore_ascii_case(api)){Some(*cat)}else{None}
    }).collect()
}
fn parse_rva(text:&str)->Option<u64>{
    let hex=text.strip_prefix("0x").or_else(||text.strip_prefix("0X"))?;
    u64::from_str_radix(hex,16).ok()
}
pub fn classify(bytes:&[u8],max_functions:usize)->Result<Value,String>{
    if max_functions==0||max_functions>500{return Err("--max-functions must be 1..=500".into())}
    let pe=PE::parse(bytes).map_err(|e|format!("Not a Windows PE: {e}"))?;
    let function_list=crate::reverse::function_candidates(bytes,max_functions)?;
    let mut entries=Vec::new();
    let mut seen_entry=BTreeSet::new();
    entries.push(pe.entry as u64);seen_entry.insert(pe.entry as u64);
    if let Some(candidates)=function_list["candidates"].as_array(){
        for obj in candidates{
            if let Some(rva)=obj["rva"].as_str().and_then(parse_rva){
                if seen_entry.insert(rva){entries.push(rva);}
            }
        }
    }
    entries.truncate(max_functions);
    let mut callsites=BTreeMap::<String,Value>::new();
    let mut hit_by_category=BTreeMap::<String,Vec<Value>>::new();
    let mut analyzed=0usize;
    let mut truncated=0usize;
    for entry in entries {
        let Ok(trace)=crate::flow::trace(bytes,Some(entry),600,80) else{continue};
        analyzed+=1;
        if trace["analysis_truncated"]==true{truncated+=1}
        let Some(calls)=trace["call_sites"].as_array() else{continue};
        for call in calls{
            let Some(api)=call["imported_api"]["name"].as_str() else{continue};
            let site=call["callsite_va"].as_str().unwrap_or("").to_string();
            if callsites.contains_key(&site){continue}
            let tags=matching_categories(api);
            if tags.is_empty(){continue}
            let record=json!({"name":api,"dll":call["imported_api"]["dll"],
                "callsite_rva":call["callsite_rva"],"callsite_va":call["callsite_va"],
                "function_entry_rva":format!("0x{entry:X}"),
                "argument_candidates":call["argument_candidates"],
                "confidence":"static_call_reference"});
            for category in tags{
                hit_by_category.entry(category.into()).or_default().push(record.clone());
            }
            callsites.insert(site,record);
        }
    }
    let mut findings=Vec::new();
    for (category,evidence) in &hit_by_category{
        findings.push(json!({"category":category,"distinct_referenced_calls":evidence.len(),
            "sample_call_sites":evidence.iter().take(25).collect::<Vec<_>>(),
            "confidence":"api_calls_resolved_in_bounded_static_trace",
            "interpretation":"Potential capability indicator, not proof of activity or intent"}));
    }
    let keyboard=hit_by_category.contains_key("keyboard_capture");
    let text=hit_by_category.contains_key("keyboard_text_conversion");
    let network=hit_by_category.contains_key("network_io");
    let mut correlations=Vec::new();
    if keyboard && text{
        correlations.push(json!({"hypothesis":"keystroke_to_text_processing",
            "signals":["keyboard_capture","keyboard_text_conversion"],
            "confidence":"multiple_api_call_categories",
            "limitation":"Data flow from keyboard acquisition to text conversion has not been established"}));
    }
    if keyboard && network{
        correlations.push(json!({"hypothesis":"possible_keystroke_exfiltration",
            "signals":["keyboard_capture","network_io"],
            "confidence":"weak_multi_capability_cooccurrence",
            "limitation":"Keylogger exfiltration requires tracing captured data into a network buffer"}));
    }
    if hit_by_category.contains_key("process_injection"){
        correlations.push(json!({"hypothesis":"possible_remote_process_modification",
            "signals":["process_injection"],"confidence":"candidate",
            "limitation":"Use of individual process APIs is not proof of process injection"}));
    }
    Ok(json!({"engine":"bounded_static_capability_rules_v1",
        "architecture":if pe.is_64{"x64"}else{"x86"},
        "functions_analyzed":analyzed,"functions_truncated_by_budget":truncated,
        "candidate_functions_available":function_list["total_candidates"],
        "matched_calls":callsites.len(),
        "findings":findings,"correlations":correlations,
        "limitations":[
            "Only referenced imports reached from entrypoint or candidate function starts are considered",
            "Dynamically resolved, indirect, or obfuscated calls may be missed",
            "Imported API call does not prove execution or malicious intent",
            "This is not interprocedural taint analysis and does not establish exfiltration",
            "Rule coverage is deliberately finite and misses unrecognized APIs"]}))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn benign_api_names_map_only_to_expected_categories(){
        assert_eq!(matching_categories("ToUnicodeEx"),vec!["keyboard_text_conversion"]);
        assert_eq!(matching_categories("GetAsyncKeyState"),vec!["keyboard_capture"]);
        assert!(matching_categories("BogusFunction").is_empty());
    }
    #[test]
    fn no_false_positive_for_unrelated_io(){
        assert_eq!(matching_categories("ReadFile"),vec!["file_operations"]);
        assert_eq!(matching_categories("CreateRemoteThread"),vec!["process_injection"]);
    }
    #[test]
    fn parse_candidate_function_rva(){
        assert_eq!(parse_rva("0x104"),Some(260));
        assert_eq!(parse_rva("bad"),None);
    }
}
