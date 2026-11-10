use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFinding {
    pub event_id: u64,
    pub timestamp: String,
    pub category: String,
    pub payload: String,
    pub risk: String,
}

pub fn evaluate_event(event_id: u64, timestamp: &str, data: &Value) -> Option<ThreatFinding> {
    let data_str = data.to_string().to_lowercase();

    match event_id {
        // Event ID 1: Process Creation
        1 => {
            let suspicious_paths = ["\\appdata\\", "\\temp\\", "\\users\\public\\", "powershell", "cmd.exe /c", "rundll32"];
            if suspicious_paths.iter().any(|&p| data_str.contains(p)) {
                let image = data["Event"]["EventData"]["Image"].as_str().unwrap_or("Desconocido");
                let cmd = data["Event"]["EventData"]["CommandLine"].as_str().unwrap_or("");
                return Some(ThreatFinding {
                    event_id,
                    timestamp: timestamp.to_string(),
                    category: "Process Creation".to_string(),
                    payload: format!("{} {}", image, cmd),
                    risk: "CRÍTICO (Ejecución Anómala)".to_string(),
                });
            }
        }
        // Event ID 2: File Creation Time Changed (Timestomping)
        2 => {
            let target = data["Event"]["EventData"]["TargetFilename"].as_str().unwrap_or("Desconocido");
            let new_time = data["Event"]["EventData"]["CreationUtcTime"].as_str().unwrap_or("N/A");
            return Some(ThreatFinding {
                event_id,
                timestamp: timestamp.to_string(),
                category: "Time Stomping".to_string(),
                payload: format!("Target: {} -> Nueva fecha: {}", target, new_time),
                risk: "ALTO (Evasión)".to_string(),
            });
        }
        // Event ID 3: Network Connection
        3 => {
            let dest_ip = data["Event"]["EventData"]["DestinationIp"].as_str().unwrap_or("0.0.0.0");
            let dest_port = data["Event"]["EventData"]["DestinationPort"].as_u64().unwrap_or(0);
            let image = data["Event"]["EventData"]["Image"].as_str().unwrap_or("Desconocido");
            if !dest_ip.starts_with("127.") && !dest_ip.starts_with("192.168.") && !dest_ip.starts_with("10.") {
                return Some(ThreatFinding {
                    event_id,
                    timestamp: timestamp.to_string(),
                    category: "Network Connection".to_string(),
                    payload: format!("{} -> {}:{}", image, dest_ip, dest_port),
                    risk: "MEDIO (Conexión Externa)".to_string(),
                });
            }
        }
        // Event ID 11: File Created
        11 => {
            let target = data["Event"]["EventData"]["TargetFilename"].as_str().unwrap_or("");
            if target.to_lowercase().ends_with(".exe") || target.to_lowercase().ends_with(".dll") || target.to_lowercase().ends_with(".ps1") {
                return Some(ThreatFinding {
                    event_id,
                    timestamp: timestamp.to_string(),
                    category: "File Created".to_string(),
                    payload: target.to_string(),
                    risk: "ALTO (Binario/Script en disco)".to_string(),
                });
            }
        }
        _ => {}
    }
    None
}