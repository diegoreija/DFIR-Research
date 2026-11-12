use colored::*;

pub struct ApiResolutionResult {
    pub target_hash: String,
    pub resolved_api: String,
    pub module: String,
    pub offset_found: String,
}

pub fn resolve_api_hash(hash_input: &str) -> ApiResolutionResult {
    // Base de datos interna de hashes comunes de Win32 API en malware (ej. Metasploit/CobaltStrike/Keyloggers)
    let normalized_input = hash_input.trim().to_lowercase();

    match normalized_input.as_str() {
        "0x26331fe9" | "26331fe9" => ApiResolutionResult {
            target_hash: hash_input.to_string(),
            resolved_api: "SetWindowsHookExA / SetWindowsHookExW".to_string(),
            module: "user32.dll".to_string(),
            offset_found: "0x104".to_string(),
        },
        "0x7c2a11b2" | "7c2a11b2" => ApiResolutionResult {
            target_hash: hash_input.to_string(),
            resolved_api: "GetAsyncKeyState".to_string(),
            module: "user32.dll".to_string(),
            offset_found: "0x08A".to_string(),
        },
        _ => ApiResolutionResult {
            target_hash: hash_input.to_string(),
            resolved_api: "[-] API no encontrada en la base de datos interna de hashes Win32".to_string(),
            module: "N/A".to_string(),
            offset_found: "Desconocido".to_string(),
        }
    }
}