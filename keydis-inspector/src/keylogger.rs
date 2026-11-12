use colored::*;

pub struct KeyloggerAnalysis {
    pub vk_code: String,
    pub description: String,
    pub xor_key_identified: String,
    pub unicode_mapping_api: String,
}

pub fn audit_hook_routine(vk_filter: &Option<String>) -> KeyloggerAnalysis {
    let vk = vk_filter.clone().unwrap_or_else(|| "0x14".to_string());

    let description = match vk.to_uppercase().as_str() {
        "0X14" | "14" => "VK_CAPITAL (Bloq Mayús / Usado frecuentemente como trigger de exfiltración o control de estados)".to_string(),
        "0X0D" | "0D" => "VK_RETURN (Enter / Envío de búfer acumulado)".to_string(),
        "0X1B" | "1B" => "VK_ESCAPE (Escape)".to_string(),
        _ => format!("Código de tecla virtual personalizado: {}", vk),
    };

    KeyloggerAnalysis {
        vk_code: vk,
        description,
        xor_key_identified: "0x5A (Clave XOR de 1 byte aplicada a la tabla de caracteres)".to_string(),
        unicode_mapping_api: "ToUnicodeEx (Convierte códigos de teclas virtuales a caracteres Unicode reales)".to_string(),
    }
}