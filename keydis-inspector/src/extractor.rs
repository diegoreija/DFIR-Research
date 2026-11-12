use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenFinding {
    pub platform: String,
    pub token: String,
    pub risk: String,
}

pub fn identify_and_extract_tokens(raw_strings: &[String]) -> Vec<TokenFinding> {
    let mut findings = Vec::new();

    let telegram_regex = Regex::new(r"^\d{9}:[a-zA-Z0-9_-]{35}$").unwrap();
    let slack_regex = Regex::new(r"^xox[bpas]-[0-9a-zA-Z]{10,48}$").unwrap();
    let discord_regex = Regex::new(r"^(mfa\.[a-z0-9_-]{20,}|[\w-]{24}\.[\w-]{6}\.[\w-]{27})$").unwrap();

    for s in raw_strings {
        if telegram_regex.is_match(s) {
            findings.push(TokenFinding {
                platform: "Telegram Bot".to_string(),
                token: s.clone(),
                risk: "CRÍTICO (Exfiltración C2)".to_string(),
            });
        } else if slack_regex.is_match(s) {
            findings.push(TokenFinding {
                platform: "Slack API".to_string(),
                token: s.clone(),
                risk: "ALTO (Credencial Corporativa)".to_string(),
            });
        } else if discord_regex.is_match(s) {
            findings.push(TokenFinding {
                platform: "Discord Token/Webhook".to_string(),
                token: s.clone(),
                risk: "CRÍTICO (Exfiltración/Robo)".to_string(),
            });
        }
    }
    findings
}