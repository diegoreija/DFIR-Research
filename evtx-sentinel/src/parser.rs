use crate::hunter::{evaluate_event, ThreatFinding};
use colored::*;
use evtx::EvtxParser;
use serde_json::Value;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

pub fn process_evtx(
    input_path: &PathBuf,
    event_ids: &[u64],
    filter_text: Option<&str>,
    hunt_mode: bool,
    verbosity: u8,
    output_path: Option<&PathBuf>,
) {
    let mut parser = match EvtxParser::from_path(input_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} No se pudo abrir el archivo {:?}: {}", "[!]".red().bold(), input_path, e);
            return;
        }
    };

    let mut total_parsed = 0;
    let mut findings: Vec<ThreatFinding> = Vec::new();

    for record in parser.records_json() {
        total_parsed += 1;
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                if verbosity >= 3 {
                    eprintln!("{} Error parseando registro {}: {}", "[DEBUG]".dimmed(), total_parsed, e);
                }
                continue;
            }
        };

        let json_val: Value = match serde_json::from_str(&record.data) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let ev_id = json_val["Event"]["System"]["EventID"]
            .as_u64()
            .or_else(|| json_val["Event"]["System"]["EventID"]["#text"].as_u64())
            .unwrap_or(0);

        // Filtrar por Event ID si se especificó
        if !event_ids.is_empty() && !event_ids.contains(&ev_id) {
            continue;
        }

        // Filtrar por texto si se especificó
        if let Some(keyword) = filter_text {
            if !record.data.to_lowercase().contains(&keyword.to_lowercase()) {
                continue;
            }
        }

        let timestamp = json_val["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"]
            .as_str()
            .unwrap_or("N/A");

        if hunt_mode {
            if let Some(finding) = evaluate_event(ev_id, timestamp, &json_val) {
                findings.push(finding);
            }
        } else {
            // Modo parse normal: mostrar coincidencia directa
            findings.push(ThreatFinding {
                event_id: ev_id,
                timestamp: timestamp.to_string(),
                category: "Raw Event".to_string(),
                payload: record.data.chars().take(120).collect::<String>() + "...",
                risk: "INFO".to_string(),
            });
        }
    }

    if verbosity >= 1 {
        println!("{} Parseados {} registros totales.", "[+]".green(), total_parsed);
    }
    println!("{} Coincidencias encontradas: {}\n", "[+]".green().bold(), findings.len());

    // Imprimir tabla en consola
    println!("{:<10} | {:<20} | {:<25} | {}", "Event ID".bold(), "Categoría".bold(), "Riesgo".bold(), "Payload / Detalle".bold());
    println!("{}", "-".repeat(100));

    for f in &findings {
        let risk_colored = if f.risk.contains("CRÍTICO") {
            f.risk.red().bold()
        } else if f.risk.contains("ALTO") {
            f.risk.yellow().bold()
        } else {
            f.risk.cyan()
        };

        println!("{:<10} | {:<20} | {:<25} | {}", f.event_id, f.category, risk_colored, f.payload);
    }

    // Exportar a JSON si se indicó --output
    if let Some(out) = output_path {
        if let Ok(json_out) = serde_json::to_string_pretty(&findings) {
            if let Ok(mut file) = File::create(out) {
                let _ = file.write_all(json_out.as_bytes());
                println!("\n{} Informe exportado a {:?}", "[+]".green().bold(), out);
            }
        }
    }
}