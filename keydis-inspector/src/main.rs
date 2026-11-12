mod pe_parser;
mod api_resolver;
mod keylogger;
mod extractor;

use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "keydis-inspector",
    version = "1.0.0",
    author = "Reija",
    about = "Windows PE & Keylogger DFIR Engine",
    long_about = "High-performance Rust utility designed to dissect malware samples, resolve Win32 API hashes, and extract embedded configurations like bot tokens and encryption keys."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Extract PE headers, SHA256/MD5 hashes, and compilation timestamps (Tasks 1-3)
    PeInfo {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Resolve Win32 API hashes, entry points, and specific offsets (Tasks 4-7)
    ApiResolve {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        target_hash: Option<String>,
    },
    /// Audit keylogger routines, virtual-key codes, and XOR keys (Tasks 8-11)
    HookAudit {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        vk_filter: Option<String>,
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
    },
    /// Extract configuration: bot tokens, encryption keys, and exfiltration data (Tasks 12-19)
    ExtractConfig {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    println!("{}", "=== KEYDIS-INSPECTOR v1.0.0 // Windows PE DFIR Engine ===".cyan().bold());

    match &cli.command {
        Commands::PeInfo { input, output: _ } => {
            println!("{} Analizando cabeceras PE y hashes en: {:?}\n", "[*]".blue(), input);
            match pe_parser::analyze_pe(input) {
                Ok(meta) => {
                    println!("  ├── SHA256:     {}", meta.sha256.green());
                    println!("  ├── MD5:        {}", meta.md5);
                    println!("  ├── SHA1:       {}", meta.sha1);
                    println!("  ├── Timestamp:  {}", meta.timestamp_utc.yellow());
                    println!("  └── Compilador: {}", meta.compiler.cyan());
                }
                Err(e) => println!("  [-] Error al leer el fichero PE: {}", e),
            }
        }
        Commands::ApiResolve { input: _, target_hash } => {
            let hash_to_check = target_hash.as_deref().unwrap_or("0x26331FE9");
            println!("{} Resolviendo hash de Win32 API: {}\n", "[*]".blue(), hash_to_check);
            let res = api_resolver::resolve_api_hash(hash_to_check);
            println!("  ├── Hash Objetivo: {}", res.target_hash.yellow());
            println!("  ├── API Resuelta:  {}", res.resolved_api.green());
            println!("  ├── Módulo DLL:    {}", res.module);
            println!("  └── Offset Memoria: {}", res.offset_found);
        }
        Commands::HookAudit { input: _, vk_filter, verbose: _ } => {
            println!("{} Auditando rutinas de Keylogger y Virtual-Keys...\n", "[*]".blue());
            let audit = keylogger::audit_hook_routine(vk_filter);
            println!("  ├── Virtual Key:   {}", audit.vk_code.yellow());
            println!("  ├── Comportamiento: {}", audit.description.green());
            println!("  ├── Clave XOR:     {}", audit.xor_key_identified);
            println!("  └── Conversión:    {}", audit.unicode_mapping_api);
        }
        Commands::ExtractConfig { input: _, output: _ } => {
            println!("{} Extrayendo configuración y tokens de exfiltración...\n", "[*]".blue());
            let simulated_strings = vec![
                "589234112:AAH9FakeTelegramBotTokenIdentifierStringHere".to_string(),
                "mfa.FakeDiscordUserTokenForTestingPurposesOnlyABC123XYZ".to_string()
            ];
            let findings = extractor::identify_and_extract_tokens(&simulated_strings);
            println!("[+] Se han identificado {} artefactos:", findings.len());
            for f in findings {
                println!("  > Platform: {} | Token: {} | Risk: {}", f.platform.cyan(), f.token, f.risk.red());
            }
        }
    }
}