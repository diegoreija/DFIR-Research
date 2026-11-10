mod hunter;
mod parser;

use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "evtx-sentinel",
    version = "2.4.0",
    author = "Reija",
    about = "Kali Linux Advanced DFIR & Threat Hunting Engine for .evtx files",
    long_about = "EVTX-Sentinel is a high-performance offline forensics and threat hunting utility designed to parse Windows Event Logs, correlate anomalies, and detect adversary techniques."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Automatically hunt for attack patterns (Malware, Timestomping, Network IOCs)
    Hunt {
        /// Path to the .evtx file or directory containing evidences
        #[arg(short, long)]
        input: PathBuf,

        /// Filter by Event IDs separated by commas (e.g., 1,3,11,22)
        #[arg(short, long, value_delimiter = ',')]
        event_id: Vec<u64>,

        /// Filter records by keyword
        #[arg(short, long)]
        filter: Option<String>,

        /// Export results to a structured JSON report
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Number of concurrent threads for massive processing (default: 4)
        #[arg(short, long, default_value_t = 4)]
        threads: usize,

        /// Verbosity level (-v, -vv, -vvv for deep forensic debugging)
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
    },
    /// Extract and list raw events based on precise filters
    Parse {
        /// Path to the .evtx file or directory containing evidences
        #[arg(short, long)]
        input: PathBuf,

        /// Filter by Event IDs separated by commas
        #[arg(short, long, value_delimiter = ',')]
        event_id: Vec<u64>,

        /// Filter records by keyword
        #[arg(short, long)]
        filter: Option<String>,

        /// Export results to a structured JSON report
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Number of concurrent threads
        #[arg(short, long, default_value_t = 4)]
        threads: usize,

        /// Verbosity level (-v, -vv, -vvv)
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
    },
    /// Generate a unified chronological timeline exportable
    Timeline {
        /// Path to the .evtx file or directory containing evidences
        #[arg(short, long)]
        input: PathBuf,

        /// Export results to a structured JSON or CSV report
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Verbosity level (-v, -vv, -vvv)
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
    },
}

fn main() {
    let cli = Cli::parse();

    println!("{}", "=== EVTX-SENTINEL v2.4.0 // Kali DFIR Engine ===".cyan().bold());

    match &cli.command {
        Commands::Hunt { input, event_id, filter, output, threads, verbose } => {
            println!("{} HUNT mode activated on: {:?} (Threads: {}) \n", "[*]".blue(), input, threads);
            parser::process_evtx(input, event_id, filter.as_deref(), true, *verbose, output.as_ref());
        }
        Commands::Parse { input, event_id, filter, output, threads, verbose } => {
            println!("{} PARSE mode activated on: {:?} (Threads: {}) \n", "[*]".blue(), input, threads);
            parser::process_evtx(input, event_id, filter.as_deref(), false, *verbose, output.as_ref());
        }
        Commands::Timeline { input, output: _output, verbose: _verbose } => {
            println!("{} TIMELINE mode activated on: {:?} \n", "[*]".blue(), input);
            // Lógica de línea temporal unificada
        }
    }
}
