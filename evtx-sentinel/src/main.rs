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
    about = "Kali Linux Advanced DFIR & Threat Hunting Engine",
    long_about = "Designed for offline forensic analysis of Windows event logs (.evtx) and advanced threat hunting.",
    help_template = "\
{bin} v{version} [{about}]
{long-about}

USAGE:
    {usage}

COMMANDS PRINCIPALES:
{subcommands}

OPCIONES GENERALES:
{all-args}

EJEMPLOS DE USO:
    evtx-sentinel hunt -i ./Sysmon.evtx -e 1,11 -vvv
    evtx-sentinel parse -i ./unit42/ --filter \"powershell.exe\" --output ./result.json
"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Extract and list all events from the analyzed file based on filters.
    Parse {
        /// Path to the .evtx file or directory containing evidences
        #[arg(short, long)]
        input: PathBuf,

        /// Filter by specific Event ID (e.g. 1, 3, 11, 22)
        #[arg(short, long, value_delimiter = ',')]
        event_id: Vec<u64>,

        /// Filter by keyword in command line or file path
        #[arg(short, long)]
        filter: Option<String>,

        /// Export results report in JSON or CSV format
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Number of concurrent threads for massive processing (default: 4)
        #[arg(short, long, default_value_t = 4)]
        threads: usize,

        /// Verbosity level (-v, -vv, -vvv for forensic debugging)
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
    },
    /// Automatically hunt for known attack patterns (e.g., Backdoors, Timestomping, RCE)
    Hunt {
        /// Path to the .evtx file or directory containing evidences
        #[arg(short, long)]
        input: PathBuf,

        /// Filter by specific Event ID
        #[arg(short, long, value_delimiter = ',')]
        event_id: Vec<u64>,

        /// Filter by keyword
        #[arg(short, long)]
        filter: Option<String>,

        /// Export results report in JSON or CSV format
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Number of concurrent threads for massive processing (default: 4)
        #[arg(short, long, default_value_t = 4)]
        threads: usize,

        /// Query suspicious hashes against heuristics or local simulation
        #[arg(short, long)]
        search_vt: bool,

        /// Verbosity level (-v, -vv, -vvv for forensic debugging)
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
    },
    /// Generate a unified exportable chronological timeline
    Timeline {
        /// Path to the .evtx file or directory containing evidences
        #[arg(short, long)]
        input: PathBuf,

        /// Export results report in JSON or CSV format
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Verbosity level (-v, -vv, -vvv for forensic debugging)
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
    },
}

fn main() {
    let cli = Cli::parse();

    println!("{}", "=== EVTX-SENTINEL v2.4.0 // Kali DFIR Engine ===".cyan().bold());

    match &cli.command {
        Commands::Hunt { input, event_id, filter, output, threads, search_vt, verbose } => {
            println!("{} HUNT mode activated on: {:?} (Threads: {}, VT: {}) \n", "[*]".blue(), input, threads, search_vt);
            parser::process_evtx(input, event_id, filter.as_deref(), true, *verbose, output.as_ref());
        }
        Commands::Parse { input, event_id, filter, output, threads, verbose } => {
            println!("{} PARSE mode activated on: {:?} (Threads: {}) \n", "[*]".blue(), input, threads);
            parser::process_evtx(input, event_id, filter.as_deref(), false, *verbose, output.as_ref());
        }
        Commands::Timeline { input, output: _output, verbose: _verbose } => {
            println!("{} TIMELINE mode activated on: {:?} \n", "[*]".blue(), input);
        }
    }
}
