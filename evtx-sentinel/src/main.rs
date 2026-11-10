mod hunter;
mod parser;

use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "evtx-sentinel",
    version = "2.4.0",
    about = "Kali Linux Advanced DFIR & Threat Hunting Engine para archivos .evtx"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Busca automáticamente patrones de ataques (Malware, Timestomping, Conexiones)
    Hunt {
        /// Ruta al archivo .evtx
        #[arg(short, long)]
        input: PathBuf,

        /// Filtrar por Event IDs separados por coma (ej. 1,2,3,11)
        #[arg(short, long, value_delimiter = ',')]
        event_id: Vec<u64>,

        /// Filtrar por palabra clave
        #[arg(short, long)]
        filter: Option<String>,

        /// Exportar resultados a JSON
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Nivel de verbosidad (-v, -vv, -vvv)
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
    },
    /// Extrae y lista eventos según filtros exactos
    Parse {
        /// Ruta al archivo .evtx
        #[arg(short, long)]
        input: PathBuf,

        /// Filtrar por Event IDs separados por coma
        #[arg(short, long, value_delimiter = ',')]
        event_id: Vec<u64>,

        /// Filtrar por palabra clave
        #[arg(short, long)]
        filter: Option<String>,

        /// Exportar resultados a JSON
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Nivel de verbosidad
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
    },
}

fn main() {
    let cli = Cli::parse();

    println!("{}", "=== EVTX-SENTINEL v2.4.0 // Kali DFIR Engine ===".cyan().bold());

    match &cli.command {
        Commands::Hunt { input, event_id, filter, output, verbose } => {
            println!("{} Modo HUNT activado sobre: {:?}\n", "[*]".blue(), input);
            parser::process_evtx(input, event_id, filter.as_deref(), true, *verbose, output.as_ref());
        }
        Commands::Parse { input, event_id, filter, output, verbose } => {
            println!("{} Modo PARSE activado sobre: {:?}\n", "[*]".blue(), input);
            parser::process_evtx(input, event_id, filter.as_deref(), false, *verbose, output.as_ref());
        }
    }
}