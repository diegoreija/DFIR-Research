mod hunter;
mod parser;

use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;

const HELP_MESSAGE: &str = r#"evtx-sentinel v2.4.0 [Kali Linux Advanced DFIR & Threat Hunting Engine]
Diseñado para análisis forense de registros de Windows (.evtx) y caza de amenazas offline.

USO:
    evtx-sentinel [COMANDO] [OPCIONES] <ARCHIVO_O_DIRECTORIO>

COMANDOS PRINCIPALES:
    parse        Extrae y lista todos los eventos del fichero analizado según filtros.
    hunt         Busca automáticamente patrones de ataques conocidos (Ej: Backdoors, Timestomping, RCE).
    timeline     Genera una línea temporal cronológica unificada exportable.

OPCIONES GENERALES:
    -i, --input <PATH>       Ruta al archivo .evtx o directorio con evidencias.
    -e, --event-id <ID>      Filtra por Event ID específico (ej. 1, 3, 11, 22).
    -f, --filter <TEXTO>     Filtra por palabra clave en la línea de comandos o ruta de archivo.
    -o, --output <DIR>       Exporta el informe de resultados en formato JSON o CSV.

OPCIONES AVANZADAS Y DE RENDIMIENTO:
    -t, --threads <NUM>      Número de hilos concurrentes para procesamiento masivo (por defecto: 4).
    -s, --search-vt          Consulta hashes sospechosos contra heurística o simulación local.
    -v, --verbose            Nivel de detalle en pantalla (-v, -vv, -vvv para depuración forense).
    -h, --help               Muestra esta pantalla de ayuda y sale.

EJEMPLOS DE USO:
    evtx-sentinel hunt -i ./Microsoft-Windows-Sysmon%40Operational.evtx -e 1,11 -VVV
    evtx-sentinel parse -i ./unit42/ --filter "powershell.exe" --output ./resultado.json
"#;

#[derive(Parser)]
#[command(name = "evtx-sentinel", version = "2.4.0", author = "Reija", disable_help_flag = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(short, long)]
    help: bool,
}

#[derive(Subcommand)]
enum Commands {
    Parse {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long, value_delimiter = ',')]
        event_id: Vec<u64>,
        #[arg(short, long)]
        filter: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long, default_value_t = 4)]
        threads: usize,
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
    },
    Hunt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long, value_delimiter = ',')]
        event_id: Vec<u64>,
        #[arg(short, long)]
        filter: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long, default_value_t = 4)]
        threads: usize,
        #[arg(short, long)]
        search_vt: bool,
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
    },
    Timeline {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
    },
}

fn main() {
    let cli = Cli::parse();

    if cli.help || cli.command.is_none() {
        print!("{}", HELP_MESSAGE);
        return;
    }

    println!("{}", "=== EVTX-SENTINEL v2.4.0 // Kali DFIR Engine ===".cyan().bold());

    match cli.command.unwrap() {
        Commands::Hunt { input, event_id, filter, output, threads, search_vt, verbose } => {
            println!("{} HUNT mode activated on: {:?} (Threads: {}, VT: {}) \n", "[*]".blue(), input, threads, search_vt);
            parser::process_evtx(&input, &event_id, filter.as_deref(), true, verbose, output.as_ref());
        }
        Commands::Parse { input, event_id, filter, output, threads, verbose } => {
            println!("{} PARSE mode activated on: {:?} (Threads: {}) \n", "[*]".blue(), input, threads);
            parser::process_evtx(&input, &event_id, filter.as_deref(), false, verbose, output.as_ref());
        }
        Commands::Timeline { input, output: _output, verbose: _verbose } => {
            println!("{} TIMELINE mode activated on: {:?} \n", "[*]".blue(), input);
        }
    }
}
