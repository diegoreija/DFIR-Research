mod hunter;
mod parser;

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

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Interceptamos la ayuda de forma nativa para que imprima exactamente tu texto plano
    if args.len() == 1 || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", HELP_MESSAGE);
        return;
    }

    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("evtx-sentinel v2.4.0");
        return;
    }

    // Extracción limpia de parámetros para el motor de la herramienta
    let mut command = "";
    let mut input_path = None;
    let mut event_ids = vec![];
    let mut filter_text = None;
    let mut output_path = None;
    let mut threads = 4;
    let mut search_vt = false;
    let mut verbose = 0;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "hunt" | "parse" | "timeline" => {
                command = &args[i];
            }
            "-i" | "--input" => {
                if i + 1 < args.len() {
                    input_path = Some(PathBuf::from(&args[i + 1]));
                    i += 1;
                }
            }
            "-e" | "--event-id" => {
                if i + 1 < args.len() {
                    event_ids = args[i + 1]
                        .split(',')
                        .filter_map(|s| s.trim().parse::<u64>().ok())
                        .collect();
                    i += 1;
                }
            }
            "-f" | "--filter" => {
                if i + 1 < args.len() {
                    filter_text = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-o" | "--output" => {
                if i + 1 < args.len() {
                    output_path = Some(PathBuf::from(&args[i + 1]));
                    i += 1;
                }
            }
            "-t" | "--threads" => {
                if i + 1 < args.len() {
                    threads = args[i + 1].parse().unwrap_or(4);
                    i += 1;
                }
            }
            "-s" | "--search-vt" => {
                search_vt = true;
            }
            other => {
                if other.starts_with("-v") {
                    verbose += other.chars().filter(|&c| c == 'v').count() as u8;
                }
            }
        }
        i += 1;
    }

    if command.is_empty() {
        print!("{}", HELP_MESSAGE);
        return;
    }

    println!("{}", "=== EVTX-SENTINEL v2.4.0 // Kali DFIR Engine ===".cyan().bold());

    let input = match input_path {
        Some(p) => p,
        None => {
            println!("{}", "[!] Error: Missing input path. Use -i <path>".red());
            return;
        }
    };

    match command {
        "hunt" => {
            println!("{} HUNT mode activated on: {:?} (Threads: {}, VT: {}) \n", "[*]".blue(), input, threads, search_vt);
            parser::process_evtx(&input, &event_ids, filter_text.as_deref(), true, verbose, output_path.as_ref());
        }
        "parse" => {
            println!("{} PARSE mode activated on: {:?} (Threads: {}) \n", "[*]".blue(), input, threads);
            parser::process_evtx(&input, &event_ids, filter_text.as_deref(), false, verbose, output_path.as_ref());
        }
        "timeline" => {
            println!("{} TIMELINE mode activated on: {:?} \n", "[*]".blue(), input);
        }
        _ => {
            print!("{}", HELP_MESSAGE);
        }
    }
}
