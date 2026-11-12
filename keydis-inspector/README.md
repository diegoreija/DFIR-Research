# KeyDis Inspector

**CLI de análisis estático de ejecutables Windows y filtrado de evidencias forenses**, desarrollada en Rust. Diseñada para consultas específicas por terminal, con resultados JSON fáciles de procesar.

> Estado: versión inicial en desarrollo. Algunas funciones avanzadas de ingeniería inversa aún no están implementadas. Los hallazgos no confirmados se indican como tales.

## Instalación

Requisitos: Rust y Cargo.

```bash
git clone https://github.com/diegoreija/DFIR-Research.git
cd DFIR-Research/keydis-inspector
cargo build --release
./target/release/keydis-inspector --help
```

También puedes usar `cargo run -- <comando>` durante el desarrollo.

## Sintaxis

```bash
keydis-inspector <COMANDO> [OPCIONES]
```

Los ejemplos siguientes asumen que `keydis-inspector` está disponible en el PATH. Si no, utiliza `./target/release/keydis-inspector`.

## Comandos disponibles

### Análisis general

```bash
keydis-inspector analyze --input sample.exe
keydis-inspector analyze --input sample.exe --profile general
keydis-inspector analyze --input sample.exe --task 1
```

`analyze` reúne hashes, metadatos PE disponibles y candidatos a IOC. `--task 1` muestra el SHA-256; `--task 2` consulta el timestamp PE. **El resto de números de tarea no representan todavía análisis especializados** y no deben interpretarse como respuestas automáticas.

### Hashes

```bash
keydis-inspector hash --input sample.exe
keydis-inspector hash --input sample.exe --algorithm sha256
keydis-inspector hash --input sample.exe --algorithm sha1
keydis-inspector hash --input sample.exe --algorithm md5
```

Calcula hashes reales del archivo. `--algorithm all` es el valor predeterminado.

### Estructura PE

```bash
keydis-inspector pe --input sample.exe
keydis-inspector pe --input sample.exe --view imports
keydis-inspector pe --input sample.exe --view sections
keydis-inspector compiler --input sample.exe
```

Consulta arquitectura, punto de entrada, timestamp, secciones e imports. El comando `compiler` informa `INCONCLUSIVE` hasta disponer de identificación fiable del compilador.

### APIs de Windows

```bash
keydis-inspector api --input sample.exe
keydis-inspector api --input sample.exe --contains Key
keydis-inspector api --input sample.exe --category keyboard --limit 10
keydis-inspector api --input sample.exe --category network
keydis-inspector api --input sample.exe --category crypto
```

Filtra las **APIs importadas** por nombre o categoría. No resuelve hashes de API ni demuestra ejecución dinámica.

### Bytes y offsets

```bash
keydis-inspector offset --input sample.exe --offset 0x104 --length 16
keydis-inspector hex --input sample.exe --offset 0x200 --length 64
```

Lee bytes en posiciones del **archivo**. Los offsets no son direcciones virtuales ni desplazamientos relativos a funciones.

### Búsqueda de cadenas

```bash
keydis-inspector strings --input sample.exe
keydis-inspector strings --input sample.exe --contains http --ignore-case
keydis-inspector strings --input sample.exe --regex 'https?://[^ ]+' --limit 20
keydis-inspector strings --input sample.exe --min-length 8 --limit 50
```

Extrae cadenas ASCII y UTF-16LE imprimibles, permite buscar texto o expresiones regulares y limita la cantidad de resultados.

### Indicadores y análisis preliminar

```bash
keydis-inspector ioc --input sample.exe --limit 25
keydis-inspector keylogger --input sample.exe --vk-code 0x14
keydis-inspector crypto --input sample.exe
keydis-inspector exfil --input sample.exe
keydis-inspector config --input sample.exe
keydis-inspector config --input sample.exe --show-secrets
```

- `ioc`: extrae URLs candidatas; todavía no implementa extracción completa de IP y dominios.
- `keylogger`: consulta códigos VK conocidos y referencias a imports relacionados con teclado; no confirma captura de teclas.
- `crypto`: informa imports criptográficos, sin atribuir algoritmos o claves no demostrados.
- `exfil`: lista referencias de red y URLs candidatas, sin afirmar que exista exfiltración.
- `config`: busca cadenas candidatas relacionadas con tokens y secretos; oculta su contenido por defecto. `--show-secrets` puede exponer información sensible en el terminal o logs.

### Informes y comparación

```bash
keydis-inspector report --input sample.exe --output report.json
keydis-inspector compare --file-a sample1.exe --file-b sample2.exe
```

`report` genera un JSON con hashes, metadatos PE e IOC candidatos. `compare` presenta información de ambos archivos e indica si son idénticos byte a byte.

### Timeline y filtrado de eventos

La versión actual trabaja con **JSONL normalizado**, no con EVTX ni PCAP nativos. Cada línea debe ser un objeto JSON con `timestamp` en formato RFC 3339:

```json
{"timestamp":"2026-11-01T08:12:04Z","event_id":1,"process":"sample.exe","activity":"Process created"}
{"timestamp":"2026-11-01T08:12:07Z","event_id":3,"process":"sample.exe","activity":"Network connection"}
```

Guardar como `events.jsonl` (una línea JSON por evento).

```bash
# Todos los eventos (hasta el límite predeterminado)
keydis-inspector timeline --input events.jsonl

# Intervalo cerrado de fechas UTC
keydis-inspector timeline --input events.jsonl --start-time 2026-11-01T08:00:00Z --end-time 2026-11-01T09:00:00Z

# Desde una fecha en adelante
keydis-inspector timeline --input events.jsonl --start-time 2026-11-01T08:00:00Z

# Hasta una fecha
keydis-inspector timeline --input events.jsonl --end-time 2026-11-01T09:00:00Z

# Diez minutos antes y después de un instante
keydis-inspector timeline --input events.jsonl --around 2026-11-01T08:12:00Z --window 10m

# Solo conexiones de red del proceso indicado
keydis-inspector events --input events.jsonl --event-id 3 --process sample.exe --limit 10

# Orden descendente
keydis-inspector events --input events.jsonl --sort desc
```

`--window` admite minutos (`m`) y horas (`h`); `--around` no se puede combinar con `--start-time` ni `--end-time`. Los filtros temporales son inclusivos. `--sort` admite `asc` o `desc`.

## Ejemplos de salida

El programa imprime JSON por defecto, para facilitar búsquedas y automatizaciones. Ejemplo **ilustrativo** de `pe --view summary`:

```json
{
  "entry_rva": 4096,
  "timestamp_utc": "2025-06-14T09:42:11+00:00",
  "timestamp_untrusted": true,
  "is_64": true,
  "sections_count": 4,
  "imports_count": 12
}
```

Ejemplo de consulta selectiva:

```bash
keydis-inspector strings --input sample.exe --contains http --limit 5
```

## Límites actuales

- No ejecuta muestras ni realiza análisis dinámico.
- No desensambla funciones ni reconstruye el flujo de control.
- No identifica todavía algoritmos de hashes de API, claves criptográficas o descifrados específicos.
- No analiza EVTX, PCAP o archivos comprimidos directamente.
- Los timestamps de PE pueden estar manipulados.
- Los indicadores encontrados son candidatos, no confirmaciones de actividad maliciosa.
- No se ha verificado todavía la compilación mediante CI ni la ejecución con muestras reales.

## Próximas mejoras

Pruebas automatizadas, desensamblado y referencias a evidencia, identificación de compiladores, resolución de hashes de APIs, parsers EVTX/PCAP, reglas YARA, inspección de archivos comprimidos y filtros adicionales.

## Seguridad

Analiza muestras sospechosas únicamente en entornos autorizados y aislados. No ejecutes archivos desconocidos en tu equipo de trabajo.
