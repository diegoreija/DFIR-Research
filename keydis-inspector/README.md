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

## Ingeniería inversa de ejecutables PE

Los comandos de esta sección **leen el archivo, no lo ejecutan**. Admiten ejecutables PE x86 y x64.

### Desensamblar

```bash
keydis-inspector disasm --input sample.exe --count 30
keydis-inspector disasm --input sample.exe --rva 0x1400 --count 50
```

Las salidas JSON incluyen instrucciones, RVA, VA, offset de archivo, longitud y destinos de control cuando se identifican. `--rva` significa dirección relativa a la imagen PE, **no** offset de archivo.

### Candidatos a funciones y referencias

```bash
keydis-inspector functions --input sample.exe --limit 30
keydis-inspector xref --input sample.exe --api GetAsyncKeyState
keydis-inspector xref --input sample.exe --target-rva 0x1400 --limit 20
keydis-inspector api --input sample.exe --category keyboard --show-references
```

`functions` combina el punto de entrada con los destinos de llamadas directas. `xref` busca referencias directas y algunas referencias a la IAT mediante RIP-relative. Ninguno de los dos demuestra por sí solo límites de funciones ni rastrea todas las llamadas indirectas.

### Constantes y operaciones

```bash
keydis-inspector constants --input sample.exe --value 0x14 --limit 20
keydis-inspector constants --input sample.exe --value 0x104
keydis-inspector constants --input sample.exe --mnemonic xor --limit 30
keydis-inspector keylogger --input sample.exe --vk-code 0x14
keydis-inspector crypto --input sample.exe
```

Se imprimen las instrucciones y las evidencias que respaldan cada coincidencia. No se atribuyen automáticamente claves ni algoritmos de cifrado.

### Hashes candidatos de API

Para probar nombres contra algoritmos conocidos, prepara un diccionario local:

```bash
printf 'GetAsyncKeyState\nSetWindowsHookExA\nToUnicodeEx\n' > winapi-names.txt

keydis-inspector api-hash --hash 0x28331FE9 \
  --dictionary winapi-names.txt --algorithm all

keydis-inspector api-hash --hash 0x28331FE9 \
  --dictionary winapi-names.txt --algorithm ror13-add --case-mode upper
```

Algoritmos: `ror13-add`, `djb2`, `fnv1a`. Se comprueban coincidencias de diccionario, **no se demuestra qué algoritmo utiliza el ejecutable**. Es necesario estudiar la rutina real.

## Validación

```bash
cargo test --all-targets
cargo build --release
./target/release/keydis-inspector --help
```

Las pruebas utilizan instrucciones benignas y un PE sintético; también se ejecutan automáticamente mediante GitHub Actions.

## Límites actuales

- El desensamblado lineal puede confundir datos insertados en código con instrucciones.
- Los candidatos a funciones y las referencias cruzadas son heurísticos; no hay aún recuperación completa de flujo de control ni propagación de argumentos.
- El reconocimiento de compilador usa indicios, pero no garantiza una atribución.
- No se identifican automáticamente algoritmos, claves, tokens cifrados, hashes de API personalizados o exfiltración confirmada.
- El análisis de tiempo sigue exigiendo JSONL normalizado; no hay parser EVTX/PCAP nativo.
- No se ejecuta malware y no se ha validado todavía frente a todas las familias o muestras reales.

## Próximas mejoras

Análisis interprocedimental de flujo de datos, llamadas indirectas, recuperación de algoritmos de hashing, detección y descifrado de configuraciones, EVTX/PCAP, YARA y pruebas con muestras de referencia.


## Flujo de investigación completo (CLI)

Esta CLI separa **hallazgos comprobados** y **candidatos**. No atribuye un algoritmo, una clave ni la funcionalidad de una muestra solo por encontrar una constante o una cadena.

### 1. Inventario inicial

```bash
keydis-inspector intelligence --input sample.exe
keydis-inspector tasks --input sample.exe
keydis-inspector tasks --input sample.exe --task 6
keydis-inspector analyze --input sample.exe --task 10
```

`intelligence` identifica hashes, fecha COFF, imports relacionados con teclado y red, URLs, candidatos de plataforma, posibles tokens en texto claro y firmas criptográficas básicas.

`tasks` construye una hoja estructurada de 19 preguntas de investigación con cuatro posibles estados: valores verificados, metadatos observados, candidatos o información inconclusa. **No garantiza respuestas automáticas** cuando el binario requiere ingeniería inversa semántica.

Para candidatos a tokens, el valor se oculta por defecto. Solo para investigación autorizada:

```bash
keydis-inspector tasks --input sample.exe --task 16 --show-secrets
```

### 2. Recuperación de posibles claves XOR

```bash
keydis-inspector xor-crib --input sample.exe \
  --known "https://api.telegram.org" --max-keylen 8 --limit 10

# Examinar explícitamente una región con una clave XOR conocida
keydis-inspector xor-decode --input sample.exe \
  --offset 0x1400 --length 100 --key-hex 4142 --show-secrets
```

`xor-crib` busca candidatos a clave de XOR repetido a partir de un texto conocido. No es un ataque universal contra cifrados, y los resultados pueden ser falsos positivos. Los secretos recuperados no se muestran sin `--show-secrets`. Los offsets de `xor-decode` son **offsets de fichero**.

### 3. Análisis profundo opcional con Ghidra (sin interfaz gráfica)

Para reconstruir funciones complejas, argumentos y operaciones de descifrado existe el backend opcional de **Ghidra Headless**. Instala Ghidra por separado y localiza su ejecutable `support/analyzeHeadless`. No hace falta abrir la interfaz gráfica.

```bash
keydis-inspector deep --input sample.exe \
  --output deep-report.json \
  --analyze-headless /opt/ghidra/support/analyzeHeadless \
  --max-functions 200 \
  --analysis-timeout 180
```

Ghidra **importa y descompila el fichero; no lo ejecuta**. El informe puede contener cadenas sensibles o tokens: no lo publiques sin revisarlo. El análisis profundo depende de disponer de una instalación de Ghidra compatible y no se valida en la CI de Rust.

Una vez generado el JSON puedes buscar en el código descompilado sin usar `grep`:

```bash
keydis-inspector deep-find --report deep-report.json \
  --contains "0x104" --before 3 --after 5

keydis-inspector deep-find --report deep-report.json \
  --contains "ToUnicodeEx" --limit 20

keydis-inspector deep-find --report deep-report.json \
  --contains "0x28331FE9"
```

También puedes asociar **funciones candidatas** a las preguntas pendientes:

```bash
keydis-inspector tasks --input sample.exe \
  --deep-report deep-report.json

keydis-inspector tasks --input sample.exe \
  --task 17 --deep-report deep-report.json
```

Los fragmentos de código descompilado no se transforman automáticamente en respuestas confirmadas. La investigación sigue requiriendo comprobar el flujo de ejecución y los datos.

### 4. Exportación

```bash
keydis-inspector report --input sample.exe --output evidence.json
```

Guarda inventario y hoja de investigación en un JSON estructurado.

### Limitaciones fundamentales

- No existe un método universal de análisis estático que identifique automáticamente cualquier algoritmo criptográfico, clave, llamada indirecta o dato cifrado de un binario desconocido.
- Para afirmar que un token es válido, que una API es la función ejecutada o que un valor causa una transmisión hay que seguir sus referencias y, cuando sea necesario, analizarlo dinámicamente en un entorno aislado.
- Sin disponer de una muestra concreta para contrastar, solo pueden verificarse tests con archivos sintéticos y las propiedades de los algoritmos implementados.
- El backend de Ghidra es opcional; los comandos nativos de Rust no lo necesitan.

## Seguridad

Analiza muestras sospechosas únicamente en entornos autorizados y aislados. No ejecutes archivos desconocidos en tu equipo de trabajo.
