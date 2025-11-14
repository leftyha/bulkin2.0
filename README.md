# Bulkin 2.0

Suite modular para automatizar recon, discovery, explotación segura y lógica de negocio en programas de Bug Bounty (BBP).

## Contenido del repositorio

- `core_runner.py`: orquestador maestro que encadena todos los módulos.
- `core_recon.py`: reconocimiento pasivo/activo ligero respetando scope.
- `core_discovery.py`: análisis y enriquecimiento de resultados de recon.
- `core_xploit.py`: pruebas de explotación seguras basadas en discovery.
- `plugin_stripchat_business_logic.py`: plugin de lógica de negocio específico.
- `program_*.json`: plantillas de configuración por programa.

## Requisitos previos

- Python 3.10 o superior.
- Acceso a Internet para instalar dependencias y realizar recon.
- Credenciales/cookies válidas si se ejecutará el plugin Stripchat u otros que requieran autenticación.

## Instalación

1. Clona el repositorio y accede a la carpeta del proyecto.
2. Ejecuta el instalador para crear un entorno virtual y resolver dependencias:

   ```bash
   ./install.sh
   ```

   El script crea `.venv` (puedes personalizar con `VENV_DIR=<ruta>`). Para usar un intérprete distinto, define `PYTHON_BIN=<comando>` antes de ejecutar.

3. Activa el entorno virtual antes de utilizar la suite:

   ```bash
   source .venv/bin/activate
   ```

Las dependencias se definen en `requirements.txt` e incluyen `aiohttp`, `websockets` y `requests`.

## Preparación de configuraciones BBP

Cada programa se describe en un JSON (`program_<id>.json`). Puedes usar `program_X.json` como plantilla.

1. Copia la plantilla con un nombre único:

   ```bash
   cp program_X.json program_miprog.json
   ```

2. Actualiza los campos clave:
   - `program_name` y `id`: identificador único (coincide con prefijos de archivos generados).
   - `scopes.in_scope/out_of_scope`: regex o dominios exactos que delimiten el alcance.
   - `headers`: cabeceras necesarias; el argumento `--handle` de los scripts añadirá automáticamente la cabecera `HackerOne` si falta.
   - `rate_limit`: ajusta `max_rps`, `default_concurrency` y `default_delay` según la política del BBP.
   - `base_targets`: URLs de inicio para recon.
   - `auth_profiles`: define perfiles/cookies necesarias para módulos que las utilicen.
   - Bloques `recon`, `discovery`, `exploit` y `plugin`: adapta heurísticas, wordlists, y activa/desactiva pruebas según lo permitido por el programa.

3. Si el programa requiere cookies o sesiones:
   - Guarda los archivos JSON en `sessions/` (o la ruta que definas).
   - Asegúrate de pasarlos vía argumentos cuando ejecutes el pipeline o plugins.

4. Prepara un archivo de objetivos (`targets.txt`) con dominios o URLs de punto de partida (uno por línea).

## Ejecución de scripts individuales

Todos los comandos deben ejecutarse con el entorno virtual activo.

### 1. Reconocimiento (`core_recon.py`)

Genera `recon_<program_id>.json` y artefactos en `data/<program_id>/`.

```bash
python core_recon.py \
  --program-config program_miprog.json \
  --handle TU_HANDLE \
  --targets targets.txt
```

Parámetros opcionales relevantes:
- `--handle`: handle de HackerOne usado en cabeceras (puede omitirse si no aplica).
- `--targets`: lista de dominios/URLs en texto plano.

### 2. Discovery (`core_discovery.py`)

Consume la salida del recon y produce `discovery_<program_id>.json`.

```bash
python core_discovery.py \
  --program-config program_miprog.json \
  --recon-file recon_miprog.json
```

### 3. Explotación segura (`core_xploit.py`)

Ejecuta pruebas seguras basadas en discovery y genera `exploit_<program_id>.json`.

```bash
python core_xploit.py \
  --program-config program_miprog.json \
  --discovery-file discovery_miprog.json
```

Respetará límites de tasa definidos en el JSON y únicamente realizará pruebas self-IDOR, XSS reflejado controlado, etc.

### 4. Plugin específico (`plugin_stripchat_business_logic.py`)

Analiza reglas de negocio con sesiones de Viewer/Model y produce `plugin_stripchat_business_<program_id>.json`.

```bash
python plugin_stripchat_business_logic.py \
  --program-config program_stripchat.json \
  --discovery-file discovery_stripchat.json \
  --exploit-file exploit_stripchat.json \
  --viewer-session sessions/stripchat_viewer.json \
  --model-session sessions/stripchat_model.json
```

Adapta las rutas de sesiones según tu configuración.

## Pipeline completo con `core_runner.py`

Para automatizar el flujo de recon → discovery → exploit → plugin:

```bash
python core_runner.py \
  --program-config program_stripchat.json \
  --handle TU_HANDLE \
  --targets targets.txt \
  --viewer-session sessions/stripchat_viewer.json \
  --model-session sessions/stripchat_model.json \
  --run-plugin
```

- Omitir `--run-plugin` si no deseas ejecutar el módulo de negocio.
- El runner generará un resumen en `pipeline_summary_<program_id>.json`.

## Buenas prácticas

- Respeta siempre las políticas del BBP antes de lanzar cualquier prueba.
- Ajusta límites de velocidad y listas de palabras para minimizar ruido.
- Revisa los archivos JSON generados entre etapas para validar resultados.
- Mantén tus sesiones/cookies protegidas y actualízalas periódicamente.

## Desinstalación / limpieza

Para eliminar el entorno virtual creado por el instalador:

```bash
rm -rf .venv
```

Los archivos generados por los módulos (`recon_*.json`, `discovery_*.json`, etc.) pueden borrarse manualmente cuando ya no sean necesarios.
