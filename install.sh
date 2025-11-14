#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[ERROR] No se encontró $PYTHON_BIN en el PATH." >&2
  echo "Instala Python 3.10+ antes de continuar." >&2
  exit 1
fi

PYTHON_VERSION=$($PYTHON_BIN -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_MAJOR=3
REQUIRED_MINOR=10

MAJOR=${PYTHON_VERSION%%.*}
MINOR=${PYTHON_VERSION#*.}

if (( MAJOR < REQUIRED_MAJOR )) || { (( MAJOR == REQUIRED_MAJOR )) && (( MINOR < REQUIRED_MINOR )); }; then
  echo "[ERROR] Se requiere Python >= ${REQUIRED_MAJOR}.${REQUIRED_MINOR}." >&2
  echo "Versión detectada: $PYTHON_VERSION" >&2
  exit 1
fi

echo "[+] Creando entorno virtual en $VENV_DIR"
$PYTHON_BIN -m venv "$VENV_DIR"

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

pip install --upgrade pip
pip install -r requirements.txt

echo "[+] Instalación completa."
echo "[+] Activa el entorno ejecutando: source $VENV_DIR/bin/activate"
