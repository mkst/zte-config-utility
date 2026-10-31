#!/usr/bin/env bash
set -e

# Directorio del script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Buscar el intérprete de Python en el entorno virtual o en el sistema
if [ -x "$SCRIPT_DIR/../bin/python3" ]; then
    PYTHON_BIN="$SCRIPT_DIR/../bin/python3"
elif [ -n "$VIRTUAL_ENV" ] && [ -x "$VIRTUAL_ENV/bin/python3" ]; then
    PYTHON_BIN="$VIRTUAL_ENV/bin/python3"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
else
    echo "Error: No se encontró un intérprete de python3 disponible." >&2
    exit 1
fi

if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Uso: $0 [archivo_entrada.bin] [archivo_salida.xml]"
    echo ""
    echo "Ejemplos:"
    echo "  $0                           # Decripta 'config.bin' a 'config.xml'"
    echo "  $0 mi_backup.bin             # Decripta 'mi_backup.bin' a 'mi_backup.xml'"
    echo "  $0 mi_backup.bin salida.xml  # Decripta 'mi_backup.bin' a 'salida.xml'"
    exit 0
fi

INPUT="${1:-config.bin}"
OUTPUT="${2:-}"

if [ -n "$OUTPUT" ]; then
    "$PYTHON_BIN" "$SCRIPT_DIR/f6600_tool.py" decrypt "$INPUT" "$OUTPUT"
else
    "$PYTHON_BIN" "$SCRIPT_DIR/f6600_tool.py" decrypt "$INPUT"
fi
