#!/bin/bash
# Avvia il bridge della diretta verso l'ingest deployato su Dokploy.
# Legge le credenziali da deploy/.env.dokploy (locale, gitignored).
set -euo pipefail
cd "$(dirname "$0")"
ENVF=deploy/.env.dokploy
[ -f "$ENVF" ] || { echo "ERR: manca $ENVF" >&2; exit 1; }

get() { grep "^$1=" "$ENVF" | cut -d= -f2-; }

export YIMIRROR_UPLOAD=http
export YIMIRROR_INGEST_URL="${YIMIRROR_INGEST_URL:-https://testgest.areaditest.click}"
export YIMIRROR_INGEST_USER="$(get YIMIRROR_INGEST_USER)"
export YIMIRROR_INGEST_PASS="$(get YIMIRROR_INGEST_PASS)"
export YIMIRROR_INGEST_TOKEN="$(get YIMIRROR_INGEST_TOKEN)"

echo "bridge -> ${YIMIRROR_INGEST_URL} (segmenti da ${2:-60}s, upload http)"
exec python3 -m src.live --seconds "${2:-60}" ${1:+--once}
