#!/bin/bash
# Genera la stringa users per il middleware basic-auth di Traefik.
# Uso: bash deploy/htpasswd.sh <utente> <password>
# Esempio: bash deploy/htpasswd.sh bridge 'password-lunga-casuale'
set -euo pipefail
if [ $# -ne 2 ]; then
  echo "uso: bash deploy/htpasswd.sh <utente> <password>" >&2
  exit 1
fi
USER="$1"
PASS="$2"
# bcrypt tramite il container httpd (htpasswd -B), niente dipendenze locali
docker run --rm httpd:2.4-alpine htpasswd -nbB "$USER" "$PASS" | sed 's/\$/\$\$/g'
echo
echo '^ copia la riga in YIMIRROR_BASICAUTH_USERS (nel .env di Dokploy)'
