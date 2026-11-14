# Guida deploy Dokploy — yimirror ingest (storage della diretta)

Prerequisiti: server con Dokploy installato, dominio con record DNS **A** → IP del
server, Traefik attivo su Dokploy con entrypoint `websecure` e certResolver
`letsencrypt` (default Dokploy).

## 1. Carica l'immagine sul server

```bash
# dal Mac
scp deploy/yimirror-image.tar utente@SERVER:/tmp/
# sul server
docker load -i /tmp/yimirror-image.tar      # -> immagine `yimirror:latest`
```

## 2. Crea il servizio su Dokploy

Dokploy → **Create Service → Compose** (raw compose) e incolla il contenuto di
`deploy/docker-compose.dokploy.yml`.

## 3. Variabili d'ambiente (scheda Environment di Dokploy)

Valori già generati in `deploy/.env.dokploy` (locale, mai committato) — incollali:
- `YIMIRROR_DOMAIN` → il tuo dominio reale (es. `ingest.esempio.com`)
- `YIMIRROR_INGEST_TOKEN` → dal file
- `YIMIRROR_BASICAUTH_USERS` → dal file (utente `bridge` + hash bcrypt)

## 4. Deploy e verifica

1. **Deploy** → attendi che il container sia Healthy.
2. Da un browser: `https://ingest.esempio.com/` → deve chiedere utente/password
   (basic auth) → dopo il login: `yimirror ingest ok — retention 7d`.
3. Test di scrittura dal Mac:
   ```bash
   curl -u bridge:PASSWORD -H "X-Ingest-Token: TOKEN" \
     -F "file=@/tmp/test.h264" https://ingest.esempio.com/segments
   # atteso: "ok"
   ```

## 5. Avvia il bridge sul Mac (cattura + invio)

```bash
cd tools/yimirror
YIMIRROR_UPLOAD=http \
YIMIRROR_INGEST_URL=https://ingest.esempio.com \
YIMIRROR_INGEST_USER=bridge \
YIMIRROR_INGEST_PASS='PASSWORD' \
YIMIRROR_INGEST_TOKEN='TOKEN' \
  python3 src/live.py --seconds 60
```

I segmenti arrivano in `/data/live/{YYYY-MM-DD}/live-*.h264` sul volume di Dokploy;
retention 7 giorni automatica (l'ingest elimina le directory più vecchie di 7 giorni
a ogni upload).

## Sicurezza del setup

- Nessuna porta pubblica: solo la rotta Traefik `Host(dominio)` con TLS.
- Basic auth bcrypt (Traefik) + `X-Ingest-Token` (secondo fattore, verificato
  dall'app) + rate limit 30 req/min per IP.
- Se il server è solo tuo, puoi anche aggiungere in Dokploy un IP allowlist sul
  middleware (`traefik.http.middlewares.yimirror-ip.ipallowlist.sourcerange`).
- Rotazione: per cambiare password → `bash deploy/htpasswd.sh bridge 'nuova'` e
  aggiorna la variabile; per il token → nuovo valore casuale in entrambi i lati.
