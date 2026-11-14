# Handoff — Deploy Dokploy di yimirror (storage della diretta)

Data: 2026-11-12. Scopo: deploy dell'ingest su Dokploy e avvio del bridge sul Mac.
Tutti i pezzi sono **già pronti e verificati** — restano solo i passi operativi sotto.

## Stato (cosa è già fatto e verificato)

- Bridge live: cattura della **sorgente video** TNP via tcpdump sul device (root) →
  segmenti .h264 — verificato dal vivo (60 s → 554 frame / 430 KB, findings §7g).
- Upload: `http` (POST multipart con basic auth + X-Ingest-Token) e `rclone` (B2/Drive)
  — verificato end-to-end offline (§7e).
- Ingest server (`src/ingest.py`): salvataggio per giorno + retention 7 g + token —
  verificato (§7e).
- Pacchetto deploy: `docker-compose.dokploy.yml` (Traefik: nessuna porta pubblica,
  TLS Let's Encrypt, basic auth bcrypt, rate limit 30/min, healthcheck),
  immagine `yimirror:latest` esportata in `yimirror-image.tar` (245 MB).
- Segreti generati in **`deploy/.env.dokploy`** (locale, gitignored): password bridge
  casuale, token 64 hex, hash bcrypt. NON committare, NON incollare in chat pubbliche.

## Passi operativi

### A. Server (Dokploy host)

```bash
# dal Mac: copia immagine + compose + env sul server
scp tools/yimirror/deploy/yimirror-image.tar tools/yimirror/deploy/docker-compose.dokploy.yml utente@SERVER:/tmp/
# sul server
docker load -i /tmp/yimirror-image.tar        # atteso: Loaded image: yimirror:latest
```

### B. DNS

Record **A** per `ingest.<tuo-dominio>` → IP pubblico del server.

### C. Dokploy UI

1. **Create Service → Compose** (raw): incolla `docker-compose.dokploy.yml`.
2. **Environment** (da `deploy/.env.dokploy`, con il dominio reale):
   - `YIMIRROR_DOMAIN=ingest.<tuo-dominio>`
   - `YIMIRROR_INGEST_TOKEN=<dal file>`
   - `YIMIRROR_BASICAUTH_USERS=bridge:$2y$05$...` (singolo `$`, già giusto nel file)
   - `TZ=Europe/Rome`
3. **Deploy** → attendere Healthy.
   - Se TLS non parte: verificare che su Dokploy l'entrypoint si chiami `websecure` e
     il certResolver `letsencrypt` (nomi default Dokploy; altrimenti adattare le label
     del compose).
4. **Verifica browser**: `https://ingest.<dominio>/` → richiesta basic auth →
   dopo il login: `yimirror ingest ok — retention 7d`.

### D. Verifica scrittura dal Mac

```bash
curl -u bridge:'<PASS dal .env.dokploy>' \
  -H "X-Ingest-Token: <TOKEN dal .env.dokploy>" \
  -F "file=@/tmp/test.h264" https://ingest.<dominio>/segments
# atteso: "ok"  →  file sul volume: /data/live/YYYY-MM-DD/test.h264
# senza auth atteso: 401
```

### E. Avvio bridge continuo sul Mac

```bash
cd "/Users/gabrielepiccinnu/Sviluppo/App YI Home/yi-home-7.0.1/tools/yimirror"
YIMIRROR_UPLOAD=http \
YIMIRROR_INGEST_URL=https://ingest.<dominio> \
YIMIRROR_INGEST_USER=bridge \
YIMIRROR_INGEST_PASS='<PASS>' \
YIMIRROR_INGEST_TOKEN='<TOKEN>' \
  python3 src/live.py --seconds 60
```

Prerequisito: emulatore acceso con app in live view (se la sessione cade, riaprire la
pagina camera — il bridge riprende da solo quando il traffico torna).

## Stato complessivo del progetto (per contesto)

- Clone app: ads/telemetria/AI-alert off, crash-free, APK universale condivisibile.
- Streaming: protocollo TNP/PPPP mappato; stream video IN CHIARO (frame layout
  verificato); I-frame con NAL type custom variabile (0x3D/0x99) → riproduzione
  standard pendente (RE di `libvideodraw.so` AntsDecoder).
- Mirror clip cloud: pronto, manca la chiave HMAC richieste.
- Client TNP nativo attivo: manca token f141 + handshake completo.

## Troubleshooting rapido

- **401 su curl**: utente/password sbagliati o `$` rovinato nell'hash → rigenera con
  `bash deploy/htpasswd.sh bridge 'password'` (l'output va con `$` singolo nel .env).
- **404 sul dominio**: router Traefik non attivo → controlla label + entrypoint.
- **TLS error**: certResolver/dns — attendi 1-2 min (Let's Encrypt), poi log Traefik.
- **Segmenti non arrivano**: log del bridge (`YIMIRROR_LOG=DEBUG`), check emulatore in
  live view (`adb shell dumpsys activity activities | grep topResumedActivity`).
- **Rotazione segreti**: nuova password via htpasswd.sh + nuovo token casuale; aggiorna
  entrambi i lati (.env Dokploy + env del bridge).

File collegati: `DOKPLOY-GUIDE.md` (guida lunga), `../README.md` (manuale), findings
§7e–§7g, `docs/codebase/yimirror.md`.
