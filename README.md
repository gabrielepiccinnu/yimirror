# yimirror — mirror delle registrazioni cloud Yi sul tuo cloud personale

Container Docker che scarica le registrazioni già salvate nel cloud Yi (clip degli
eventi di movimento) e le replica su **Backblaze B2** (o qualsiasi backend rclone).
Uso personale: solo il tuo account e le tue camere.

> Stato: **v0 strutturale**. La firma HMAC-SHA1 è mappata (`ra/c1`), ma mancano i
> valori reali del segreto, la forma esatta di `/vas/v8/cloud/videos` e il template
> URL dei segmenti .ts — si completano con la verifica dinamica (fase 6 del progetto).
> Riferimento tecnico: `docs/api/cloud-recording.md` e `docs/codebase/yimirror.md`.

## Setup

1. **Bucket B2**: crea un bucket (es. `yi-home-archivio`) e una application key con
   accesso solo a quel bucket.
2. **Config**: `cp .env.example .env` e compila:
   - `YI_USER` / `YI_PASS` — credenziali del tuo account Yi;
   - `YI_REGION` — `us`, `eu`, `cn` o `tw` (base `api.{regione}.xiaoyi.com`);
   - `YI_CLIENT_SECRET` — per ora il fallback in codice; aggiornare con i valori
     recuperati dinamicamente;
   - `RCLONE_CONFIG_B2_*` + `B2_BUCKET` — chiavi B2 (config rclone via env, nessun
     file di config in chiaro).
3. **Build e avvio**:
   ```bash
   cd tools/yimirror
   docker compose up -d --build
   docker compose logs -f yimirror
   ```
4. **Primo ciclo**: il log dice esplicitamente per ogni camera se la registrazione
   cloud è **attiva** (`/vas/v8/all/cloud/status`) — risponde alla domanda
   "ho un abbonamento Yi Cloud?".

## Modalità

- Loop continuo (default): un ciclo ogni `YIMIRROR_INTERVAL` secondi (1200 = 20 min).
- Ciclo singolo (cron esterno):
  ```bash
  docker compose run --rm yimirror python -m src.main --once
  ```

## Verifica

- `data/state.db` (SQLite): tabella `clips` con stato per clip (`downloaded`,
  `uploaded`, `failed`) — il dedup è per `(uid, giorno, clip_id)`.
- B2: file in `yi-home/{uid}/{YYYY-MM-DD}/{clip_id}.mp4`.
- Riepilogo a fine ciclo nel log: `cycle done: {...}`.

## Limiti attuali (v0)

- Login: l'app cifra la password (`ra/d2`) prima di inviarla; il porting della cifra
  è pendente. Se il server rifiuta la password in chiaro, imposta `YI_SESSION_TOKEN`
  con un token catturato da una sessione dell'app loggata.
- Segmenti .ts: il template URL CDN reale va impostato in `YIMIRROR_TS_URL_TEMPLATE`
  (placeholders `{uid}` `{t}` `{d}`) dopo la cattura dinamica.
- Connessioni con concorrenza limitata (`YIMIRROR_SEGMENT_WORKERS`, default 4) e
  intervallo conservativo: non stressare i server Yi.

## Sicurezza

- `.env` **mai** committato (gitignored). `data/` contiene i clip scaricati prima
  dell'upload: se imposti `YIMIRROR_KEEP_LOCAL=0` vengono rimossi dopo l'upload.
- Ricerca locale, nessuna distribuzione: solo il tuo account e le tue camere.

## Recorder (tap dello stream live TNP)

`python -m src.tap` registra lo stream live **senza** reimplementare l'auth: intercetta
il flusso UDP TNP (sulla rete del device o su una bridge dove passa il traffico) e
ricostruisce i frame H.264 (`tnp_proto.FrameReassembler`). Verificato offline sul pcap
della sessione: 9.229 NAL estratti (P-frame in chiaro; le teste degli I-frame sono
AES-cifrate, findings §7c).

```bash
# verifica/conversione di una cattura esistente
python -m src.tap --pcap captures/yi-tnp-session-20261110.pcap \
    --out /tmp/out.h264 --mp4 /tmp/out.mp4 --password <password-p2p>
# live (su host che vede il traffico UDP, root)
python -m src.tap --udp 44162 --out live.h264 --mp4 live.mp4 --password <password-p2p>
```

L'MP4 è riproducibile quando la chiave media è nota (open item §7b: password runtime).

## Architettura finale (diretta → tuo storage sicuro)

```
Mac/device con l'app in live view (punto di cattura)
   │  sudo python3 -m src.live --seconds 60
   │  (sniffer UDP dello stream TNP della camera)
   ▼  POST HTTPS con basic auth + X-Ingest-Token
Dokploy (tuo server) — ingest dietro Traefik
   │  https://ingest.tuo-dominio.tld  (TLS Let's Encrypt, basic auth, rate limit)
   ▼
volume persistente: /data/live/{YYYY-MM-DD}/live-*.h264  — retention 7 giorni
```

**Avvio sul punto di cattura (Mac)** — serve sudo per lo sniffer:

```bash
cd tools/yimirror
YIMIRROR_UPLOAD=http \
YIMIRROR_INGEST_URL=https://ingest.tuo-dominio.tld \
YIMIRROR_INGEST_USER=bridge \
YIMIRROR_INGEST_PASS='...' \
YIMIRROR_INGEST_TOKEN='...' \
  sudo -E python3 src/live.py --seconds 60
```

**Deploy su Dokploy** (vedi `deploy/docker-compose.dokploy.yml`):
1. Dominio → IP del server (record DNS), Dokploy con Traefik + Let's Encrypt attivo.
2. `bash deploy/htpasswd.sh bridge 'password'` → imposta `YIMIRROR_BASICAUTH_USERS` nel .env.
3. Imposta nel .env di Dokploy: `YIMIRROR_DOMAIN`, `YIMIRROR_INGEST_TOKEN` (casuale lungo).
4. Deploy del compose: l'ingest NON ha porta pubblica — solo la rotta Traefik con
   basic auth + rate limit (30 req/min). Il token è il secondo fattore.
