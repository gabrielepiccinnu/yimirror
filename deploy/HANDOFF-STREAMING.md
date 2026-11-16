# HANDOFF — Proxy streaming nativo YI Home (stato 14/11/2026 sera)

## Obiettivo
Sorgente ORIGINALE della camera (frame TNP, 640×360) su Frigate (fg.areaditest.click),
SENZA app né emulatore. L'emulatore è SPENTO e deve restarlo (stabilizza la
viewPassword e libera la sessione della camera).

## Cosa FUNZIONA (verificato)
- **Protocollo TNP completo mappato** — findings.md §7v (handshake+firma 0x41 HMAC),
  §7w (controlli IOCTRL autenticati, viewPassword, decrypt I-frame AES-ECB),
  §7w-bis (wake: sequenze/timing), §7w-ter (deploy VPS), §7w-quater (wake 0x1a via Ghidra).
- **Client nativo riceve+decifra+decodifica i frame** — verificato il 14/11 pomeriggio
  (527 pacchetti, 288 frame, ffmpeg estrae le immagini dal dump).
- **Wake 0x1a (MSG_DEV_WAKEUP_REQ) implementato e ACK-ATO**: i log del container VPS
  mostrano `wake ack 0x1a ricevuto (result=0)` e `sessione attiva: ('82.192.139.67', …)`.
- Proxy deployato sul VPS (Dokploy) con CI GitHub Actions → GHCR.

## Cosa MANCA (l'ultimo anello)
La camera non avvia lo stream per il proxy. Frigate = "trasmissione disconnessa"
(DESCRIBE su mediamtx = 404 = nessun publisher). Il wake passa, la sessione passa —
resta da vedere SE la camera processa i controlli IOCTRL.

## PASSO 1 — il diagnostico decisivo (5 minuti)
UI Dokploy → Contabo #4 → yimirror → **yimirror-native** → **Logs** (container).
Cercare le righe `[ctrl]`:
- `[ctrl] risposta a 0x1300: type=0x1301` (risposta REALE, reqId+1) → la camera
  processa → il blocco è l'avvio stream: riprovare SET_RESOLUTION (0x1311) su
  sessioni fresche; in ultima istanza **reboot fisico della camera** (la giornata
  di test l'ha martellata; il RESTART via IOCTRL passa dallo stesso canale ignorato).
- `type=0xffff` → controllo in coda: la camera è lenta o la **viewPassword è ruotata**
  (vedi sotto) — verificare la password e riprovare con calma.
- `nessuna risposta` → il relay non inoltra: verificare la firma 0x41/sequenza (§7v)
  o il rate-limit (decine di sessioni di test oggi — si azzera col tempo).

## PASSO 2 — verifiche rapide da qualunque macchina
```bash
# publisher attivo? (200 = lo stream è su)
python3 - << 'PY'
import socket, base64
auth = base64.b64encode(b"bridge:RTSP_PASS").decode()
s = socket.create_connection(("164.68.119.188", 8554), timeout=6)
req = (f"DESCRIBE rtsp://164.68.119.188:8554/ingresso RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\nAuthorization: Basic {auth}\r\n\r\n")
s.sendall(req.encode()); print(s.recv(4096).decode(errors="replace").splitlines()[0])
PY
```

## Infrastruttura (TUTTI i dettagli operativi)
- **Dokploy CLI locale**: `~/.local/bin/dokploy` (token in Portachiavi; `GET/POST "route?param"`).
  Route utili: `project.all`, `compose.one?composeId=`, `compose.update` (POST, JSON),
  `compose.deploy`, `docker.getContainers?serverId=Mt316FxqE-i-NHynJCuJS`
  (SENZA serverId elenca un ALTRO server! I timestamp dell'API sono UTC).
- **Servizio proxy**: `yimirror-native`, composeId `PRkP_WgtbveKcKvFMNtLw`,
  sourceType **raw** + compose inline con immagine GHCR taggata per SHA
  (mai :latest — resta in cache docker e i deploy non pullano).
- **Rete**: `compose-transmit-haptic-port-fqgvn7_default` (default del progetto
  `yimirror-video`), host mediamtx = `mediamtx:8554`, path `/ingresso`.
- **CI**: `.github/workflows/build-native.yml` → GHCR `latest` + `${{ github.sha }}`.
  ⚠️ I deploy falliscono con "manifest unknown" se partono PRIMA che la CI finisca:
  fare `gh run watch <id> --exit-status` e POI deployare. Un deploy che cambia solo
  il tag fallisce istantaneo: cambiare anche l'env (marker `YIMIRROR_RELOAD=n`).
- **Credenziali camera** (SYUPE/Ingresso): nell'env del servizio Dokploy
  (YIMIRROR_P2PID/LICENSE/INIT_STRING/P2P_PASSWORD) e in `tools/yimirror/.env` locale
  (gitignored — MAI nel repo, è PUBBLICO).
  ⚠️ **viewPassword RUOTA a ogni refresh device list dell'app**: con l'app spenta è
  stabile. Se servisse: emulatore → `adb pull …/databases/ants_yi_home.db` →
  `SELECT viewPassword FROM device_info` (oppure via cloud API, yi_client.py).
- **File chiave**: `src/tnp_client.py` (protocollo/sessione/wake — `build_wakeup_packet`,
  `wake_device`, `build_ioctrl`, `ioctrl_auth`, `start_video`, `run_video`),
  `src/rtsp_push.py --source native` (entrypoint del proxy), `src/native_test.py`
  (test locale), `src/replay_wake.py` (replay del tap), `Dockerfile.native`.
- **Lezioni del giorno** (dettagli in findings §7w-ter): il compose con rete sbagliata
  non vede mediamtx; `compose.create` NON salva l'env (serve update); i deploy git
  usano `customGitUrl` (non `repository`); la camera risponde ai controlli solo su
  sessioni fresche (refresh 0x41→0x42 prima di ogni controllo); il relay risponde
  `ffff` = "in coda" (non è un rifiuto).

## Se serve rifare la mappatura (per il futuro)
Ghidra/REA su `rebuild/fix/config.arm64_v8a/lib/arm64-v8a/libPPPP_API.so`:
funzioni chiave già mappate (§7w-quater): `PPPP_DoWakeup` (0x120268),
`PPPP_TryWakeUp` (0x11d2e8), `PPPP_Proto_Send_WakeUp` (0x129638),
`Write_HeaderV2` (0x12412c), `Recv_ALL` (0x123eac), SendMessage (0x12b8b8),
SendMessageByTCP (0x12b418).

---

# Handoff sessione 11 (2026-11-16) — FLUIDITÀ risolta, nodo SUSTAIN isolato, cloud plan

## Stato in una riga
La camera streamma benissimo (provato: **l'app mostra live fluido e continuo**). Il **proxy dal
VPS** si aggancia (riceve 0x42), prende un **burst iniziale ~4s** e poi **non sostiene il media** →
Frigate 404 "disconnessa". Non è fluidità, non è camera/relay: è il **canale media dopo il 0x42**.
**Proxy fermato** (Dokploy compose.stop) per non martellare il relay.

## ✅ Risolto: FLUIDITÀ (commit yimirror `dfbc243`, immagine deployata `dfbc243`, reload=10)
- `rtsp_push.push_native_loop` ora **MISURA l'fps reale** sui primi ~4s (dal primo keyframe):
  bufferizza i frame, calcola fps wall-clock, avvia ffmpeg con quel `-r`, poi riversa il buffer.
  Logga anche l'fps da `ts_ms` (clock camera). Fallback 15; `YIMIRROR_FPS` forza/salta la misura.
  Env: `YIMIRROR_MEASURE_SECONDS=4`, `YIMIRROR_MEASURE_MIN_FRAMES=20`.
- **Dato validato dal vivo**: la camera gira a **~20fps** (`fps camera (ts_ms): 19.97/20.21/20.47`),
  NON 15. Col `-r 15` fisso il video sembrava accelerato/a scatti → era quello.
- Nota: warning ffmpeg "Timestamps are unset in a packet" è innocuo (deprecation sul muxer RTSP),
  lo stream apre comunque.

## 🔴 Nodo aperto: SUSTAIN del media (post-0x42) — NON è fluidità
**Test decisivo (stanotte):**
- App aperta su live Ingresso → **fluido e continuo >60s** ⇒ camera+relay OK, niente mute globale.
- Anche con app aperta, il proxy fa **burst-then-stop** ⇒ non è "serve l'app a tenere aperta".
- Senza app, idem: ogni connect = 0x42 → ~82 frame @20fps (~4s) → stop; **tutti i controlli
  `resp=None`** (0x2345, 0x03c0); Frigate `method DESCRIBE failed: 404` (nessun publisher).

**Interpretazione**: il burst è il buffer iniziale che il relay inoltra; poi la camera **non
committa/sostiene** il canale media verso il VPS come fa verso l'app. Coincide col "delta dopo
0x42" di §7x-octies. Ipotesi da verificare col diff: destinatari di ack/keepalive (relay
82.192.139.67 **vs IP LAN camera 192.168.1.9**, dual-target come nei pcap), token/porta presi
dalla 0x42, binding/porta sorgente, cadenze. Possibile concausa 2°-viewer (app = sessione
primaria) ma NON è la causa core (burst-then-stop c'è anche senza app).

## ▶️ PROSSIMO PASSO deciso: DIFF OFFLINE (niente più prove dal vivo finché non indica il delta)
Confrontare la sequenza del proxy in `src/tnp_client.py` (`connect()` + `run_video`) contro le
catture dell'app **già disponibili**:
- `captures/app-boot-20261115.pcap` (boot con dual-target 0x41: relay :44844 + camera LAN :16376)
- `captures/app-liveview-20261115.pcap`
Focus: **tutto ciò che l'app fa DOPO il 0x42** per tenere vivo il media (verso chi manda ack/e0,
se echeggia un token/porta della 0x42, ogni quanto). Il nostro `run_video` manda ack a
`self.server` (relay) soltanto — l'app potrebbe mandare anche verso l'endpoint LAN/porta dalla 0x40.

## 🟡 Alternativa valutata: CLOUD PLAN di YI (per REGISTRAZIONE, non live)
- Il cloud plan **non usa il P2P live**: è la **camera** che fa upload diretto ai server YI (storage
  tipo S3). Scavalca il nodo post-0x42 → registrazione affidabile. Ma: clip a evento (continuo solo
  sui piani cari), latenza, abbonamento, e **NON migliora il live P2P**.
- Abbiamo già sessione cloud autenticata (`adopt_token`/`/v5`): si potrebbero **scaricare i clip via
  API** e darli a Frigate come *recordings* (fallback affidabile, non live). Da decidere con l'utente
  se attivarlo in parallelo al lavoro sul live.

## Operatività (stato lasciato stanotte)
- **Proxy FERMO**: `yimirror-native` stoppato via Dokploy `compose.stop` (composeId
  `PRkP_WgtbveKcKvFMNtLw`). Per riaccendere: `compose.deploy` (o start) stesso composeId.
- Immagine corrente nel compose: `yimirror-native:dfbc243fd209...`, `YIMIRROR_RELOAD=10`.
- API Dokploy: base `https://app.hardsoundsensation.com`, header `x-api-key:` (token nel Portachiavi
  `dokploy-api`), serverId `Mt316FxqE-i-NHynJCuJS`. Log solo via WebSocket (vedi `scratchpad/dlogs.py`).
- Repo yimirror PUBBLICO: nessuna credenziale nei commit (verificato prima del push).
