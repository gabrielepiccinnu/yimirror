"""rtsp_push.py — PUSH dello stream verso il proxy RTSP sul VPS (Frigate legge).

Due sorgenti:
- `--source screen` (default, banco di test): screenrecord dell'emulatore con
  l'app in live view → H.264 → RTSP. Richiede adb + emulatore.
- `--source native` (produzione, §7v/§7w): sessione TNP nativa del proxy —
  frame 0xd0 dal relay → unwrap I-frame 0x3D → annex-b → ffmpeg → RTSP.
  Richiede YIMIRROR_P2PID, YIMIRROR_LICENSE, YIMIRROR_INIT_STRING.

Uso:
  RTSP_URL=rtsp://bridge:PASS@164.68.119.188:8554/ingresso \
    python3 src/rtsp_push.py --source native
Richiede: ffmpeg nel PATH.
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import time

log = logging.getLogger("yimirror.rtsp_push")

ADB = os.environ.get("YIMIRROR_ADB", "adb")
RTSP_URL = os.environ.get("RTSP_URL", "")


def live_view_active() -> bool:
    out = subprocess.run([ADB, "shell", "dumpsys", "activity", "activities"],
                         capture_output=True, text=True, timeout=20).stdout
    return "PlayerActivity" in out


def _fresh_view_password(p2pid: str) -> str:
    """viewPassword SEMPRE fresca dal cloud (§7x-terdecies). La viewPassword
    ruota a ogni refresh della device list dell'app: rileggendola dal cloud a
    ogni riconnessione il proxy resta autonomo e immune alla rotazione.

    Fonte primaria: sessione adottata via `YI_TOKEN`/`YI_TOKEN_SECRET`/`YI_USERID`
    (la firma /v5 usa `token&token_secret`, HmacSHA1). Il login diretto
    `/v4/users/login` dà -10003 (social/anti-bot), quindi si usa il token della
    sessione già autenticata. Fallback: login (se un giorno sbloccato) → statica
    `YIMIRROR_P2P_PASSWORD`."""
    suffix = p2pid.split("-")[-1]
    region = os.environ.get("YI_REGION", "eu")
    token = os.environ.get("YI_TOKEN", "")
    secret = os.environ.get("YI_TOKEN_SECRET", "")
    userid = os.environ.get("YI_USERID", "")
    if token and secret:
        try:
            from yi_client import YiClient
            yc = YiClient(region=region)
            yc.adopt_token(token, userid=userid or None, token_secret=secret)
            vp = yc.view_password_for(suffix)
            if vp:
                log.info("viewPassword dal cloud (token) per '%s' (len %d)", suffix, len(vp))
                return vp
            log.warning("viewPassword non trovata nel cloud (token) per '%s'", suffix)
        except Exception as exc:
            log.warning("recupero viewPassword via token fallito: %s", exc)
    acc = os.environ.get("YI_ACCOUNT", "")
    pw = os.environ.get("YI_PASSWORD", "")
    if acc and pw:
        try:
            from yi_client import YiClient
            yc = YiClient(region=region)
            yc.login(acc, pw)
            vp = yc.view_password_for(suffix)
            if vp:
                log.info("viewPassword dal cloud (login) per '%s' (len %d)", suffix, len(vp))
                return vp
        except Exception as exc:
            log.warning("login cloud fallito: %s", exc)
    return os.environ.get("YIMIRROR_P2P_PASSWORD", "")


def push_native_loop(restart_every: float = 3600.0) -> None:
    """Macchina a stati: sessione TNP nativa → unwrap → pipe ffmpeg → RTSP
    (produzione, §7w/§7y). Lo stato DESIDERATO (ON/OFF) arriva da Frigate via
    MQTT o dall'API HTTP; OFF = privacy mode reale (CLOSE_CAMERA 0x1304)."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from tnp_client import TnpSession
    from tnp_proto import FrameReassembler, unwrap_frame
    from control import ProxyState, start_mqtt, start_api

    p2pid = os.environ.get("YIMIRROR_P2PID", "")
    license_key = os.environ.get("YIMIRROR_LICENSE", "")
    init_string = os.environ.get("YIMIRROR_INIT_STRING", "")
    if not (p2pid and license_key and init_string):
        log.error("source native: servono YIMIRROR_P2PID, YIMIRROR_LICENSE, "
                  "YIMIRROR_INIT_STRING")
        raise SystemExit(1)

    state = ProxyState()
    start_mqtt(state)
    start_api(state)

    session: TnpSession | None = None
    heartbeat = 15.0                    # ripubblica lo stato retained ogni 15 s

    def drop_session(power_off: bool) -> None:
        nonlocal session
        if session is None:
            return
        if power_off:
            try:
                session.set_camera_power(False)   # privacy mode reale
            except Exception as exc:              # pragma: no cover
                log.warning("spegnimento camera fallito: %s", exc)
        session.close()
        session = None

    while True:
        # --- stato desiderato OFF → privacy mode, nessuna sessione ---------
        if not state.desired_on:
            if session is not None:
                log.info("OFF richiesto → privacy mode + chiusura sessione")
                drop_session(power_off=True)
            cc = session.devinfo.get("close_camera") if session else 1
            state.update(status="privacy", close_camera=cc)
            state.wait_change(600)
            continue

        # --- stato desiderato ON → assicura sessione + video ---------------
        if session is None or not session.connected:
            state.update(status="waking")
            log.info("connessione TNP...")
            session = TnpSession(p2pid, license_key, init_string)
            session.desired_on = True
            if not session.connect(timeout=10):
                log.warning("connect fallito — ritento tra 30 s")
                session = None
                state.update(status="error")
                state.wait_change(30)
                continue
            log.info("sessione attiva: %s — apertura canale video", session.server)
            session.start_video(password=_fresh_view_password(p2pid))
            reasm = FrameReassembler(password=session.p2p_password)
            state.update(server=str(session.server),
                         close_camera=session.devinfo.get("close_camera"))

        # --- pompa i frame verso ffmpeg finché resta ON --------------------
        # I frame arrivano dal P2P a raffica e senza timestamp. Il wall-clock
        # NON basta (frame della stessa raffica → timestamp identici → DTS
        # all'indietro → Frigate resta fermo). Si FORZA il framerate d'ingresso
        # con `-r` (opzione di INPUT, prima di `-i`): il demuxer h264 grezzo
        # assegna timestamp sequenziali (0, 1/fps, 2/fps, …) in ordine di
        # decodifica → DTS strettamente monotòni a prescindere dalle raffiche
        # → stream fluido.
        fps = os.environ.get("YIMIRROR_FPS", "15")
        cmd = ["ffmpeg", "-loglevel", "warning",
               "-r", fps, "-f", "h264", "-i", "pipe:0",
               "-c", "copy", "-f", "rtsp", "-rtsp_transport", "tcp", RTSP_URL]
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        start = time.time()
        last_pub = 0.0
        last_frame = start
        announced = False
        # L'I-frame YI (unwrap → `00 00 00 01 67` = SPS+PPS+IDR) è l'UNICO frame
        # che porta SPS/PPS: i P-frame no. Se ffmpeg riceve per primo un P-frame
        # va in "non-existing PPS 0 / dimensions not set" e non apre l'output.
        # → scarta i P-frame finché non è passato il primo keyframe di QUESTA
        # sessione ffmpeg (seen_key si azzera a ogni (ri)avvio di ffmpeg).
        seen_key = False
        # Se la camera dorme, 0x2345 non produce frame: NON restare appesi nella
        # stessa sessione (la camera, risvegliata dopo, va agganciata con una
        # sessione FRESCA). Riconnetti se non arriva nulla entro questi timeout.
        NOFRAME_START = 25.0      # nessun primo frame → sessione stantia, riconnetti
        NOFRAME_DROP = 30.0       # stream morto a metà → riconnetti
        try:
            while p.poll() is None and state.desired_on:
                for pkt in session.run_video(1.0, ack_interval=1.0):
                    vf = reasm.feed(pkt)
                    if vf is None:
                        continue
                    u = unwrap_frame(vf)
                    reasm.frames.clear()
                    if not u:
                        continue
                    if not seen_key:
                        # aspetta il primo I-frame (SPS/PPS) prima di scrivere
                        if not u.startswith(b"\x00\x00\x00\x01\x67"):
                            continue
                        seen_key = True
                    try:
                        p.stdin.write(u)
                        p.stdin.flush()
                    except (BrokenPipeError, OSError):
                        break
                    last_frame = time.time()
                    state.note_frame()
                    if not announced:
                        state.update(status="streaming",
                                     close_camera=session.devinfo.get("close_camera"))
                        announced = True
                now = time.time()
                if now - last_pub >= heartbeat:   # keep-alive stato retained
                    state.publish()
                    last_pub = now
                if not announced and now - start > NOFRAME_START:
                    log.info("nessun frame entro %.0fs — riconnessione fresca", NOFRAME_START)
                    break
                if announced and now - last_frame > NOFRAME_DROP:
                    log.warning("stream fermo da %.0fs — riconnessione", NOFRAME_DROP)
                    break
                if now - start > restart_every:
                    break
        finally:
            try:
                p.stdin.close()
            except OSError:
                pass
            p.wait()
        # sessione senza frame → buttala, la prossima iterazione riconnette da zero
        if not announced and session is not None:
            session.close()
            session = None

        if not state.desired_on:
            continue                      # transizione a OFF gestita in testa
        # stream caduto ma ancora ON: la sessione può essere morta → riconnetto
        log.warning("stream interrotto — riavvio")
        state.update(status="waking")
        if session is not None and not session.connected:
            session = None
        time.sleep(2)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bitrate", default="4M")
    ap.add_argument("--source", choices=["screen", "native"], default="screen")
    args = ap.parse_args()
    logging.basicConfig(level=os.environ.get("YIMIRROR_LOG", "INFO").upper(),
                        format="%(asctime)s %(name)s: %(message)s")
    if not RTSP_URL:
        log.error("imposta RTSP_URL (rtsp://USER:PASS@VPS:8554/ingresso)")
        raise SystemExit(1)

    if args.source == "native":
        push_native_loop()
        return

    while True:
        if not live_view_active():
            log.info("live view non attiva — attendo")
            time.sleep(30)
            continue
        log.info("push verso %s", RTSP_URL.split("@")[-1])
        # adb screenrecord in streaming -> ffmpeg -> RTSP (publish)
        p1 = subprocess.Popen(
            [ADB, "exec-out", "screenrecord", "--output-format=h264",
             "--bit-rate", args.bitrate, "-"],
            stdout=subprocess.PIPE)
        cmd = ["ffmpeg", "-loglevel", "warning", "-f", "h264", "-i", "pipe:0",
               "-c", "copy", "-f", "rtsp", "-rtsp_transport", "tcp", RTSP_URL]
        p2 = subprocess.Popen(cmd, stdin=p1.stdout)
        p1.stdout.close()
        rc = p2.wait()
        try:
            p1.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p1.terminate()
        # screenrecord ha un limite nativo di ~3 minuti: riavvio rapido per
        # minimizzare il buco nello stream (Frigate/HLS si ricollegano da soli)
        log.warning("stream interrotto (rc=%s) — riavvio immediato", rc)
        time.sleep(2)


if __name__ == "__main__":
    main()
