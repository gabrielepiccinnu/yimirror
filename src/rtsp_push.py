"""rtsp_push.py — PUSH dello stream verso il proxy RTSP sul VPS (Frigate legge).

Due sorgenti:
- `--source screen` (default, banco di test): screenrecord dell'emulatore con
  l'app in live view → H.264 → RTSP. Richiede adb + emulatore.
- `--source native` (produzione, §7v/§7w): sessione TNP nativa del proxy —
  frame 0xd0 dal relay → unwrap I-frame 0x3D → annex-b → ffmpeg → RTSP.
  Con YIMIRROR_AUDIO=1 (default) manda IOCTRL 0x0300 AUDIOSTART dopo il primo
  keyframe e muxa l'AAC del canale TNP 1 (ADTS) come seconda traccia RTSP.
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

# --- audio camera (IOCTRL 0x0300 AUDIOSTART, canale TNP 1) --------------------
# Il byte `flags` del TNPFrameHead audio codifica il sample rate:
# flags>>>2 = indice (AVFrame.getSamplerate, com/tutk/IOTC).
_SR_BY_FLAG_IDX = {0: 16000, 1: 11025, 2: 12000, 3: 16000, 4: 22050,
                   5: 24000, 6: 32000, 7: 44100, 8: 48000}
_ADTS_IDX = {16000: 8, 11025: 10, 12000: 9, 22050: 7, 24000: 6,
             32000: 5, 44100: 4, 48000: 3, 8000: 11}


def _audio_rate(head) -> int:
    return _SR_BY_FLAG_IDX.get(head.flags >> 2, 16000)


def adts_wrap(payload: bytes, rate: int) -> bytes:
    """AAC grezzo (senza ADTS, come lo invia la camera) → frame ADTS (7 B)
    per il demuxer `-f aac` di ffmpeg. Profilo LC, mono."""
    idx = _ADTS_IDX.get(rate, 8)
    ln = len(payload) + 7
    hdr = bytes([
        0xFF, 0xF1,                        # sync + MPEG-4 + layer 0 + no CRC
        0x40 | (idx << 2),                 # profile LC(01) + sf idx + priv 0 + chcfg>>2
        0x40 | ((ln >> 11) & 0x3),         # chcfg(1) + frame len high
        (ln >> 3) & 0xFF,
        ((ln & 0x7) << 5) | 0x1F,
        0xFC,                              # fullness low + num raw blocks-1 = 0
    ])
    return hdr + payload


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
    from tnp_proto import FrameReassembler, unwrap_frame, AudioFrame, AUDIO_CODECS
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
    # Anti-mute del relay (§7x-bis): a mutare l'IP è lo SPAM di handshake+wake,
    # non i resend su sessione calda. Quindi NON si ricostruisce la sessione a
    # ogni buco: la si tiene calda (run_video ri-triggera 0x2345 a caldo ogni ~4s
    # + keepalive) e si fa un vero re-handshake SOLO dopo REHANDSHAKE_AFTER di 0
    # frame, con backoff esponenziale tra i tentativi falliti.
    REHANDSHAKE_AFTER = float(os.environ.get("YIMIRROR_REHANDSHAKE_AFTER", "120"))
    BACKOFF_BASE = float(os.environ.get("YIMIRROR_BACKOFF_BASE", "60"))
    BACKOFF_MAX = float(os.environ.get("YIMIRROR_BACKOFF_MAX", "300"))
    fail_streak = 0                    # reconnect consecutivi senza frame (→ backoff)

    def backoff_wait() -> float:
        return min(BACKOFF_BASE * 2 ** max(fail_streak - 1, 0), BACKOFF_MAX)

    privacy_done = False               # privacy 0x1304 confermata (close_camera=1)

    while True:
        # --- stato desiderato OFF → privacy REALE sulla camera (0x1304) -----
        if not state.desired_on:
            # Spegnimento affidabile: ci si connette APPOSTA se serve, si manda
            # 0x1304 e si VERIFICA close_camera=1 (prima si mandava solo se una
            # sessione era già viva → con OFF a sessione chiusa la camera restava
            # accesa). Un flag evita di ripetere; se fallisce, backoff.
            if not privacy_done:
                try:
                    if session is None or not session.connected:
                        log.info("OFF richiesto → connessione per privacy...")
                        session = TnpSession(p2pid, license_key, init_string)
                        session.desired_on = False
                        if not session.connect(timeout=10):
                            session = None
                            raise RuntimeError("connect per privacy fallito")
                    session.p2p_password = _fresh_view_password(p2pid)
                    ok = session.set_camera_power(False)   # privacy mode reale
                    cc = session.devinfo.get("close_camera")
                    session.close()
                    session = None
                    if not ok:
                        raise RuntimeError(f"0x1304 non confermato (close_camera={cc})")
                    privacy_done = True
                    fail_streak = 0
                    log.info("privacy applicata: camera spenta (close_camera=%s)", cc)
                except Exception as exc:
                    fail_streak += 1
                    wait = backoff_wait()
                    log.warning("privacy OFF non applicata: %s — ritento tra %.0fs",
                                exc, wait)
                    session = None
                    state.update(status="error")
                    state.wait_change(wait)
                    continue
            state.update(status="privacy", close_camera=1)
            state.wait_change(600)
            continue

        # --- stato desiderato ON → assicura sessione + video ---------------
        privacy_done = False           # alla prossima OFF si riapplica privacy
        if session is None or not session.connected:
            state.update(status="waking")
            log.info("connessione TNP...")
            session = TnpSession(p2pid, license_key, init_string)
            session.desired_on = True
            if not session.connect(timeout=10):
                fail_streak += 1
                wait = backoff_wait()
                log.warning("connect fallito — backoff %.0fs (tentativo %d)", wait, fail_streak)
                session = None
                state.update(status="error")
                state.wait_change(wait)
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
        # decodifica → DTS strettamente monotòni a prescindere dalle raffiche.
        # FLUIDITÀ: un `-r` fisso sbagliato rende il video accelerato (se la
        # camera va più piano) o in ritardo crescente (se va più veloce). Quindi
        # si MISURA l'fps reale sui primi secondi di stream e si avvia ffmpeg con
        # quel valore. Durante la misura i frame (dal primo keyframe) si
        # bufferizzano e poi si riversano in ffmpeg. `YIMIRROR_FPS` forza il
        # valore e salta la misura.
        fps_override = os.environ.get("YIMIRROR_FPS", "").strip()
        MEASURE_SECONDS = float(os.environ.get("YIMIRROR_MEASURE_SECONDS", "4"))
        MEASURE_MIN_FRAMES = int(os.environ.get("YIMIRROR_MEASURE_MIN_FRAMES", "20"))
        audio_enabled = os.environ.get("YIMIRROR_AUDIO", "1") not in ("0", "false", "no")
        AUDIO_GRACE = float(os.environ.get("YIMIRROR_AUDIO_GRACE", "5"))
        audio_rate_override = os.environ.get("YIMIRROR_AUDIO_RATE", "").strip()
        if audio_rate_override:
            audio_rate_override = int(audio_rate_override)

        def start_ffmpeg(fps: str, with_audio: bool) -> "tuple[subprocess.Popen, int | None]":
            """Video su pipe:0; audio (se with_audio) su pipe:1 = fd 1 del
            processo (preexec dup2 della fine lettura di un os.pipe). Il
            demuxer aac legge i frame ADTS e li timesta da sé (durata per
            frame) → pacing audio reale senza opzioni extra."""
            cmd = ["ffmpeg", "-loglevel", "warning",
                   "-r", fps, "-f", "h264", "-i", "pipe:0"]
            if with_audio:
                # rate e canali li porta l'ADTS: niente -ar/-ac (ffmpeg 9 non
                # li accetta come opzioni input del demuxer aac)
                cmd += ["-f", "aac", "-i", "pipe:1"]
            cmd += ["-map", "0:v:0"]
            if with_audio:
                cmd += ["-map", "1:a:0", "-c:a", "copy"]
            cmd += ["-c:v", "copy", "-f", "rtsp", "-rtsp_transport", "tcp", RTSP_URL]
            aw = None
            if with_audio:
                ar, aw = os.pipe()

                def _dup_audio():
                    os.dup2(ar, 1)          # pipe:1 = fd 1 → fine lettura audio
                    os.close(ar)

                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                        pass_fds=(ar,), preexec_fn=_dup_audio)
                os.close(ar)
            else:
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
            return proc, aw

        p: "subprocess.Popen | None" = None   # ffmpeg: avviato dopo la misura fps
        aw: "int | None" = None               # fd scrittura pipe audio (se attivo)
        start = time.time()
        last_pub = 0.0
        last_frame = start
        announced = False
        # L'I-frame YI (unwrap → `00 00 00 01 67` = SPS+PPS+IDR) è l'UNICO frame
        # che porta SPS/PPS: i P-frame no. Se ffmpeg riceve per primo un P-frame
        # va in "non-existing PPS 0 / dimensions not set" e non apre l'output.
        # → scarta i P-frame finché non è passato il primo keyframe.
        seen_key = False
        buf_frames: list[bytes] = []          # frame in attesa della misura fps
        audio_sent = False                    # AUDIOSTART 0x0300 per questa sessione
        audio_seen = False                    # primo frame audio ricevuto
        buf_audio: list[bytes] = []           # ADTS audio in attesa di ffmpeg
        measure_start = 0.0                    # tempo del primo keyframe
        ts_first = ts_last = None              # ts_ms camera (diagnostica fps reale)
        ts_count = 0
        # Niente frame: si TIENE la sessione calda (run_video ri-triggera 0x2345 a
        # caldo + keepalive) e si re-handshaka solo dopo REHANDSHAKE_AFTER, per non
        # martellare il relay (§7x-bis). NOFRAME_DROP resta breve: se lo stream era
        # partito e cade, la sessione è morta → riconnetti presto.
        NOFRAME_DROP = 30.0       # stream morto a metà → riconnetti
        try:
            # UNA sola chiamata lunga al generatore (NON in un loop a 1s, che
            # azzererebbe i timer interni → check-online 0x18 ~1/s → mute del
            # relay §7x-bis). Il generatore emette i frame appena arrivano
            # (fluidità) e `None` sui tick di housekeeping.
            for pkt in session.run_video(restart_every, ack_interval=1.0):
                if (p is not None and p.poll() is not None) or not state.desired_on:
                    break
                if pkt is not None:
                    mf = reasm.feed(pkt)
                    if isinstance(mf, AudioFrame):
                        # --- audio: canale 1, dopo AUDIOSTART 0x0300 ---------
                        rate = audio_rate_override or _audio_rate(mf.head)
                        if not audio_seen:
                            audio_seen = True
                            log.info("PRIMO frame audio: codec=0x%04X (%s) "
                                     "flags=0x%02X rate=%dHz len=%d decifrato=%s",
                                     mf.codec_id, AUDIO_CODECS.get(mf.codec_id, "?"),
                                     mf.head.flags, rate, len(mf.data),
                                     mf.is_decrypted)
                        adts = adts_wrap(mf.data, rate)
                        if aw is not None:
                            try:
                                os.write(aw, adts)
                            except OSError:
                                pass
                        elif p is None:
                            buf_audio.append(adts)   # ffmpeg non ancora avviato
                        # (se ffmpeg è partito solo-video, i frame tardivi si scartano)
                    elif mf is not None:
                        vf = mf
                        u = unwrap_frame(vf)
                        reasm.frames.clear()
                        # gate keyframe: considera solo dopo il primo I-frame
                        if u and (seen_key or u.startswith(b"\x00\x00\x00\x01\x67")):
                            if not seen_key:
                                seen_key = True
                                measure_start = time.time()
                                if audio_enabled and not audio_sent:
                                    # AUDIOSTART appena la camera streamma video
                                    # (come l'app: live aperta → toggle audio)
                                    session.start_audio()
                                    audio_sent = True
                                    log.info("AUDIOSTART 0x0300 inviato")
                            if vf.head.ts_ms:            # diagnostica fps camera
                                if ts_first is None:
                                    ts_first = vf.head.ts_ms
                                ts_last = vf.head.ts_ms
                                ts_count += 1
                            if p is None:
                                # fase di misura: bufferizza finché non so l'fps
                                buf_frames.append(u)
                                elapsed = time.time() - measure_start
                                ready = bool(fps_override) or (
                                    elapsed >= MEASURE_SECONDS
                                    and len(buf_frames) >= MEASURE_MIN_FRAMES
                                ) or (elapsed >= MEASURE_SECONDS * 2
                                      and len(buf_frames) >= 2)
                                if audio_enabled and not audio_seen and not fps_override:
                                    # decide il mux audio: aspetta il primo frame
                                    # audio entro la grazia, altrimenti parte
                                    # solo-video (camera senza audio / 0x0300 rifiutato)
                                    ready = (ready and
                                             elapsed >= MEASURE_SECONDS + AUDIO_GRACE)
                                if ready:
                                    if fps_override:
                                        fps = fps_override
                                        src = "env"
                                    else:
                                        measured = len(buf_frames) / max(elapsed, 0.001)
                                        measured = max(5.0, min(30.0, measured))
                                        fps = f"{measured:.2f}"
                                        src = "wall-clock"
                                    if (ts_first is not None and ts_last is not None
                                            and ts_last > ts_first and ts_count > 1):
                                        cam_fps = (ts_count - 1) * 1000.0 / (ts_last - ts_first)
                                        log.info("fps camera (ts_ms): %.2f su %d frame",
                                                 cam_fps, ts_count)
                                    with_audio = bool(audio_enabled and audio_seen)
                                    log.info("avvio ffmpeg a %s fps (%s)%s, %d frame bufferizzati",
                                             fps, src, " + audio" if with_audio else "",
                                             len(buf_frames))
                                    p, aw = start_ffmpeg(fps, with_audio)
                                    try:
                                        for fb in buf_frames:
                                            p.stdin.write(fb)
                                        p.stdin.flush()
                                    except (BrokenPipeError, OSError):
                                        pass
                                    if aw is not None:
                                        try:
                                            for adts in buf_audio:
                                                os.write(aw, adts)
                                        except OSError:
                                            pass
                                    buf_frames = []
                                    buf_audio = []
                                    last_frame = time.time()
                                    state.note_frame()
                                    state.update(status="streaming",
                                                 close_camera=session.devinfo.get("close_camera"))
                                    announced = True
                            else:
                                try:
                                    p.stdin.write(u)
                                    p.stdin.flush()
                                except (BrokenPipeError, OSError):
                                    break
                                last_frame = time.time()
                                state.note_frame()
                now = time.time()
                if now - last_pub >= heartbeat:   # keep-alive stato retained
                    state.publish()
                    last_pub = now
                if not announced and now - start > REHANDSHAKE_AFTER:
                    log.info("nessun frame entro %.0fs su sessione calda — re-handshake",
                             REHANDSHAKE_AFTER)
                    break
                if announced and now - last_frame > NOFRAME_DROP:
                    log.warning("stream fermo da %.0fs — riconnessione", NOFRAME_DROP)
                    break
        finally:
            if aw is not None:
                try:
                    os.close(aw)
                except OSError:
                    pass
            if p is not None:
                try:
                    p.stdin.close()
                except OSError:
                    pass
                p.wait()
        if not state.desired_on:
            continue                      # transizione a OFF (privacy) gestita in testa
        if announced:
            # avevamo frame → nessun mute: azzera il backoff, riconnetti presto.
            # Se la sessione regge (solo ffmpeg caduto) la si tiene calda.
            fail_streak = 0
            log.warning("stream interrotto — riavvio")
            state.update(status="waking")
            if session is not None and not session.connected:
                session.close()
                session = None
            time.sleep(2)
        else:
            # 0 frame dopo REHANDSHAKE_AFTER su sessione calda: probabile relay muto
            # o camera che non streamma → butta la sessione e re-handshaka con
            # backoff crescente (non martellare il relay, §7x-bis).
            fail_streak += 1
            wait = backoff_wait()
            if session is not None:
                session.close()
                session = None
            log.warning("0 frame — re-handshake tra %.0fs (tentativo %d)", wait, fail_streak)
            state.update(status="waking")
            state.wait_change(wait)


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
