"""cloud_mirror.py — Frigate alimentato dalla registrazione cloud in
background della camera (la stessa che il cloud YI usa, senza app).

La camera registra e carica da sola (cloud plan attivo): segmenti .ts ~30s
cifrati AES-128 su OSS Alibaba. Il mirror li scarica/decifra (cloud_reader) e
li spinge a mediamtx → Frigate legge rtsp://mediamtx:8554/ingresso come oggi.
Col piano **Continuous** i segmenti sono contigui → Frigate 24/7 (~1-2 min di
ritardo); col piano Motion arrivano solo gli eventi.

Uso:
  RTSP_URL=rtsp://bridge:PASS@164.68.119.188:8554/ingresso \
    python3 -m src.cloud_mirror
Env: YI_TOKEN/YI_TOKEN_SECRET/YI_USERID (sessione adottata), YIMIRROR_CLOUD_UID
(default dal P2PID), YIMIRROR_CLOUD_POLL (20), YIMIRROR_CLOUD_LOOKBACK (3600),
YIMIRROR_CLOUD_PACE (1 = -re), YIMIRROR_CLOUD_PUBLISH (0/1 = ffmpeg verso RTSP;
0 = spool su disco, per test), YIMIRROR_CLOUD_SPOOL (/data/spool).
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

log = logging.getLogger("yimirror.cloud_mirror")

RTSP_URL = os.environ.get("RTSP_URL", "")


def push_cloud_mirror_loop() -> None:
    from yi_client import YiClient
    from cloud_reader import fetch_new_segments
    from control import ProxyState, start_mqtt, start_api

    token = os.environ.get("YI_TOKEN", "")
    secret = os.environ.get("YI_TOKEN_SECRET", "")
    userid = os.environ.get("YI_USERID", "")
    if not (token and secret):
        log.error("servono YI_TOKEN e YI_TOKEN_SECRET (sessione cloud adottata)")
        raise SystemExit(1)
    uid = os.environ.get("YIMIRROR_CLOUD_UID", "") or os.environ.get(
        "YIMIRROR_P2PID", "")
    if not uid:
        log.error("imposta YIMIRROR_CLOUD_UID (o YIMIRROR_P2PID)")
        raise SystemExit(1)

    state = ProxyState()
    start_mqtt(state)
    start_api(state)

    POLL = float(os.environ.get("YIMIRROR_CLOUD_POLL", "20"))
    LOOKBACK = int(os.environ.get("YIMIRROR_CLOUD_LOOKBACK", "3600"))
    PACE = os.environ.get("YIMIRROR_CLOUD_PACE", "1") == "1"
    PUBLISH = os.environ.get("YIMIRROR_CLOUD_PUBLISH", "1") == "1"
    SPOOL = Path(os.environ.get("YIMIRROR_CLOUD_SPOOL", "/data/spool"))
    SPOOL.mkdir(parents=True, exist_ok=True)
    CURSOR_FILE = SPOOL.parent / "mirror_cursor.txt"

    yc = YiClient(region=os.environ.get("YI_REGION", "eu"))
    yc.adopt_token(token, userid=userid or None, token_secret=secret)

    def cursor() -> int:
        try:
            return int(CURSOR_FILE.read_text().strip())
        except (OSError, ValueError):
            return int(time.time()) - LOOKBACK

    def save_cursor(t: int) -> None:
        try:
            CURSOR_FILE.write_text(str(t))
        except OSError:  # pragma: no cover
            pass

    p: subprocess.Popen | None = None
    last_seg = 0.0
    heartbeat = 15.0
    last_pub = 0.0

    def start_ffmpeg() -> "subprocess.Popen":
        cmd = ["ffmpeg", "-loglevel", "warning"]
        if PACE:
            cmd += ["-re"]
        cmd += ["-f", "mpegts", "-i", "pipe:0",
                "-an",                       # l'AAC del TS non è copiabile su
                                             # RTSP (no global headers); Frigate
                                             # registra solo video
                "-c", "copy", "-f", "rtsp", "-rtsp_transport", "tcp", RTSP_URL]
        return subprocess.Popen(cmd, stdin=subprocess.PIPE)

    def feed(data: bytes) -> None:
        nonlocal p
        if not PUBLISH:
            ts = int(time.time())
            (SPOOL / f"{ts}.ts").write_bytes(data)
            return
        if p is None or p.poll() is not None:
            log.info("avvio ffmpeg verso mediamtx")
            p = start_ffmpeg()
        try:
            p.stdin.write(data)
            p.stdin.flush()
        except (BrokenPipeError, OSError):
            log.warning("ffmpeg caduto — riavvio al prossimo segmento")
            p = None

    while True:
        if not state.desired_on:
            # OFF → stop ffmpeg + privacy reale via P2P (stesso path del
            # push_native_loop: la camera va spenta davvero)
            if p is not None:
                try:
                    p.stdin.close()
                except OSError:
                    pass
                p.wait()
                p = None
            state.update(status="privacy", close_camera=1)
            # privacy 0x1304 riusando la logica del proxy nativo
            from rtsp_push import _fresh_view_password
            from tnp_client import TnpSession
            p2pid = os.environ.get("YIMIRROR_P2PID", "")
            lic = os.environ.get("YIMIRROR_LICENSE", "")
            init = os.environ.get("YIMIRROR_INIT_STRING", "")
            if p2pid and lic and init:
                try:
                    sess = TnpSession(p2pid, lic, init)
                    sess.desired_on = False
                    if sess.connect(timeout=10):
                        sess.p2p_password = _fresh_view_password(p2pid)
                        if sess.set_camera_power(False):
                            log.info("privacy applicata: camera spenta")
                except Exception as exc:  # noqa: BLE001
                    log.warning("privacy fallita: %s", exc)
            state.wait_change(600)
            continue

        now = time.time()
        cur = cursor()
        got = 0
        try:
            for t, dur, data in fetch_new_segments(yc, uid, cur, int(now)):
                feed(data)
                save_cursor(t)
                last_seg = now
                got += 1
        except Exception as exc:  # noqa: BLE001 — il loop deve sopravvivere
            log.warning("ciclo mirror interrotto: %s", exc)
        if got:
            log.info("segmenti scaricati: %d (ultimo %s)", got,
                     time.strftime("%H:%M:%S", time.localtime(last_seg)))
            state.update(status="streaming")
            state.note_frame()
        elif p is not None and now - last_seg > 120:
            # nessun segmento da un po': chiudi il publisher (mediamtx torna
            # 404 e Frigate smette di registrare il vuoto)
            try:
                p.stdin.close()
            except OSError:
                pass
            p.wait()
            p = None
            log.info("nessun segmento da 120s — publisher chiuso")
        if now - last_pub >= heartbeat:
            state.publish()
            last_pub = now
        state.wait_change(POLL)


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()
    logging.basicConfig(level=os.environ.get("YIMIRROR_LOG", "INFO").upper(),
                        format="%(asctime)s %(name)s: %(message)s")
    push_cloud_mirror_loop()


if __name__ == "__main__":
    main()
