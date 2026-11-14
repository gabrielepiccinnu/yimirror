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


def push_native_loop(restart_every: float = 3600.0) -> None:
    """Sessione TNP nativa → unwrap → pipe ffmpeg → RTSP (produzione, §7w)."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from tnp_client import TnpSession
    from tnp_proto import FrameReassembler, unwrap_frame

    p2pid = os.environ.get("YIMIRROR_P2PID", "")
    license_key = os.environ.get("YIMIRROR_LICENSE", "")
    init_string = os.environ.get("YIMIRROR_INIT_STRING", "")
    if not (p2pid and license_key and init_string):
        log.error("source native: servono YIMIRROR_P2PID, YIMIRROR_LICENSE, "
                  "YIMIRROR_INIT_STRING")
        raise SystemExit(1)
    session = TnpSession(p2pid, license_key, init_string)
    reasm = FrameReassembler(password=os.environ.get("YIMIRROR_P2P_PASSWORD", ""))
    while True:
        if not session.connected:
            log.info("connessione TNP...")
            if not session.connect(timeout=10):
                log.warning("connect fallito — ritento tra 30 s")
                time.sleep(30)
                continue
            log.info("sessione attiva: %s — apertura canale video", session.server)
            session.start_video()
            reasm = FrameReassembler(password=session.p2p_password)
        cmd = ["ffmpeg", "-loglevel", "warning", "-f", "h264", "-i", "pipe:0",
               "-c", "copy", "-f", "rtsp", "-rtsp_transport", "tcp", RTSP_URL]
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        start = time.time()
        try:
            while p.poll() is None:
                for pkt in session.run_video(1.0, ack_interval=1.0):
                    vf = reasm.feed(pkt)
                    if vf is None:
                        continue
                    u = unwrap_frame(vf)
                    reasm.frames.clear()
                    if not u:
                        continue
                    try:
                        p.stdin.write(u)
                        p.stdin.flush()
                    except (BrokenPipeError, OSError):
                        break
                if time.time() - start > restart_every:
                    break
        finally:
            try:
                p.stdin.close()
            except OSError:
                pass
            p.wait()
        log.warning("stream interrotto — riavvio immediato")
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
