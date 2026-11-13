"""rtsp_push.py — PUSH dello stream (test dal Mac) verso il proxy RTSP sul VPS.

SOLO banco di test: streamma lo schermo dell'emulatore (live view attiva) come
H.264 e lo pubblica su rtsp://USER:PASS@VPS:8554/ingresso, da cui Frigate legge.
In produzione il concetto è lo stesso su un device Android dedicato (o il client
TNP nativo nel proxy — findings §7d).

Uso:
  RTSP_URL=rtsp://bridge:PASS@164.68.119.188:8554/ingresso \
    python3 src/rtsp_push.py [--bitrate 4M]
Richiede: emulatore con app in live view, adb nel PATH, ffmpeg.
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


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bitrate", default="4M")
    args = ap.parse_args()
    logging.basicConfig(level=os.environ.get("YIMIRROR_LOG", "INFO").upper(),
                        format="%(asctime)s %(name)s: %(message)s")
    if not RTSP_URL:
        log.error("imposta RTSP_URL (rtsp://USER:PASS@VPS:8554/ingresso)")
        raise SystemExit(1)

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
        log.warning("stream interrotto (rc=%s) — riavvio tra 5s", rc)
        time.sleep(5)


if __name__ == "__main__":
    main()
