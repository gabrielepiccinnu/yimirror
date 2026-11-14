"""live.py — BRIDGE: cattura la sorgente video TNP e la consegna a un sistema di storage.

Sorgente (default `tap`): sniffer UDP dello stream TNP (pacchetti f1d0 verso/da
82.192.139.67) → frame → segmenti .h264 rolling (default 60 s).
Consegna (`YIMIRROR_UPLOAD`):
- `http`: POST dei segmenti a un server di ingest (es. `src/ingest.py` sul tuo server)
- `rclone`: upload verso Google Drive / Backblaze B2 / altro backend rclone
- `local`: solo salvataggio in data/live/ (per test)
Retention (default 7 giorni): lato server (`ingest.py`) e/o sweep rclone.

Prerequisito: cattura pacchetti → sudo su macOS, o Docker con `--net host` + NET_RAW.
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tnp_proto import FrameReassembler  # noqa: E402
from tap import sniff_udp  # noqa: E402
from uploader import upload_file  # noqa: E402

log = logging.getLogger("yimirror.live")

DATA_DIR = Path(os.environ.get("YIMIRROR_DATA_DIR", "./data"))
PENDING = DATA_DIR / "live"
REMOTE_ROOT = "live"
ADB = os.environ.get("YIMIRROR_ADB", "adb")


def adb(*args: str, timeout: int = 30) -> str:
    return subprocess.run([ADB, *args], capture_output=True, text=True,
                          timeout=timeout).stdout.strip()


def upload_http(path: Path, endpoint: str) -> bool:
    """POST multipart del segmento al server di ingest (basic auth + token)."""
    import requests
    user = os.environ.get("YIMIRROR_INGEST_USER", "")
    password = os.environ.get("YIMIRROR_INGEST_PASS", "")
    token = os.environ.get("YIMIRROR_INGEST_TOKEN", "")
    headers = {"X-Ingest-Token": token} if token else {}
    auth = (user, password) if user else None
    with open(path, "rb") as f:
        r = requests.post(endpoint.rstrip("/") + "/segments",
                          files={"file": (path.name, f)},
                          auth=auth, headers=headers, timeout=120)
    if r.status_code not in (200, 201):
        log.warning("POST fallito (%d): %s", r.status_code, r.text[:200])
        return False
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seconds", type=int, default=60, help="durata segmento (default 60)")
    ap.add_argument("--source", choices=["adb", "tap", "screen", "native"], default="adb",
                    help="adb: tcpdump sul device (grezzo TNP) — tap: sniffer UDP "
                         "sull'host (sudo) — screen: screenrecord → MP4 giocabili — "
                         "native: sessione TNP nativa del proxy (§7v/§7w, richiede "
                         "YIMIRROR_P2PID/LICENSE/INIT_STRING)")
    ap.add_argument("--host", default=os.environ.get("YIMIRROR_TNP_HOST", "82.192.139.67"),
                    help="host TNP da catturare (default il relay)")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--pcap", default="", help="sorgente offline (verifica)")
    args = ap.parse_args()

    logging.basicConfig(level=os.environ.get("YIMIRROR_LOG", "INFO").upper(),
                        format="%(asctime)s %(name)s: %(message)s")
    upload = os.environ.get("YIMIRROR_UPLOAD", "local")   # http | rclone | local
    endpoint = os.environ.get("YIMIRROR_INGEST_URL", "")
    bucket = os.environ.get("B2_BUCKET") or os.environ.get("YIMIRROR_BUCKET")
    remote_name = os.environ.get("YIMIRROR_REMOTE", "b2")
    retention = int(os.environ.get("YIMIRROR_RETENTION_DAYS", "7"))
    PENDING.mkdir(parents=True, exist_ok=True)

    log.info("bridge: host=%s segment=%ds upload=%s retention=%dd",
             args.host, args.seconds, upload, retention)

    def finish_segment(reasm: FrameReassembler, day: str, start_ts: float,
                       h264: bytes | None = None) -> None:
        if reasm.stats["video"] == 0:
            return
        name = f"live-{datetime.now().strftime('%H%M%S')}.h264"
        dest = PENDING / day / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(h264 if h264 is not None else reasm.h264())
        log.info("segmento: %s (%d frame, %d B in %.0fs)",
                 dest.name, reasm.stats["video"], dest.stat().st_size,
                 time.time() - start_ts)
        if upload == "http" and endpoint:
            upload_http(dest, endpoint) and dest.unlink(missing_ok=True)
        elif upload == "rclone" and bucket:
            try:
                upload_file(str(dest), f"{REMOTE_ROOT}/{day}/{name}", bucket,
                            remote_name=remote_name)
                dest.unlink(missing_ok=True)
                subprocess.run(["rclone", "delete", "--min-age", f"{retention}d",
                                f"{remote_name}:{bucket}/yi-home/{REMOTE_ROOT}"],
                               capture_output=True, timeout=300)
            except Exception as e:  # noqa: BLE001
                log.error("upload rclone fallito (riprovo): %s", e)
        # local: resta in data/live/ (pulizia retention locale sotto)
        if upload == "local":
            cutoff = time.time() - retention * 86400
            for old in PENDING.glob("*/*.h264"):
                try:
                    if old.stat().st_mtime < cutoff:
                        old.unlink()
                        log.info("retention locale: rimosso %s", old)
                except OSError:
                    pass

    session = None
    if args.source == "native":
        from tnp_client import TnpSession
        p2pid = os.environ.get("YIMIRROR_P2PID", "")
        license_key = os.environ.get("YIMIRROR_LICENSE", "")
        init_string = os.environ.get("YIMIRROR_INIT_STRING", "")
        if not (p2pid and license_key and init_string):
            log.error("source native: servono YIMIRROR_P2PID, YIMIRROR_LICENSE, "
                      "YIMIRROR_INIT_STRING")
            raise SystemExit(1)
        session = TnpSession(p2pid, license_key, init_string)

    while True:
        day = datetime.now().strftime("%Y-%m-%d")
        reasm = FrameReassembler()
        start = time.time()
        if args.pcap:
            from tap import parse_pcap_udp
            for payload in parse_pcap_udp(args.pcap):
                reasm.feed(payload)
            finish_segment(reasm, day, start)
            return
        if args.source == "screen":
            # screenrecord sul device → MP4 giocabile (bitrate config, default 2 Mbps)
            name = f"live-{datetime.now().strftime('%H%M%S')}.mp4"
            dest = PENDING / day / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            remote = "/sdcard/yimirror-seg.mp4"
            bitrate = int(os.environ.get("YIMIRROR_SCREEN_BITRATE", "2000000"))
            adb("shell", "rm", "-f", remote)
            proc = subprocess.run(
                [ADB, "shell", "screenrecord", "--time-limit", str(args.seconds),
                 "--bit-rate", str(bitrate), remote],
                capture_output=True, text=True, timeout=args.seconds + 30)
            r = subprocess.run([ADB, "pull", remote, str(dest)],
                               capture_output=True, text=True, timeout=120)
            adb("shell", "rm", "-f", remote)
            if r.returncode == 0 and dest.exists() and dest.stat().st_size > 1000:
                log.info("segmento MP4: %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
                if upload == "http" and endpoint:
                    upload_http(dest, endpoint) and dest.unlink(missing_ok=True)
                elif upload == "rclone" and bucket:
                    try:
                        upload_file(str(dest), f"{REMOTE_ROOT}/{day}/{name}", bucket,
                                    remote_name=remote_name)
                        dest.unlink(missing_ok=True)
                    except Exception as e:  # noqa: BLE001
                        log.error("upload rclone fallito (riprovo): %s", e)
            else:
                log.warning("screenrecord fallito (rc=%s)", proc.returncode)
            if args.once:
                break
            continue
        if args.source == "adb":
            # tcpdump sul device (root) → pull → parse: niente sudo sull'host
            remote = "/data/local/tmp/yimirror-seg.pcap"
            local = Path("/tmp/yimirror-seg.pcap")
            adb("shell", "rm", "-f", remote)
            proc = subprocess.Popen(
                [ADB, "shell", "tcpdump", "-i", "any", "-s", "0",
                 "-w", remote, "udp", "and", "host", args.host],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(args.seconds)
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            time.sleep(1)
            subprocess.run([ADB, "pull", remote, str(local)],
                           capture_output=True, timeout=60)
            adb("shell", "rm", "-f", remote)
            if local.exists():
                from tap import parse_pcap_udp
                for payload in parse_pcap_udp(str(local)):
                    reasm.feed(payload)
                local.unlink()
        elif args.source == "native":
            from tnp_proto import unwrap_yi_stream
            assert session is not None
            if session.p2p_password:
                reasm = FrameReassembler(password=session.p2p_password)
            if not session.connected:
                log.info("connessione TNP...")
                if not session.connect(timeout=10):
                    log.warning("connect fallito — ritento tra 30 s")
                    time.sleep(30)
                    continue
                log.info("sessione attiva: %s — apertura canale video", session.server)
                session.start_video()
            idle = time.time()
            while time.time() - start < args.seconds:
                got = session.run_video(1.0, ack_interval=1.0)
                for pkt in got:
                    reasm.feed(pkt)
                if got:
                    idle = time.time()
                if time.time() - idle > 60:
                    log.warning("nessun frame da 60 s — sessione da ristabilire")
                    session.close()
                    break
            finish_segment(reasm, day, start, h264=unwrap_yi_stream(reasm.frames))
            if args.once:
                break
            continue
        else:
            for payload in sniff_udp(host=args.host):
                if payload is not None:
                    reasm.feed(payload)
                if time.time() - start >= args.seconds:
                    break
        finish_segment(reasm, day, start)
        if args.once:
            break


if __name__ == "__main__":
    main()
