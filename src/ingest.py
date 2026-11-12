"""ingest.py — server di storage per i segmenti della diretta (stdlib, zero dipendenze).

Da eseguire sul TUO server (o ovunque): riceve i segmenti .h264 dal bridge
(POST /segments multipart), li salva in {data}/live/{YYYY-MM-DD}/ e applica la
retention (default 7 giorni). GET / elenca i segmenti del giorno corrente.

Uso:
  python3 ingest.py --port 8088 --data /var/lib/yimirror [--retention-days 7]

Sicurezza: nessuna auth integrata — esporre solo su rete fiduciata o dietro
reverse proxy con auth (es. Caddy/nginx + basic auth o token header via
YIMIRROR_INGEST_TOKEN).
"""

from __future__ import annotations

import argparse
import cgi
import os
import re
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKEN = os.environ.get("YIMIRROR_INGEST_TOKEN", "")

_RATE = {}          # ip -> lista timestamp (rate limit semplice in-process)
RATE_MAX = 10       # richieste POST consentite per minuto
RATE_WINDOW = 60.0


def rate_ok(ip: str) -> bool:
    now = time.time()
    hits = [t for t in _RATE.get(ip, []) if now - t < RATE_WINDOW]
    _RATE[ip] = hits
    if len(hits) >= RATE_MAX:
        return False
    hits.append(now)
    return True


class Handler(BaseHTTPRequestHandler):
    data_dir: Path = Path("./data")
    retention_days: int = 7

    def log_message(self, fmt, *args):  # silenzioso
        pass

    def _auth_ok(self) -> bool:
        if not TOKEN:
            return True
        return self.headers.get("X-Ingest-Token", "") == TOKEN

    def do_GET(self):
        if self.path.rstrip("/") == "":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            body = f"yimirror ingest ok — retention {self.retention_days}d\n"
            self.wfile.write(body.encode())
            return
        m = re.match(r"^/segments/(\d{4}-\d{2}-\d{2})$", self.path)
        if m:
            day = m.group(1)
            d = self.data_dir / "live" / day
            files = sorted(p.name for p in d.glob("*.h264")) if d.exists() else []
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(("\n".join(files) + "\n").encode())
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path.rstrip("/") != "/segments":
            self.send_response(404)
            self.end_headers()
            return
        if not self._auth_ok():
            self.send_response(401)
            self.end_headers()
            return
        if not rate_ok(self.client_address[0]):
            self.send_response(429)
            self.end_headers()
            return
        ctype, pdict = cgi.parse_header(self.headers.get("Content-Type", ""))
        if ctype != "multipart/form-data":
            self.send_response(400)
            self.end_headers()
            return
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                                environ={"REQUEST_METHOD": "POST",
                                         "CONTENT_TYPE": self.headers["Content-Type"]})
        fitem = form["file"]
        if fitem is None or not fitem.file:
            self.send_response(400)
            self.end_headers()
            return
        name = os.path.basename(fitem.filename) or f"seg-{int(time.time())}.h264"
        if not name.endswith(".h264"):
            name += ".h264"
        day = datetime.now().strftime("%Y-%m-%d")
        dest = self.data_dir / "live" / day
        dest.mkdir(parents=True, exist_ok=True)
        with open(dest / name, "wb") as out:
            while True:
                chunk = fitem.file.read(65536)
                if not chunk:
                    break
                out.write(chunk)
        self.send_response(201)
        self.end_headers()
        self.wfile.write(b"ok\n")
        self._retention()

    def _retention(self):
        cutoff = time.time() - self.retention_days * 86400
        base = self.data_dir / "live"
        if not base.exists():
            return
        for day_dir in base.iterdir():
            if not day_dir.is_dir():
                continue
            try:
                if day_dir.stat().st_mtime < cutoff:
                    for f in day_dir.iterdir():
                        f.unlink()
                    day_dir.rmdir()
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--data", default="./data")
    ap.add_argument("--retention-days", type=int, default=7)
    args = ap.parse_args()

    Handler.data_dir = Path(args.data)
    Handler.retention_days = args.retention_days
    (Handler.data_dir / "live").mkdir(parents=True, exist_ok=True)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"ingest in ascolto su {args.host}:{args.port} — data={Handler.data_dir} "
          f"retention={args.retention_days}d token={'on' if TOKEN else 'off'}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
