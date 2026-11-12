"""Tap recorder — cattura il flusso TNP e salva H.264/MP4 senza reimplementare l'auth.

Due sorgenti:
- `--pcap FILE`: replay offline di una cattura (verifica della pipeline senza device)
- `--udp PORT` (richiede root/NET_RAW sul host): sniffer UDP live su una porta sorgente
  della sessione TNP (es. far puntare il traffico dell'app a questo container come
  gateway, o snifferare su una rete bridge)

Output: NAL stream .h264 (tutti i frame) + MP4 via ffmpeg (playable quando la chiave
media è nota e gli I-frame risultano decifrabili).
"""

from __future__ import annotations

import argparse
import logging
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tnp_proto import FrameReassembler  # noqa: E402

log = logging.getLogger("yimirror.tap")


def parse_pcap_udp(path: str):
    """Generatore: payload UDP di ogni pacchetto (SLL2 o Ethernet)."""
    data = Path(path).read_bytes()
    off = 0
    magic, = struct.unpack("<I", data[0:4])
    endian = "<" if magic == 0xA1B2C3D4 else ">"
    _, _, _, _, _, snaplen, link = struct.unpack(endian + "IHHIIII", data[off:off + 24])
    off += 24
    while off + 16 <= len(data):
        _, _, cap, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + cap]
        off += cap
        if link == 276:          # Linux SLL2: 20-byte header
            if len(pkt) < 28: continue
            if struct.unpack(">H", pkt[0:2])[0] != 0x0800: continue
            ip = pkt[20:]
        elif link == 1:          # Ethernet
            if len(pkt) < 34: continue
            if struct.unpack(">H", pkt[12:14])[0] != 0x0800: continue
            ip = pkt[14:]
        else:
            continue
        if ip[0] >> 4 != 4 or ip[9] != 17: continue
        ihl = (ip[0] & 0x0F) * 4
        _, _, ulen, _ = struct.unpack(">HHHH", ip[ihl:ihl + 8])
        yield ip[ihl + 8:ihl + ulen]


def sniff_udp(host: str | None = None, port: int | None = None,
              iface: str | None = None, timeout: float = 0.5):
    """Sniffer UDP live (solo IPv4; richiede privilegi root/NET_RAW).

    Filtra per destinazione `host` e/o `port`: i pacchetti TNP passano tra il device
    e il relay (es. 82.192.139.67) su porte dinamiche → di norma si filtra per host.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.settimeout(timeout)
    while True:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            yield None
            continue
        if data[0] >> 4 != 4:  # solo IPv4
            continue
        ihl = (data[0] & 0x0F) * 4
        if data[9] != 17:  # solo UDP
            continue
        src = ".".join(str(b) for b in data[12:16])
        dst = ".".join(str(b) for b in data[16:20])
        sport, dport, ulen, _ = struct.unpack(">HHHH", data[ihl:ihl + 8])
        if host and src != host and dst != host:
            continue
        if port and sport != port and dport != port:
            continue
        yield data[ihl + 8:ihl + ulen]


def mux_mp4(h264_path: Path, mp4_path: Path, fps: int = 15) -> bool:
    """ffmpeg: raw H.264 (annexb) -> mp4."""
    cmd = ["ffmpeg", "-y", "-loglevel", "error", "-f", "h264", "-r", str(fps),
           "-i", str(h264_path), "-c", "copy", str(mp4_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        log.error("ffmpeg mux fallito: %s", proc.stderr[-300:])
        return False
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap", help="replay offline del pcap (verifica)")
    ap.add_argument("--udp", type=int, default=0, help="sniff UDP live su questa porta")
    ap.add_argument("--host", default="", help="sniff UDP live da/verso questo host "
                    "(es. il relay 82.192.139.67) — consigliato rispetto a --udp")
    ap.add_argument("--iface", default=None)
    ap.add_argument("--out", default="capture.h264")
    ap.add_argument("--mp4", default="")
    ap.add_argument("--password", default="",
                    help="chiave media (password P2P) — SOLO se lo stream è cifrato; "
                         "i sessioni catturate (model 89) sono IN CHIARO (§7d): non usare")
    ap.add_argument("--max-seconds", type=float, default=0, help="0 = illimitato")
    ap.add_argument("--fps", type=int, default=15)
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    # findings §7d: gli stream catturati sono in chiaro → niente decifratura di default
    reasm = FrameReassembler(password=None)

    start = time.time()
    src = None
    if args.pcap:
        src = parse_pcap_udp(args.pcap)
        total = 0
        for payload in src:
            f = reasm.feed(payload)
            if f is not None:
                total += 1
        log.info("pcap replay: %s (stats=%s)", total, reasm.stats)
    elif args.udp or args.host:
        src = sniff_udp(host=args.host or None, port=args.udp or None, iface=args.iface)
        for payload in src:
            if payload is not None:
                reasm.feed(payload)
            if args.max_seconds and time.time() - start > args.max_seconds:
                break
    else:
        ap.error("serve --pcap, --udp o --host")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(reasm.h264())
    log.info("scritto %s (%d byte, %d frame)", out, out.stat().st_size, reasm.stats["video"])
    if args.mp4:
        ok = mux_mp4(out, Path(args.mp4), args.fps)
        log.info("mp4: %s -> %s", "ok" if ok else "FAILED", args.mp4)


if __name__ == "__main__":
    main()
