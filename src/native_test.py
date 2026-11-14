"""native_test.py — Gate A/B: sessione TNP nativa → cold start (§7w) → frame → parsing.

Replica il wire ESATTO: handshake (§7v) → 0xa0 ai server P2P → e0 → controlli
IOCTRL autenticati → ack ritmici → frame 0xd0 dal relay.

Credenziali: da variabili d'ambiente o da tools/yimirror/.env (gitignored):
  YIMIRROR_P2PID, YIMIRROR_LICENSE, YIMIRROR_INIT_STRING, YIMIRROR_P2P_PASSWORD

Uso (camera online):
  python3 src/native_test.py [--seconds 30] [--dump /tmp/live.h264]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from env_loader import load_env             # noqa: E402
from tnp_client import TnpSession          # noqa: E402
from tnp_proto import FrameReassembler     # noqa: E402

load_env()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seconds", type=float, default=30)
    ap.add_argument("--dump", default="/tmp/live.h264")
    args = ap.parse_args()

    p2pid = os.environ.get("YIMIRROR_P2PID", "")
    license_key = os.environ.get("YIMIRROR_LICENSE", "")
    init = os.environ.get("YIMIRROR_INIT_STRING", "")
    if not (p2pid and license_key and init):
        print("servono YIMIRROR_P2PID, YIMIRROR_LICENSE, YIMIRROR_INIT_STRING "
              "(vedi .env.example)")
        raise SystemExit(1)

    s = TnpSession(p2pid, license_key, init)
    ok = s.connect(timeout=8)
    print(f"connect: {ok} | server: {s.server}")
    if not ok:
        return
    print("0x42:", s.h42.hex())
    print("cold start (0xa0 + controlli 0xd0)...")
    started = s.start_video()
    print("risposta relay ai controlli:", started)
    print(f"ascolto {args.seconds:.0f} s...")
    frames = s.run_video(args.seconds, ack_interval=1.0, verbose=True)
    print(f"frame 0xd0 ricevuti: {len(frames)}")
    if frames:
        reasm = FrameReassembler(password=s.p2p_password)
        for pkt in frames:
            reasm.feed(pkt)
        for vf in reasm.frames[:10]:
            h = vf.head
            print(f"  frame: codec={h.codec_id:04x} flags={h.flags} "
                  f"{'I' if h.is_iframe else 'P'} seq={h.seq} {h.width}x{h.height} "
                  f"use_count={h.use_count} data[{len(vf.data)}]={vf.data[:16].hex()}")
        if args.dump:
            Path(args.dump).write_bytes(reasm.h264())
            print(f"dump annex-b: {args.dump} ({reasm.stats})")


if __name__ == "__main__":
    main()
