"""replay_wake.py — replay ESATTO dei primi ~11 s dell'app dal tap.pcap (§7w).

Sequenza (timing dal pcap, 0x41 rigenerate con ts+sig freschi):
  0.00  0x18 check-online ×1 a ogni server
  0.27  Hello + 0x20 + 0x30 broadcast
  0.42  0x41 ×3 al relay + ×3 al target LAN
  0.51  sulla 0x41-response del relay: 0x41 ×2
  0.58  0xa0 (trailer P2P\\0P) a ogni server
  0.59  0x1300
  1.48  0x03c0
  9.92  Hello + 0x20 + 0x30 di nuovo
  9.97  0x1311 SET_RESOLUTION  -> frame attesi ~0,1 s dopo
  10.4  0x0330 DEVINFO
Poi ascolta N secondi e stampa i frame.
"""
import os
import socket
import sys
import time
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tnp_client as tc           # noqa: E402
from env_loader import load_env   # noqa: E402

load_env()
INIT = os.environ.get("YIMIRROR_INIT_STRING", "")
P2PID = os.environ.get("YIMIRROR_P2PID", "")
LICENSE = os.environ.get("YIMIRROR_LICENSE", "")
PWD = os.environ.get("YIMIRROR_P2P_PASSWORD", "")


def main() -> None:
    if not (INIT and P2PID and LICENSE and PWD):
        print("servono le env YIMIRROR_* (vedi .env.example)")
        raise SystemExit(1)
    servers = tc.decode_init_string(INIT)
    s = tc.TnpSession(P2PID, LICENSE, INIT)
    s.p2p_password = PWD
    s.nonce_prefix = tc.gen_nonce(7)
    sock = s.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.3)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    t0 = time.time()

    def at(t: float) -> None:
        while time.time() - t0 < t:
            time.sleep(0.01)

    def recv_all(until: float):
        out = []
        while time.time() < until:          # until ASSOLUTO (t0 + offset)
            try:
                d, a = sock.recvfrom(65535)
            except socket.timeout:
                continue
            out.append((d, a))
        return out

    # 0.00: 0x18 a tutti i server
    for srv in servers:
        sock.sendto(tc.build_check_online(P2PID), (srv, tc.P2P_PORT))
    # 0.27: Hello + 0x20 + 0x30
    at(0.27)
    for srv in servers:
        sock.sendto(tc.header(0x00, 0), (srv, tc.P2P_PORT))
    sock.sendto(tc.build_p2preq(P2PID, LICENSE), ("255.255.255.255", 32108))
    for srv in servers:
        sock.sendto(tc.build_p2pserverreq(P2PID, LICENSE), (srv, tc.P2P_PORT))
    # attesa 0x40 (relay + LAN)
    relay = lan = None
    deadline = t0 + 0.45
    while time.time() < deadline and (relay is None or lan is None):
        for d, a in recv_all(deadline):
            if d[:2] != b"\xf1\x40" or len(d) < 12:
                continue
            body = d[4:]
            port = struct.unpack("<H", body[2:4])[0]
            ip = ".".join(str(b) for b in body[4:8][::-1])
            if ip.startswith("192.168.") or ip.startswith("10."):
                lan = (ip, port)
            else:
                relay = (ip, port)
    print(f"0x40: relay={relay} lan={lan}")
    s.target = relay
    s.lan_target = lan
    # 0.42: 0x41 ×3 a relay e LAN
    at(0.42)
    r41 = tc.build_connect_response(P2PID, LICENSE, b"")[4:]
    pkt = tc.header(0x41, len(r41)) + r41
    for _ in range(3):
        sock.sendto(pkt, relay)
        if lan:
            sock.sendto(pkt, lan)
    # 0.51: sulla 0x41-response del relay ritrasmetti
    at(0.51)
    got41 = False
    for d, a in recv_all(t0 + 1.2):
        if d[:2] == b"\xf1\x41" and a[0] == relay[0]:
            got41 = True
    for _ in range(2):
        sock.sendto(pkt, relay)
        if lan:
            sock.sendto(pkt, lan)
    # 0.58: 0xa0
    at(0.58)
    for srv in servers:
        sock.sendto(tc.build_notify_0xa0(P2PID), (srv, tc.P2P_PORT))
    # 0.59: 0x1300 (ctr 0)
    at(0.59)
    sock.sendto(tc.build_ioctrl(0, tc.IOCTRL_UPDATE_CHECK_PHONE, b"\x00" * 4,
                                s.nonce_prefix, PWD), relay)
    got42 = False
    for d, a in recv_all(t0 + 1.5):
        if d[:2] == b"\xf1\x42":
            got42 = True
            s.server = a
    print(f"0x42 ricevuta: {got42}")
    # 1.48: 0x03c0 (ctr 1)
    at(1.48)
    sock.sendto(tc.build_ioctrl(1, tc.IOCTRL_TRIGGER_SYNC, b"\x00\x00\x00\x01",
                                s.nonce_prefix, PWD), relay)
    # 9.92: secondo giro Hello/0x20/0x30
    at(9.92)
    for srv in servers:
        sock.sendto(tc.header(0x00, 0), (srv, tc.P2P_PORT))
    sock.sendto(tc.build_p2preq(P2PID, LICENSE), ("255.255.255.255", 32108))
    for srv in servers:
        sock.sendto(tc.build_p2pserverreq(P2PID, LICENSE), (srv, tc.P2P_PORT))
    # 9.97: SET_RESOLUTION (ctr 2)
    at(9.97)
    sock.sendto(tc.build_ioctrl(2, tc.IOCTRL_SET_RESOLUTION,
                                b"\x00\x00\x00\x02\x00\x00\x00\x01",
                                s.nonce_prefix, PWD), relay)
    # 10.4: DEVINFO (ctr 3)
    at(10.4)
    sock.sendto(tc.build_ioctrl(3, tc.IOCTRL_DEVINFO_REQ, b"\x00" * 4,
                                s.nonce_prefix, PWD), relay)
    print("replay fatto — ascolto 120 s per i frame (con storm 0x18)...")
    frames = []
    end = t0 + 130
    last18 = 0.0
    while time.time() < end:
        # storm check-online come l'app: 0x18 a tutti i server ogni ~1 s
        if time.time() - last18 > 1.0:
            for srv in servers:
                sock.sendto(tc.build_check_online(P2PID), (srv, tc.P2P_PORT))
            last18 = time.time()
        try:
            d, a = sock.recvfrom(65535)
        except socket.timeout:
            continue
        if d[:2] == b"\xf1\xd0":
            body = d[4:]
            if body[:2] in (b"\xd1\x02", b"\xd1\x03") and len(d) > 100:
                seq = struct.unpack(">H", body[2:4])[0]
                sock.sendto(tc.ack_video_0xd1(seq), a)
                frames.append(d)
                if len(frames) == 1:
                    print("PRIMO FRAME:", len(d), d[:40].hex())
        elif d[:2] == b"\xf1\xe0":
            sock.sendto(b"\xf1\xe1\x00\x00", a)
    print(f"frame ricevuti: {len(frames)}")


if __name__ == "__main__":
    main()
