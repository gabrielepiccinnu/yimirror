"""tnp_client.py — client TNP/PPPP nativo definitivo (proxy autonomo).

Protocollo recuperato via Ghidra + catture live (findings §7k-§7p):
- InitString → server (PPPP_DecodeString, chiave 54 byte, XOR feedback)
- Header pacchetti: `f1 <type> <len16BE>`
- Check-online: `f1 18 0014` + prefix(8)+sn(4rev)+checkcode(8) → ACK `f1 19 0008`
  + lastLgTime(4BE) + flag(4LE, 1=online) — NESSUNA firma
- Firma messaggi: `hex(HMAC-SHA1(license, body))` — chiave = License (6 char) dal
  tnp/device_info; data = corpo del pacchetto PRIMA del campo firma
- Sequenza connect: Hello (`f1 00 0000`) → P2PServerReq (0x20, firmato) →
  P2PReq (0x30, firmato) → challenge 0x40 → risposta 0x41 → sessione
  (d0/d1/d2 video/ack, e0/e1 heartbeat)

Da verificare live (una costante): il campo 16 B della 0x41 — ipotesi corrente:
primi 16 byte del digest HMAC-SHA1 grezzo sul corpo senza coda.
"""

from __future__ import annotations

import hmac
import hashlib
import os
import socket
import struct
import time

KEY_54 = [0xc1, 0x6b, 0x8b, 0x95, 0x97, 0x6d, 0xa3, 0x47, 0xe3, 0x71, 0xe9, 0x67,
          0x7f, 0x11, 0x53, 0x4f, 0x61, 0x65, 0xad, 0xb3, 0x89, 0x2b, 0x2f, 0x35,
          0xe5, 0xa7, 0x0d, 0xef, 0xf1, 0x05, 0x07, 0x83, 0xfb, 0x9d, 0x3b, 0xc5,
          0xc7, 0x13, 0x17, 0x1d, 0x1f, 0x25, 0x29, 0xd3, 0xdf, 0x49, 0x59, 0x43,
          0x3d, 0xb5, 0xbf, 0x02, 0x03, 0x0b]

P2P_PORT = 32100
MSG_DEV_ONLINE_ACK = 0x19
MSG_HELLO = 0x00
MSG_P2PSERVERREQ = 0x20
MSG_P2PREQ = 0x30
MSG_CHALLENGE = 0x40
MSG_CONNECT = 0x41
MSG_ALIVE = 0xE0
MSG_ALIVE_ACK = 0xE1


def decode_init_string(s: str) -> list[str]:
    """PPPP_DecodeString: InitString → server IP (stringa separata da virgole)."""
    out = bytearray()
    mask = 0x39
    for i in range(len(s) // 2):
        c1, c2 = ord(s[2 * i]), ord(s[2 * i + 1])
        b = ((c1 * 16 + c2 + 0xAF) & 0xFF) ^ mask ^ KEY_54[i % len(KEY_54)]
        out.append(b)
        mask ^= b
    text = bytes(out).decode("ascii", errors="replace")
    return [x for x in text.split(",") if x]


def split_p2pid(p2pid: str) -> tuple[str, int, str]:
    """'TNPUSAQ-245460-SYUPE' → ('TNPUSAQ', 245460, 'SYUPE')."""
    parts = p2pid.split("-")
    return parts[0][:8], int(parts[1]), parts[2][:8]


def p2pid_body(p2pid: str) -> bytes:
    """prefix(7)+00 + sn(4 byte-reversed) + checkcode(7) — il campo p2pid nel wire."""
    prefix, sn, check = split_p2pid(p2pid)
    b = prefix.encode()[:7].ljust(7, b"\x00") + b"\x00"
    b += struct.pack("<I", sn)[::-1]
    b += check.encode()[:7].ljust(7, b"\x00")
    return b


def header(typ: int, ln: int) -> bytes:
    return b"\xf1" + bytes([typ]) + struct.pack(">H", ln)


def sign(license_key: str, data: bytes) -> str:
    """hex(HMAC-SHA1(license, data)) — la firma dei messaggi (§7p)."""
    return hmac.new(license_key.encode(), data, hashlib.sha1).hexdigest()


def build_check_online(p2pid: str) -> bytes:
    body = p2pid_body(p2pid)
    return header(0x18, 0x14) + body


def check_device_online(p2pid: str, init_string: str, timeout: float = 4.0) -> tuple[bool, int]:
    servers = decode_init_string(init_string)
    packet = build_check_online(p2pid)
    for srv in servers:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(packet, (srv, P2P_PORT))
            try:
                data, _ = s.recvfrom(2048)
                if len(data) >= 12 and data[0] == 0xF1 and data[1] == MSG_DEV_ONLINE_ACK:
                    return data[8] == 1, struct.unpack(">I", data[4:8])[0]
            except socket.timeout:
                pass
            finally:
                s.close()
        except OSError:
            continue
    return False, 0


def build_p2pserverreq(p2pid: str, license_key: str, ts: int | None = None) -> bytes:
    """0x20 firmato: body = p2pid_body + 00 + seq(4) + 0200 0a00 + 00*8 + flags(4) + ts(4)."""
    if ts is None:
        ts = int(time.time())
    body = p2pid_body(p2pid)                      # 19 byte
    body += b"\x00"                               # 20
    body += struct.pack(">I", 2)                  # seq — 24
    body += b"\x02\x00\x0a\x00"                   # 28
    body += b"\x00" * 8                           # 36
    body += b"\xa2\x05\x04\x00"                   # flags — 40
    body += struct.pack(">I", ts)                 # 44
    body += bytes.fromhex(sign(license_key, body))[:32]  # firma (32 char hex)
    return header(MSG_P2PSERVERREQ, len(body)) + body


def build_p2preq(p2pid: str, license_key: str, ts: int | None = None) -> bytes:
    """0x30 firmato: body = p2pid_body + 00*2 + flags(4) + ts(4)."""
    if ts is None:
        ts = int(time.time())
    body = p2pid_body(p2pid) + b"\x00\x00"
    body += b"\xa2\x05\x04\x00"
    body += struct.pack(">I", ts)
    body += bytes.fromhex(sign(license_key, body))[:16]  # ipotesi: 16 byte di firma
    return header(MSG_P2PREQ, len(body)) + body


def build_connect_response(p2pid: str, license_key: str, challenge: bytes,
                           flags: bytes = b"\xa2\x05\x04\x00", ts: int | None = None) -> bytes:
    """0x41: risposta alla challenge 0x40 (il campo 16 B da validare live)."""
    if ts is None:
        ts = int(time.time())
    body = p2pid_body(p2pid)
    body += b"\x00" * 2
    body += flags
    body += struct.pack(">I", ts)
    # ipotesi (§7o/§7p): i 16 byte = primi 16 del digest HMAC grezzo su body+challenge
    raw = hmac.new(license_key.encode(), body + challenge, hashlib.sha1).digest()
    body += raw[:16]
    return header(MSG_CONNECT, len(body)) + body


class TnpSession:
    """Una sessione TNP verso una camera (sequenza di connect, §7o)."""

    def __init__(self, p2pid: str, license_key: str, init_string: str):
        self.p2pid = p2pid
        self.license = license_key
        self.servers = decode_init_string(init_string)
        self.sock: socket.socket | None = None
        self.server: tuple[str, int] | None = None
        self.connected = False
        self.frames: list[bytes] = []

    def connect(self, timeout: float = 6.0) -> bool:
        for srv in self.servers:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            try:
                # 1. Hello
                s.sendto(header(MSG_HELLO, 0), (srv, P2P_PORT))
                # 2. P2PServerReq (firmato)
                s.sendto(build_p2pserverreq(self.p2pid, self.license), (srv, P2P_PORT))
                # 3. P2PReq (firmato)
                s.sendto(build_p2preq(self.p2pid, self.license), (srv, P2P_PORT))
                # 4. attesa challenge 0x40 → risposta 0x41
                deadline = time.time() + timeout
                while time.time() < deadline:
                    try:
                        data, addr = s.recvfrom(65535)
                    except socket.timeout:
                        break
                    if data[:1] == b"\xf1" and data[1] == MSG_CHALLENGE and len(data) >= 44:
                        s.sendto(build_connect_response(self.p2pid, self.license,
                                                        data[28:44]), addr)
                        self.sock = s
                        self.server = addr
                        self.connected = True
                        return True
            except OSError:
                continue
            s.close()
        return False

    def recv_frames(self, timeout: float = 1.0) -> list[bytes]:
        """Raccoglie i frame video (0xd0) — struttura §7d (header 24 B + NAL)."""
        if not self.sock:
            return []
        out = []
        self.sock.settimeout(timeout)
        while True:
            try:
                data, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                break
            if data[:2] == b"\xf1\xd0":
                out.append(data)
        return out

    def keepalive(self) -> None:
        if self.sock and self.server:
            self.sock.sendto(header(MSG_ALIVE, 4) + b"\x00" * 4, self.server)


if __name__ == "__main__":
    init = "MAEEJGLJICFGKJHPOOFCPOEJHNCHFCGAHMENLBIBIPBPDFBNPMIGAANGPPCFBFKEOOKGDCPFNJDPALDGBI"
    print("server:", decode_init_string(init))
    online, ts = check_device_online("TNPUSAQ-245460-SYUPE", init)
    print("online:", online, "| last login:", ts)
    if online:
        s = TnpSession("TNPUSAQ-245460-SYUPE", "RBRDZR", init)
        ok = s.connect(timeout=5)
        print("session connect:", ok, "| server:", s.server)
        if ok:
            for _ in range(10):
                fr = s.recv_frames()
                if fr:
                    print("frame ricevuti:", len(fr))
                s.keepalive()
                time.sleep(1)
