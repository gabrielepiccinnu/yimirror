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

import base64
import hmac
import hashlib
import os
import random
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
    """prefix(7)+00 + sn(4 byte-reversed) + checkcode(5)+000 = 20 byte (wire §7k)."""
    prefix, sn, check = split_p2pid(p2pid)
    b = prefix.encode()[:7].ljust(7, b"\x00") + b"\x00"
    b += struct.pack("<I", sn)[::-1]
    b += check.encode()[:5].ljust(8, b"\x00")
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


def build_p2pserverreq(p2pid: str, license_key: str = "") -> bytes:
    """0x20 P2PServerReq — formato ESATTO dal pcap (§7u): p2pid(20) + blocco 16B.
    Nessuna firma."""
    body = p2pid_body(p2pid)
    body += b"\x00" + bytes.fromhex("02a3421002000a00") + b"\x00" * 7  # blocco statico catturato
    return header(MSG_P2PSERVERREQ, len(body)) + body


def build_p2preq(p2pid: str, license_key: str = "") -> bytes:
    """0x30 P2PReq — formato ESATTO dal pcap: p2pid(20) + flags a2050400. Nessuna firma."""
    body = p2pid_body(p2pid)
    body += bytes.fromhex("a2050400")
    return header(MSG_P2PREQ, len(body)) + body


def build_connect_response(p2pid: str, license_key: str, challenge: bytes,
                           flags: bytes = b"\xa2\x05\x04\x00", ts: int | None = None) -> bytes:
    """0x41: risposta alla 0x40 — formato ESATTO dal wire (§7w):
    body = p2pid(20) + flags(4) + ts(4) = 28 B; campo 16 B =
    HMAC-SHA1(License, body).digest()[:16] (§7p pattern; la challenge della
    0x40 NON entra nella firma)."""
    if ts is None:
        ts = int(time.time())
    body = p2pid_body(p2pid)
    body += flags
    body += struct.pack(">I", ts)
    sig = hmac.new(license_key.encode(), body, hashlib.sha1).digest()[:16]
    body += sig
    return header(MSG_CONNECT, len(body)) + body


def build_devlgn(p2pid: str, key: str, nonce: str,
                 local_addr: bytes = b"\x00" * 16,
                 api_version: int = 0x0001, dat_byte: int = 0,
                 nattype: int = 0) -> bytes:
    """DevLgn (0x14, 108 B) — login al server P2P (§7m/§7n), il passo che il
    client nativo non fa ancora: struct(40) + nonce(32) + signature(32).
    signature = primi 32 char hex di HMAC-SHA1(key, '<nonce>:<p2pid>')."""
    prefix, sn, check = split_p2pid(p2pid)
    body = prefix.encode()[:7].ljust(7, b"\x00")
    body += struct.pack("<I", sn)[::-1]          # sn byte-reversed
    body += check.encode()[:5].ljust(7, b"\x00")
    body += bytes([nattype & 0xFF])
    body += struct.pack(">H", api_version)
    body += bytes([dat_byte & 0xFF])
    body += local_addr[:16].ljust(16, b"\x00")
    body += nonce.encode()[:32].ljust(32, b"\x00")
    sig = hmac.new(key.encode(), f"{nonce}:{p2pid}".encode(),
                   hashlib.sha1).hexdigest()[:32].encode()
    body += sig
    return header(0x14, len(body)) + body


def build_notify_0xa0(p2pid: str) -> bytes:
    """0xa0 (44 B) → server P2P subito dopo la 0x42 (§7w, cold start del pcap):
    p2pid ASCII con trattini (20) + zeros(12) + a2050401 + 'P2P\\x00P'."""
    body = p2pid.encode()[:20].ljust(20, b"\x00")
    body += b"\x00" * 12
    body += b"\xa2\x05\x04\x01"
    body += b"P2P\x00P"
    return header(0xA0, len(body)) + body


# ---- Controlli IOCTRL (§7w, da TnpCamera.java/AVIOCTRLDEFs.java) ----
# TNPHead: version(1) + ioType(1)=3 + reserved(2) + dataSize(4 BE)
# TNPIOCtrlHead (40 B): commandType(2 BE) + commandNumber(2 BE) +
#   exHeaderSize(2) + dataSize(2) + authInfo(32)
# authInfo = noncePrefix(7)+nonce(8) + "," + base64(HMAC-SHA1(pwd32hex,
#            "user=xiaoyiuser&nonce="+nonce15))[:15]  (AntsUtil.java)

NONCE_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

IOCTRL_UPDATE_CHECK_PHONE = 0x1300    # UPDATE_CHECK_PHONE_REQ (4864)
IOCTRL_TRIGGER_SYNC = 0x03C0          # TRIGGER_SYNC_INFO_FROM_SERVER_REQ (960)
IOCTRL_SET_RESOLUTION = 0x1311        # SET_RESOLUTION (4881): data = res(4BE)+useCount(4BE)
IOCTRL_DEVINFO_REQ = 0x0330           # DEVINFO_REQ (816): data = 4 zero
IOCTRL_START_REALTIME = 0x2345        # TNP_START_REALTIME (9029) ← il comando video


def gen_nonce(n: int) -> str:
    return "".join(random.choice(NONCE_ALPHA) for _ in range(n))


def ioctrl_auth(nonce_prefix: str, password: str) -> bytes:
    """authInfo (32 B) di un controllo IOCTRL — AntsUtil.getPassword."""
    s = nonce_prefix + gen_nonce(8)
    msg = f"user=xiaoyiuser&nonce={s}".encode()
    der = base64.b64encode(
        hmac.new(password.encode(), msg, hashlib.sha1).digest()).decode()
    return (s + "," + der[:15]).encode().ljust(32, b"\x00")


def build_ioctrl(outer_ctr: int, req_id: int, data: bytes,
                 nonce_prefix: str, password: str) -> bytes:
    """0xd0 IOCTRL completo: d1 00 <ctr> + TNPHead + TNPIOCtrlHead + data."""
    inner = b"\x02\x03\x00\x00" + struct.pack(">I", 40 + len(data))
    ctrl = (struct.pack(">H", req_id) + struct.pack(">H", outer_ctr + 1) +
            b"\x00\x00" + struct.pack(">H", len(data)) +
            ioctrl_auth(nonce_prefix, password))
    body = b"\xd1\x00" + struct.pack(">H", outer_ctr) + inner + ctrl + data
    return header(0xD0, len(body)) + body


def build_stop_blocks(outer_ctr: int, nonce_prefix: str, password: str) -> bytes:
    """0xd0 con 3 blocchi IOCTRL in uno (§7w, il pacchetto ~196 B dell'app al tap):
    STOP (0x02ff, data 8 zero) + RECORD_PLAYCONTROL2 (0x31ae, data 24 B dal
    pcap) + SPEAKERSTOP (0x0351, data 8 zero) — reset dello stato di
    riproduzione prima dello start."""
    blocks = [
        (0x02FF, b"\x00" * 8),
        (0x31AE, b"\x00" * 8 + b"\x01" + b"\x00" * 15),
        (0x0351, b"\x00" * 8),
    ]
    body = b"\xd1\x00" + struct.pack(">H", outer_ctr)
    for i, (req_id, data) in enumerate(blocks):
        inner = b"\x02\x03\x00\x00" + struct.pack(">I", 40 + len(data))
        ctrl = (struct.pack(">H", req_id) +
                struct.pack(">H", outer_ctr + 2 + i) +
                b"\x00\x00" + struct.pack(">H", len(data)) +
                ioctrl_auth(nonce_prefix, password))
        body += inner + ctrl + data
    return header(0xD0, len(body)) + body


def ack_control_0xd1(ctr: int) -> bytes:
    """Ack di un controllo/risposta: `f1 d1 0006 d1 00 <ctr+1 2B> 0000`."""
    return b"\xf1\xd1\x00\x06\xd1\x00" + struct.pack(">H", ctr + 1) + b"\x00\x00"


def ack_video_0xd1(seq: int) -> bytes:
    """Ack di un frame video: `f1 d1 0006 d1 03 00 01 <seq 2B>` (echo del wrapper)."""
    return b"\xf1\xd1\x00\x06\xd1\x03\x00\x01" + struct.pack(">H", seq)


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

    def connect(self, timeout: float = 8.0) -> bool:
        """Sequenza ESATTA dal wire (§7u/§7v):
        1. Hello → server 32100
        2. ← HelloAck (0x01)
        3. P2PServerReq (0x20) → server
        4. ← ack 0x21
        5. P2PReq (0x30) → broadcast LAN :32108
        6. ← 0x40 con il TARGET (porta 2LE + flag 2 + ip 4LE)
        7. 0x41 → target (relay) con ts + 16B
        8. ← 0x42 dal relay → sessione attiva
        """
        for srv in self.servers:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                # 1. Hello
                s.sendto(header(MSG_HELLO, 0), (srv, P2P_PORT))
                # 2-3. attesa HelloAck poi P2PServerReq
                deadline = time.time() + timeout
                got_ack = False
                while time.time() < deadline and not got_ack:
                    try:
                        data, addr = s.recvfrom(65535)
                    except socket.timeout:
                        break
                    if data[:2] == b"\xf1\x01":
                        got_ack = True
                if not got_ack:
                    continue
                s.sendto(build_p2pserverreq(self.p2pid, self.license), (srv, P2P_PORT))
                # 4-5. attesa 0x21 poi P2PReq broadcast
                deadline = time.time() + timeout
                while time.time() < deadline:
                    try:
                        data, addr = s.recvfrom(65535)
                    except socket.timeout:
                        break
                    if data[:2] == b"\xf1\x21":
                        s.sendto(build_p2preq(self.p2pid, self.license),
                                 ("255.255.255.255", 32108))
                        break
                # 6. attesa 0x40 con il target
                deadline = time.time() + timeout
                while time.time() < deadline:
                    try:
                        data, addr = s.recvfrom(65535)
                    except socket.timeout:
                        break
                    if data[:2] != b"\xf1\x40" or len(data) < 12:
                        continue
                    body = data[4:]
                    port = struct.unpack("<H", body[2:4])[0]   # flag(2) + porta(2 LE)
                    target_ip = ".".join(str(b) for b in body[4:8][::-1])
                    target = (target_ip, port)
                    if target_ip.startswith("192.168.") or target_ip.startswith("10."):
                        self.lan_target = target   # il target LAN (camera diretta)
                    else:
                        self.target = target       # il relay
                    # 7. 0x41 verso il target — FIRMATA (§7w: HMAC(License, body)[:16])
                    r41 = build_connect_response(self.p2pid, self.license,
                                                 body, ts=int(time.time()))[4:]
                    s.sendto(header(MSG_CONNECT, len(r41)) + r41, target)
                    # 8. attesa 0x42 dal relay — il relay prima risponde con una
                    # sua 0x41 (d2040200): come l'app, ritrasmettiamo la 0x41
                    # finché non arriva la 0x42 (§7w)
                    deadline = time.time() + timeout
                    while time.time() < deadline:
                        try:
                            data2, addr2 = s.recvfrom(65535)
                        except socket.timeout:
                            break
                        if data2[:2] == b"\xf1\x41":
                            s.sendto(header(MSG_CONNECT, len(r41)) + r41, target)
                            continue
                        if data2[:2] == b"\xf1\x42":
                            self.h42 = data2          # corpo 0x42: candidato seed seq
                            self.sock = s
                            self.server = addr2
                            self.connected = True
                            return True
            except OSError:
                continue
            s.close()
        return False

    def start_video(self, password: str | None = None) -> bool:
        """Cold start ESATTO (§7w, TnpCamera.java + pcap):
        0xa0 ai server P2P → e0 → controlli IOCTRL autenticati
        (0x1300 UPDATE_CHECK_PHONE → 0x03c0 TRIGGER_SYNC → 0x03c0 ancora →
        0x2345 TNP_START_REALTIME con data [1, resolution, 1, 0]) — ciascuno
        con attesa della risposta del relay e ack. Ritorna True se il relay
        risponde ai controlli."""
        if not self.sock or not self.server:
            return False
        if password is None:
            # viewPassword dal db dell'app (device_info) — ruota a ogni refresh
            # della device list; aggiornabile via YIMIRROR_P2P_PASSWORD o .env
            from env_loader import load_env
            load_env()
            password = os.environ.get("YIMIRROR_P2P_PASSWORD", "")
        if not password:
            raise RuntimeError("YIMIRROR_P2P_PASSWORD non impostata "
                               "(viewPassword della camera, vedi .env.example)")
        self.p2p_password = password
        # check-online 0x18 a tutti i server (l'app lo manda di continuo)
        for srv in self.servers:
            try:
                self.sock.sendto(build_check_online(self.p2pid), (srv, P2P_PORT))
            except OSError:
                pass
        for srv in self.servers:
            try:
                self.sock.sendto(build_notify_0xa0(self.p2pid), (srv, P2P_PORT))
            except OSError:
                pass
        self.sock.sendto(b"\xf1\xe0\x00\x04\xa2\x05\x04\x00", self.server)
        self.nonce_prefix = gen_nonce(7)
        self.sock.settimeout(0.5)
        self.ctrl = 0
        # heartbeat ×2 e attesa della risposta e0/e1 del relay (§7w: l'app
        # aspetta 99.703→99.876 prima di mandare i controlli)
        for _ in range(2):
            self.sock.sendto(b"\xf1\xe0\x00\x04\xa2\x05\x04\x00", self.server)
        deadline = time.time() + 2.5
        while time.time() < deadline:
            try:
                pkt, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            if pkt[:2] == b"\xf1\xe0":
                self.sock.sendto(b"\xf1\xe1\x00\x00", self.server)
        # controlli — ordine ESATTO del wake dal pcap del lancio (§7w):
        # 0x1300 → 0x03c0 → 8 s → 0x1311 SET_RESOLUTION (IL TRIGGER del wake:
        # i frame arrivano ~0,1 s dopo) → 0x0330 DEVINFO — CIASCUNO su una
        # sessione FRESCA (0x41→0x42 prima di ogni controllo)
        steps = [
            (IOCTRL_UPDATE_CHECK_PHONE, b"\x00" * 4, 0.3),
            (IOCTRL_TRIGGER_SYNC, b"\x00\x00\x00\x01", 8.0),
            (IOCTRL_SET_RESOLUTION, b"\x00\x00\x00\x02\x00\x00\x00\x01", 0.5),
            (IOCTRL_DEVINFO_REQ, b"\x00" * 4, 0.0),
        ]
        ok = False
        for req_id, data, pause in steps:
            resp = self.send_control_fresh(req_id, data)
            if resp is not None:
                body = resp[4:]
                rtype = struct.unpack(">H", body[12:14])[0] if len(body) >= 14 else 0
                print(f"  <- risposta a 0x{req_id:04x}: type=0x{rtype:04x}")
                if rtype != 0xFFFF:
                    ok = True
            if pause:
                time.sleep(pause)
        return ok

    def send_control_fresh(self, req_id: int, data: bytes,
                           wait: float = 3.0) -> bytes | None:
        """Rinnova la sessione (0x41→0x42) e manda UN controllo con cmdNum 1
        (§7w: la camera risponde solo ai controlli su sessioni fresche).
        Ritorna la risposta 0xd0 del relay o None."""
        if not self.refresh_session():
            return None
        self.ctrl = 1
        self.sock.sendto(
            build_ioctrl(0, req_id, data, self.nonce_prefix, self.p2p_password),
            self.server)
        deadline = time.time() + wait
        resp = None
        while time.time() < deadline:
            try:
                pkt, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            if pkt[:2] != b"\xf1\xd0" or len(pkt) < 16:
                continue
            body = pkt[4:]
            if body[:2] == b"\xd1\x00":
                resp = pkt
                self.sock.sendto(ack_control_0xd1(0), self.server)
                break
        return resp

    def refresh_session(self) -> bool:
        """Refresh della sessione sul relay (§7w: l'app lo fa ogni ~10 s):
        nuova 0x41 (ts fresco + firma) sullo stesso socket fino alla 0x42,
        senza rifare Hello/P2PServerReq/P2PReq. Reset del contatore controlli."""
        if not self.sock or not self.target:
            return False
        r41 = build_connect_response(self.p2pid, self.license,
                                     b"", ts=int(time.time()))[4:]
        self.sock.settimeout(0.5)
        deadline = time.time() + 5.0
        while time.time() < deadline:
            self.sock.sendto(header(MSG_CONNECT, len(r41)) + r41, self.target)
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            if data[:2] == b"\xf1\x42":
                self.h42 = data
                self.server = addr
                self.connected = True
                self.ctrl = 0
                return True
        return False

    def close(self) -> None:
        self.connected = False
        self.server = None
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def run_video(self, seconds: float, ack_interval: float = 1.0,
                  verbose: bool = False) -> list[bytes]:
        """Loop di ricezione post-start_video: risponde alle risposte di
        controllo (ack d1 00 <ctr+1>), ack-a i frame dati con la seq del
        wrapper (d1 03), risponde agli heartbeat e0 con e1, e mantiene un ack
        ritmico d103 con contatore proprio (come l'app nel pcap)."""
        if not self.sock:
            return []
        frames: list[bytes] = []
        start = time.time()
        last_ack = 0.0
        last_sync = 0.0
        last_start = 0.0
        last_refresh = 0.0
        self.video_seq = 0
        self.sock.settimeout(0.2)
        while time.time() - start < seconds:
            now = time.time()
            if now - last_ack >= ack_interval:
                self.sock.sendto(ack_video_0xd1(self.video_seq), self.server)
                self.video_seq = (self.video_seq + 1) & 0xFFFF
                self.sock.sendto(b"\xf1\xe0\x00\x04\xa2\x05\x04\x00", self.server)
                last_ack = now
            if (not frames and now - last_start >= 11.0
                    and hasattr(self, "p2p_password")):
                # finché non arrivano frame: ogni ~11 s (ritmo dell'app) una
                # sessione fresca + alternanza TRIGGER_SYNC / SET_RESOLUTION
                # (il wake, §7w — il ffff del relay è solo 'in coda': la
                # camera processa i controlli lentamente)
                self._retry_n = getattr(self, "_retry_n", 0)
                self._retry_n += 1
                if self._retry_n % 2:
                    req, dta = IOCTRL_TRIGGER_SYNC, b"\x00\x00\x00\x01"
                else:
                    req, dta = IOCTRL_SET_RESOLUTION, \
                        b"\x00\x00\x00\x02\x00\x00\x00\x01"
                self.send_control_fresh(req, dta, wait=2.0)
                # knock LAN (§7w: per le camere con wakeup=1 la 0x41 diretta
                # alla camera è parte del wake — SYUPE la richiede)
                lan = getattr(self, "lan_target", None)
                if lan:
                    r41 = build_connect_response(self.p2pid, self.license,
                                                 b"", ts=int(time.time()))[4:]
                    self.sock.sendto(header(MSG_CONNECT, len(r41)) + r41, lan)
                self.sock.sendto(b"\xf1\xf0\x00\x00", self.server)
                last_start = now
            try:
                data, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            if len(data) < 4 or data[0] != 0xF1:
                continue
            if data[1] == MSG_ALIVE:
                self.sock.sendto(b"\xf1\xe1\x00\x00", self.server)
                continue
            if data[1] == 0xF0:
                self.sock.sendto(b"\xf1\xf0\x00\x00", self.server)
                continue
            if data[1] == 0xD0:
                body = data[4:]
                if verbose:
                    print(f"  <- 0xd0 len={len(data)} {data[:28].hex()}")
                if body[:2] == b"\xd1\x00":
                    ctr = struct.unpack(">H", body[2:4])[0]
                    self.sock.sendto(ack_control_0xd1(ctr), self.server)
                elif body[:2] in (b"\xd1\x02", b"\xd1\x03"):
                    seq = struct.unpack(">H", body[2:4])[0]
                    self.sock.sendto(ack_video_0xd1(seq), self.server)
                    frames.append(data)
            elif verbose and data[1] != MSG_ALIVE_ACK:
                print(f"  <- tipo 0x{data[1]:02x} len={len(data)} {data[:28].hex()}")
        return frames


if __name__ == "__main__":
    # test rapido: usa native_test.py (gestisce .env e credenziali)
    print("usa: python3 src/native_test.py")
