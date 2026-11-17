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

# Ritmo dei retry/wake/check in run_video — moderato per NON saturare il relay
# (martellarlo → rate-limit/mute, §7x-bis). Tunabile via env senza ricompilare.
# Il cold-start della camera da sleep profondo richiede ~35 s di polling continuo
# (§7x-quater: anche l'app ripete il controllo ~1/s per 35 s finché la camera
# invia un 0x40 di re-invito, poi risponde e parte lo stream). Il resend del
# controllo su sessione stabilita NON causa rate-limit (quello era handshake/wake
# spam) → ritmo serrato. Wake 0x1a e full-reconnect restano radi.
_RETRY_INTERVAL = float(os.environ.get("YIMIRROR_RETRY_INTERVAL", "2"))
_WAKE_INTERVAL = float(os.environ.get("YIMIRROR_WAKE_INTERVAL", "60"))
_CHECK_INTERVAL = float(os.environ.get("YIMIRROR_CHECK_INTERVAL", "5"))
# Ri-trigger di START_REALTIME (0x2345) SOLO dopo questo gap senza frame: mai
# mentre lo stream scorre, o la camera riparte in continuazione e non si sostiene.
_RETRIGGER_AFTER = float(os.environ.get("YIMIRROR_RETRIGGER_AFTER", "4"))
# TRIGGER_SYNC 0x03c0 periodico durante lo stream (l'app lo manda ~ogni 10s, §7w).
_SYNC_INTERVAL = float(os.environ.get("YIMIRROR_SYNC_INTERVAL", "10"))

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
    """0x20 P2PServerReq — forma corta da 36 B (§7x-sexies, confronto col pcap
    coldstart app). Layout: UID(20) + 00 + 02 + token(2) + 0f 02 00 0a + 00*8.
    Il `token` è un nonce per-round scelto dal CLIENT: l'app lo ruota a ogni
    raffica (es. SYUPE 0x6536→0xd259→0x0a6a) e lo manda identico a tutti i
    server della raffica. NON è un segreto, NON deriva dall'UID e NON viene
    validato come tale dai server → un valore qualsiasi va bene. Nessuna firma.
    (Correzione: il byte a offset 0x18 è 0x0f in tutti i device del pcap, non
    0x10 come nel vecchio §7u.)"""
    body = p2pid_body(p2pid)                                  # 20 B UID
    token = os.urandom(2)                                     # nonce per-round
    body += b"\x00\x02" + token + bytes.fromhex("0f02000a") + b"\x00" * 8
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


def build_wakeup_packet(p2pid: str, license_key: str) -> bytes:
    """MSG_DEV_WAKEUP_REQ (0x1a, 48 B) — il comando di wake della camera
    (§7w-quater, da PPPP_Proto_Send_WakeUp/Write_HeaderV2 via Ghidra):
    f2 1a len16(20) 00 | prefix(8) | sn(4BE) |
    HMAC-SHA1(License, primi 20 B) | prefix(7) | sn(4BE) | checkcode(7)."""
    prefix, sn, check = split_p2pid(p2pid)
    pkt = bytearray(48)
    pkt[0] = 0xF2                       # magic header V2
    pkt[1] = 0x1A                       # MSG_DEV_WAKEUP_REQ
    pkt[2:4] = struct.pack(">H", 20)    # len16 = 20
    pkt[4] = 0
    pkt[8:16] = prefix.encode()[:7].ljust(8, b"\x00")
    pkt[0x10:0x14] = struct.pack(">I", sn)
    sig = hmac.new(license_key.encode(), pkt[:0x14], hashlib.sha1).digest()
    pkt[0x14:0x28] = sig                # HMAC sui primi 20 B
    pkt[0x1C:0x23] = prefix.encode()[:7].ljust(7, b"\x00")
    pkt[0x24:0x28] = struct.pack(">I", sn)
    pkt[0x28:0x2F] = check.encode()[:5].ljust(7, b"\x00")
    return bytes(pkt)


def wake_device(p2pid: str, license_key: str, servers: list[str],
                timeout: float = 6.0) -> bool:
    """Invia MSG_DEV_WAKEUP_REQ ai server P2P da un socket dedicato con porta
    bindata e attende l'ack 0x1a (PPPP_TryWakeUp). Ritorna True se ack-ato."""
    pkt = build_wakeup_packet(p2pid, license_key)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("0.0.0.0", 0))
    except OSError:
        pass
    s.settimeout(0.5)
    start = time.time()
    while time.time() - start <= timeout:
        for srv in servers:
            try:
                s.sendto(pkt, (srv, P2P_PORT))
            except OSError:
                continue
        deadline = time.time() + 1.0
        while time.time() < deadline:
            try:
                data, _ = s.recvfrom(2048)
            except socket.timeout:
                continue
            if len(data) >= 2 and data[1] == 0x1A:
                # WakeUp_ReqAck: il payload (col result) parte a offset 28 per
                # i pacchetti f2 (Read_Header), a 4 per gli f1 (Recv_ALL §7w-q)
                if data[0] == 0xF2 and len(data) > 28:
                    result = data[28]
                elif data[0] == 0xF1 and len(data) > 4:
                    result = data[4]
                else:
                    result = 0
                print(f"wake ack 0x1a ricevuto (result={result})")
                return result == 0
    return False


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
IOCTRL_DEVINFO_RESP = 0x0331          # DEVINFO_RESP (817): SMsgAVIoctrlDeviceInfoResp
# Interruttore "Camera on/off" dell'app (privacy mode reale) —
# CameraCommandHelper.doOpenOrCloseVideo: data = int (0 = accesa, 1 = spenta),
# big-endian per TNP (AntsCamera.isByteOrderBig, type 3); la risposta è una
# SMsgAVIoctrlDeviceInfoResp con close_camera al byte 48.
IOCTRL_CLOSE_CAMERA = 0x1304          # IOTYPE_USER_IPCAM_CLOSE_CAMERA_REQ (4868)
IOCTRL_CLOSE_CAMERA_RESP = 0x130C     # IOTYPE_USER_IPCAM_CLOSE_CAMERA_RESP (4876)

# ---- Famiglia RTMP = motore della registrazione cloud in background ----
# La camera ha un client RTMP integrato: SET_RTMP_ADDR (URL UTF-8) → START_RTMP
# (int BE a 4 byte) → la camera PUSHA il video verso l'ingest indicato. È la
# stessa macchina del cloud recording 24/7: l'app 7.0.1 NON li chiama mai in
# Java (i comandi li invia il server YI sulla sessione della camera) e i clip
# cloud sono segmenti .ts con timeline continua (tipici di un ingest RTMP).
# Per Frigate: si punta l'indirizzo al NOSTRO mediamtx (porta 1935) → flusso
# nativo continuo senza il canale media P2P (niente sustain problem).
# Fonti: AVIOCTRLDEFs.java (944–963), CameraCommandHelper.startRtmpStream/
# startAndSetAddrRtmpStream/stopRtmpStream, smali SMsgAVIoctlStartRtmpReq/
# SMsgAVIoctlQueryRtmpStateResp/SMsgAVIoctlCloudStorageResp.
IOCTRL_START_RTMP = 0x03B0        # IOTYPE_USER_IPCAM_START_RTMP_REQ (944)
IOCTRL_STOP_RTMP = 0x03B2         # IOTYPE_USER_IPCAM_STOP_RTMP_REQ (946)
IOCTRL_QUERY_RTMP_STAT = 0x03B4   # IOTYPE_USER_IPCAM_QUERY_RTMP_STAT_REQ (948)
IOCTRL_SET_RTMP_ADDR = 0x03B6     # IOTYPE_USER_IPCAM_SET_RTMP_ADDR_REQ (950)
IOCTRL_STOP_CLOUD_STORAGE = 0x03C2  # IOTYPE_USER_IPCAM_STOP_CLOUD_STORAGE_REQ (962)
RTMP_RESP_TYPES = frozenset({
    IOCTRL_START_RTMP + 1, IOCTRL_STOP_RTMP + 1, IOCTRL_QUERY_RTMP_STAT + 1,
    IOCTRL_SET_RTMP_ADDR + 1, IOCTRL_STOP_CLOUD_STORAGE + 1,
})

# offset dei dati nel corpo di una risposta di controllo:
# d1 00 <ctr2> (4) + TNPHead (8) + TNPIOCtrlHead (40)
CTRL_DATA_OFFSET = 4 + 8 + 40


def ctrl_response_type(resp_pkt: bytes | None) -> int | None:
    """commandType della risposta di controllo (0xffff = 'in coda' del relay)."""
    if not resp_pkt or len(resp_pkt) < 18:
        return None
    return struct.unpack(">H", resp_pkt[4 + 12:4 + 14])[0]


def parse_devinfo(resp_pkt: bytes | None) -> dict | None:
    """Campi principali di SMsgAVIoctrlDeviceInfoResp (AVIOCTRLDEFs.parse) da
    una risposta 0x0331 o 0x130C. None se la risposta non porta i dati."""
    rtype = ctrl_response_type(resp_pkt)
    if rtype not in (IOCTRL_DEVINFO_RESP, IOCTRL_CLOSE_CAMERA_RESP):
        return None
    d = resp_pkt[4 + CTRL_DATA_OFFSET:]
    if len(d) < 55:
        return None
    return {
        "type": rtype,
        "interface_version": d[0],
        "tfstat": d[2],
        "hardware_version": d[8],
        "version": struct.unpack(">I", d[32:36])[0],
        "sd_total": struct.unpack(">I", d[40:44])[0],
        "sd_free": struct.unpack(">I", d[44:48])[0],
        "close_camera": d[48],
        "close_light": d[49],
        "record_mode": d[52],
    }


def parse_rtmp_state(resp_pkt: bytes | None) -> dict | None:
    """SMsgAVIoctrlQueryRtmpStateResp — risposta a SET_RTMP_ADDR/START_RTMP/
    STOP_RTMP/QUERY_RTMP_STAT: leftTime = int BE @0 (tempo residuo del push,
    secondi), url = stringa @4 (max 512 B). Il campo `rtype` è SEMPRE presente
    quando esiste una risposta (anche 0xFFFF o tipo inatteso, per diagnosi);
    left_time/url compaiono solo se il tipo è della famiglia RTMP."""
    rtype = ctrl_response_type(resp_pkt)
    if rtype is None:
        return None
    out: dict = {"rtype": rtype,
                 "raw_head": resp_pkt[4:40].hex()}   # d1 00 ctr + TNPHead + type…
    if rtype in RTMP_RESP_TYPES:
        d = resp_pkt[4 + CTRL_DATA_OFFSET:]
        if len(d) >= 4:
            out["left_time"] = struct.unpack(">I", d[:4])[0]
            out["url"] = d[4:516].split(b"\x00")[0].decode(errors="replace").strip()
    return out


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


def build_frag_ack(wseqs: list[int]) -> bytes:
    """Ack BATCH dei frammenti d1 02 (ARQ, verificato sul pcap dell'app):
    `f1 d1 <4+2+2n> d1 02 00 <n 2B> <wseq 2B ×n>`. L'app li manda ogni ~0.4-1s
    e a fine raffica: è il flow-control che la camera aspetta prima di inviare
    il prossimo I-frame."""
    body = b"\xd1\x02\x00" + struct.pack(">H", len(wseqs))
    for w in wseqs:
        body += struct.pack(">H", w & 0xFFFF)
    return header(0xD1, len(body)) + body


def build_frame_request(channel: int, wseq: int) -> bytes:
    """Richiesta del prossimo frame (ARQ): `f1 d2 0004 d2 <ch> <wseq 2B>`.
    ch=0x02 per i frammenti d1 02, ch=0x03 per i frame video d1 03.
    L'app la manda su gap/duplicati/cambio di flusso (pcap 15/11)."""
    return (b"\xf1\xd2\x00\x04\xd2" + bytes([channel & 0xFF])
            + struct.pack(">H", wseq & 0xFFFF))


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
        self.ctrl = 0
        self.nonce_prefix = ""
        self.p2p_password = ""
        self.desired_on = True
        self.devinfo: dict = {}

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
                    # la 0x40 può portare DUE endpoint (relay + camera LAN,
                    # §7x-octies: "2 target"). L'app risponde 0x41 a ENTRAMBI:
                    # è l'anello che committa la sessione media lato camera.
                    targets: list[tuple[str, int]] = []
                    for off in (2, 8):
                        if len(body) < off + 8:
                            break
                        port = struct.unpack("<H", body[off:off + 2])[0]
                        t_ip = ".".join(str(b) for b in body[off + 2:off + 6][::-1])
                        if t_ip and t_ip != "0.0.0.0":
                            targets.append((t_ip, port))
                    for t_ip, port in targets:
                        if t_ip.startswith("192.168.") or t_ip.startswith("10."):
                            self.lan_target = (t_ip, port)   # camera diretta (LAN)
                        else:
                            self.target = (t_ip, port)       # il relay
                    # 7. 0x41 verso TUTTI i target — FIRMATA (§7w: HMAC(License,
                    # body)[:16]); dual-target come l'app
                    r41 = build_connect_response(self.p2pid, self.license,
                                                 body, ts=int(time.time()))[4:]
                    pkt41 = header(MSG_CONNECT, len(r41)) + r41
                    for t_ip, port in targets:
                        try:
                            s.sendto(pkt41, (t_ip, port))
                        except OSError:
                            pass
                    # 8. attesa 0x42 dal relay — il relay prima risponde con una
                    # sua 0x41 (d2040200): come l'app, ritrasmettiamo la 0x41 a
                    # TUTTI i target finché non arriva la 0x42 (§7w)
                    deadline = time.time() + timeout
                    while time.time() < deadline:
                        try:
                            data2, addr2 = s.recvfrom(65535)
                        except socket.timeout:
                            break
                        if data2[:2] == b"\xf1\x41":
                            for t_ip, port in targets:
                                try:
                                    s.sendto(pkt41, (t_ip, port))
                                except OSError:
                                    pass
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

    def _session_preamble(self, password: str | None = None) -> dict | None:
        """Preamble comune di una sessione video: wake 0x1a → check-online
        0x18 → notify 0xa0 → heartbeat e0 → controlli auth (0x1300 + DEVINFO,
        con power-on se in privacy). Ritorna il devinfo o None. NON avvia
        l'encoder: a quello pensano start_video (0x2345) o start_rtmp_push."""
        if not self.sock or not self.server:
            return None
        if password is None:
            from env_loader import load_env
            load_env()
            password = os.environ.get("YIMIRROR_P2P_PASSWORD", "")
        if not password:
            raise RuntimeError("YIMIRROR_P2P_PASSWORD non impostata "
                               "(viewPassword della camera, vedi .env.example)")
        self.p2p_password = password
        # WAKE: MSG_DEV_WAKEUP_REQ 0x1a dai server (§7w-quater — il passo che
        # sveglia la camera, mai catturato nei pcap: avviene pre-connect)
        print("wake device...")
        wake_device(self.p2pid, self.license, self.servers)
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
        # controlli DIRETTI sulla sessione connessa (§7x: niente refresh
        # 0x41→0x42 per controllo). La viewPassword DEVE essere fresca o
        # l'authInfo dei controlli è rifiutato (ffff).
        self.send_control(IOCTRL_UPDATE_CHECK_PHONE, b"\x00" * 4)
        # DEVINFO per close_camera (privacy mode) — se spenta la riaccendo
        info = parse_devinfo(self.send_control(IOCTRL_DEVINFO_REQ, b"\x00" * 4))
        if info is not None:
            self.devinfo = info
            print(f"[devinfo] close_camera={info['close_camera']} "
                  f"tf={info['tfstat']} hw={info['hardware_version']}")
            if info["close_camera"] == 1 and self.desired_on:
                print("[power] camera in privacy mode → riaccendo")
                self.set_camera_power(True)
        return info

    def start_video(self, password: str | None = None) -> bool:
        """Cold start ESATTO (§7w, TnpCamera.java + pcap):
        preamble (_session_preamble) → **0x2345 START_REALTIME con data
        01020100**: È QUESTO il trigger dei frame (il video parte subito
        dopo), NON 0x1311 né 0x03c0 (quelli rispondono ma non avviano
        l'encoding). La viewPassword DEVE essere fresca o l'authInfo dei
        controlli è rifiutato (ffff). Ritorna True se il relay risponde."""
        info = self._session_preamble(password)
        if info is None and not getattr(self, "p2p_password", ""):
            return False
        # START_REALTIME = il trigger del video
        resp = self.send_control(IOCTRL_START_REALTIME,
                                 bytes.fromhex("01020100"), wait=2.0)
        rt = ctrl_response_type(resp)
        ok = rt is None or rt != 0xFFFF   # il 2345 spesso non risponde: il video parte
        print(f"[video] START_REALTIME inviato (resp={rt})")
        return ok

    def start_rtmp_push(self, url: str, param: int = 0,
                        password: str | None = None) -> tuple[dict | None, dict | None]:
        """Avvio del push RTMP (registrazione cloud in background): preamble
        (_session_preamble) → SET_RTMP_ADDR 0x03B6 (URL UTF-8) → START_RTMP
        0x03B0 (int BE). NIENTE 0x2345: il video NON passa dal canale P2P,
        la camera lo spinge direttamente verso l'ingest RTMP indicato (come
        fa col cloud YI). Ritorna (devinfo, stato rtmp parsato)."""
        info = self._session_preamble(password)
        self.rtmp_set_addr(url)
        st = self.rtmp_start(param)
        return info, st

    def rehandshake(self, timeout: float = 8.0) -> bool:
        """Handshake COMPLETO sullo stesso socket (§7w-ter: l'app rifà
        Hello→0x20→0x30→0x40→0x41→0x42 ogni ~10 s — il wake può scattare
        sull'N-esimo ciclo completo)."""
        if not self.sock:
            return False
        s = self.sock
        s.settimeout(1.5)
        for srv in self.servers:
            try:
                s.sendto(header(MSG_HELLO, 0), (srv, P2P_PORT))
                s.sendto(build_p2pserverreq(self.p2pid, self.license),
                         (srv, P2P_PORT))
            except OSError:
                continue
        try:
            s.sendto(build_p2preq(self.p2pid, self.license),
                     ("255.255.255.255", 32108))
        except OSError:
            pass
        deadline = time.time() + timeout
        target = getattr(self, "target", None)
        r41 = build_connect_response(self.p2pid, self.license,
                                     b"", ts=int(time.time()))[4:]
        pkt41 = header(MSG_CONNECT, len(r41)) + r41
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            if data[:2] == b"\xf1\x40" and len(data) >= 12:
                body = data[4:]
                port = struct.unpack("<H", body[2:4])[0]
                ip = ".".join(str(b) for b in body[4:8][::-1])
                if not (ip.startswith("192.168.") or ip.startswith("10.")):
                    target = (ip, port)
                    self.target = target
            if target and data[:2] == b"\xf1\x41":
                s.sendto(pkt41, target)
            if data[:2] == b"\xf1\x42" and target:
                self.h42 = data
                self.server = addr
                self.connected = True
                self.ctrl = 0
                return True
            if data[:2] == b"\xf1\x40" and target is None:
                pass
        return False

    def send_control(self, req_id: int, data: bytes,
                     wait: float = 3.0, resp_id: int | None = None,
                     any_resp: bool = False) -> bytes | None:
        """Invia UN controllo IOCTRL sulla sessione già connessa (NIENTE
        refresh 0x41→0x42) e attende la risposta 0xd0/d1 00 della camera.

        Verificato live (§7x): dopo la 0x42 la camera risponde ai controlli
        direttamente. Il tipo di risposta è di norma commandType+1
        (0x1300→0x1301, 0x0330→0x0331, 0x1311→0x1312), MA alcuni comandi
        rispondono con un tipo dedicato: 0x1304 CLOSE_CAMERA → **0x130C**
        (SMsgAVIoctrlDeviceInfoResp), non 0x1305. Per questi passare `resp_id`
        esplicito, altrimenti la risposta reale viene scartata e il controllo
        risulta 'senza risposta' (bug §7x-decies). Contatore self.ctrl crescente."""
        if not self.sock or not self.server:
            return None
        ctr = getattr(self, "ctrl", 0)
        self.ctrl = ctr + 1
        self.sock.sendto(
            build_ioctrl(ctr, req_id, data, self.nonce_prefix, self.p2p_password),
            self.server)
        self.sock.settimeout(0.3)
        deadline = time.time() + wait
        resp = None
        while time.time() < deadline:
            try:
                pkt, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            if pkt[:2] == b"\xf1\xe0":
                self.sock.sendto(b"\xf1\xe1\x00\x00", self.server)
                continue
            if pkt[:2] != b"\xf1\xd0" or len(pkt) < 18:
                continue
            body = pkt[4:]
            if body[:2] != b"\xd1\x00":
                continue
            # ack del controllo (echo del contatore interno del wrapper)
            self.sock.sendto(ack_control_0xd1(struct.unpack(">H", body[2:4])[0]),
                             self.server)
            rtype = struct.unpack(">H", body[12:14])[0]
            if (any_resp or rtype == (req_id + 1)
                    or (resp_id is not None and rtype == resp_id)
                    or rtype == 0xFFFF):
                resp = pkt
                print(f"[ctrl] 0x{req_id:04x} -> type=0x{rtype:04x}")
                if rtype != 0xFFFF:
                    break
        if resp is None:
            print(f"[ctrl] 0x{req_id:04x}: nessuna risposta entro {wait}s")
        return resp

    def send_control_fresh(self, req_id: int, data: bytes,
                           wait: float = 3.0) -> bytes | None:
        """Rinnova la sessione (0x41→0x42) e manda UN controllo con cmdNum 1
        (§7w: la camera risponde solo ai controlli su sessioni fresche).
        Ritorna la risposta 0xd0 del relay o None."""
        if not self.refresh_session():
            print(f"[ctrl] refresh sessione FALLITO per 0x{req_id:04x}")
            return None
        self.ctrl = 1
        self.sock.sendto(
            build_ioctrl(0, req_id, data, self.nonce_prefix, self.p2p_password),
            self.server)
        print(f"[ctrl] inviato 0x{req_id:04x}")
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
                rtype = struct.unpack(">H", body[12:14])[0] if len(body) >= 14 else 0
                print(f"[ctrl] risposta a 0x{req_id:04x}: type=0x{rtype:04x}")
                self.sock.sendto(ack_control_0xd1(0), self.server)
                break
        if resp is None:
            print(f"[ctrl] nessuna risposta a 0x{req_id:04x} entro {wait}s")
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

    def query_devinfo(self) -> dict | None:
        """DEVINFO_REQ su sessione fresca → stato della camera (close_camera…)."""
        if not getattr(self, "p2p_password", ""):
            return None
        info = parse_devinfo(self.send_control(IOCTRL_DEVINFO_REQ, b"\x00" * 4))
        if info is not None:
            self.devinfo = info
            print(f"[devinfo] close_camera={info['close_camera']} "
                  f"tf={info['tfstat']} hw={info['hardware_version']}")
        return info

    def rtmp_set_addr(self, url: str, wait: float = 3.0) -> dict | None:
        """SET_RTMP_ADDR 0x03B6: imposta l'URL RTMP verso cui la camera farà
        push (payload = URL UTF-8, come
        CameraCommandHelper.startAndSetAddrRtmpStream)."""
        resp = self.send_control(IOCTRL_SET_RTMP_ADDR, url.encode(), wait=wait,
                                 any_resp=True)
        st = parse_rtmp_state(resp)
        print(f"[rtmp] set_addr -> {st}")
        return st

    def rtmp_start(self, param: int = 0, wait: float = 3.0) -> dict | None:
        """START_RTMP 0x03B0: avvia il push RTMP. payload = int BE a 4 byte
        (SMsgAVIoctlStartRtmpReq.parseContent). Significato del parametro da
        determinare dal vivo (0 = default; candidati: durata/qualità/canale)."""
        resp = self.send_control(IOCTRL_START_RTMP, struct.pack(">I", param),
                                 wait=wait, any_resp=True)
        st = parse_rtmp_state(resp)
        print(f"[rtmp] start({param}) -> {st}")
        return st

    def rtmp_stop(self, wait: float = 3.0) -> dict | None:
        """STOP_RTMP 0x03B2: ferma il push RTMP (payload 8 zero, come l'app)."""
        resp = self.send_control(IOCTRL_STOP_RTMP, b"\x00" * 8, wait=wait,
                                 any_resp=True)
        st = parse_rtmp_state(resp)
        print(f"[rtmp] stop -> {st}")
        return st

    def rtmp_query(self, wait: float = 3.0) -> dict | None:
        """QUERY_RTMP_STAT 0x03B4: stato corrente del push (payload 8 zero).
        Risposta: left_time (s) + url attivo."""
        resp = self.send_control(IOCTRL_QUERY_RTMP_STAT, b"\x00" * 8, wait=wait,
                                 any_resp=True)
        return parse_rtmp_state(resp)

    def hold_rtmp(self, seconds: float, stat_interval: float = 20.0):
        """GENERATORE a chiamata unica: tiene la sessione TNP calda mentre la
        camera pusha RTMP verso l'ingest (keepalive e0 + ack d100 + risposta
        ai re-invito 0x40/0x41 — NIENTE 0x2345/0x03c0/0x18: il video NON passa
        da qui e lo spam comandi non serve). Ogni `stat_interval` s interroga
        lo stato del push e lo emette (`yield dict | None`); altrimenti
        `yield None` sui tick di housekeeping."""
        if not self.sock:
            return
        start = time.time()
        last_ack = 0.0
        last_stat = 0.0
        ack_interval = float(os.environ.get("YIMIRROR_RTMP_KEEPALIVE", "5"))
        self.sock.settimeout(0.5)
        while time.time() - start < seconds:
            now = time.time()
            if now - last_ack >= ack_interval:
                self.sock.sendto(b"\xf1\xe0\x00\x04\xa2\x05\x04\x00", self.server)
                last_ack = now
            if now - last_stat >= stat_interval and hasattr(self, "p2p_password"):
                yield self.rtmp_query(wait=2.0)
                last_stat = now
                continue
            try:
                data, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                yield None
                continue
            if len(data) < 4 or data[0] != 0xF1:
                yield None
                continue
            if data[1] == MSG_ALIVE:
                self.sock.sendto(b"\xf1\xe1\x00\x00", self.server)
                yield None
                continue
            if data[1] in (MSG_CHALLENGE, MSG_CONNECT):  # 0x40 re-invito / 0x41 relay
                tgt = getattr(self, "target", None) or self.server
                r41 = build_connect_response(self.p2pid, self.license,
                                             b"", ts=int(time.time()))[4:]
                self.sock.sendto(header(MSG_CONNECT, len(r41)) + r41, tgt)
                yield None
                continue
            if data[1] == 0xD0:
                body = data[4:]
                if body[:2] == b"\xd1\x00":
                    ctr = struct.unpack(">H", body[2:4])[0]
                    self.sock.sendto(ack_control_0xd1(ctr), self.server)
                    if len(body) >= 14:
                        # risposta di controllo NON sollecitata (es. risposta
                        # tardiva a un comando precedente): emettila come
                        # evento per la diagnosi invece di scartarla
                        yield {"kind": "ctrl",
                               "rtype": struct.unpack(">H", body[12:14])[0],
                               "raw_head": data[4:40].hex()}
                        continue
            yield None

    def set_camera_power(self, on: bool, retries: int = 3) -> bool:
        """Privacy mode reale (CLOSE_CAMERA 0x1304): on=True accende la camera,
        on=False la spegne. Ritorna True se la risposta conferma lo stato
        (close_camera == 0 se on, 1 se off). Ritenta sulle risposte 'ffff'."""
        if not getattr(self, "p2p_password", ""):
            return False
        want = 0 if on else 1
        for attempt in range(1, retries + 1):
            resp = self.send_control(IOCTRL_CLOSE_CAMERA,
                                     struct.pack(">I", want),
                                     resp_id=IOCTRL_CLOSE_CAMERA_RESP)
            info = parse_devinfo(resp)
            if info is not None:
                self.devinfo = info
                print(f"[power] {'ON' if on else 'OFF'} → close_camera="
                      f"{info['close_camera']} (tentativo {attempt})")
                if info["close_camera"] == want:
                    return True
            else:
                rtype = ctrl_response_type(resp)
                print(f"[power] {'ON' if on else 'OFF'}: risposta "
                      f"{'assente' if rtype is None else hex(rtype)} "
                      f"(tentativo {attempt})")
            time.sleep(2.0)
        # ultima verifica con DEVINFO (la risposta 0x130C può perdersi)
        info = self.query_devinfo()
        return info is not None and info["close_camera"] == want

    def close(self) -> None:
        self.connected = False
        self.server = None
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _hs_flood(self) -> None:
        """Un colpo del FLOOD di handshake che l'app manda durante il cold-start
        (§7x-quater: ~5-7/s di Hello 0x00 + P2PServerReq 0x20 + P2PReq 0x30 +
        0x41 al target, finché la camera fredda si sveglia e stabilisce il
        percorso P2P reale). È QUESTO, non il retry dei controlli, a svegliare la
        camera. Non bloccante: le risposte le gestisce il loop di run_video."""
        if not self.sock:
            return
        for srv in self.servers:
            try:
                self.sock.sendto(header(MSG_HELLO, 0), (srv, P2P_PORT))
                self.sock.sendto(build_p2pserverreq(self.p2pid, self.license),
                                 (srv, P2P_PORT))
            except OSError:
                pass
        try:
            self.sock.sendto(build_p2preq(self.p2pid, self.license),
                             ("255.255.255.255", 32108))
        except OSError:
            pass
        tgt = getattr(self, "target", None)
        if tgt:
            r41 = build_connect_response(self.p2pid, self.license,
                                         b"", ts=int(time.time()))[4:]
            try:
                self.sock.sendto(header(MSG_CONNECT, len(r41)) + r41, tgt)
            except OSError:
                pass

    def run_video(self, seconds: float, ack_interval: float = 1.0,
                  verbose: bool = False):
        """GENERATORE a chiamata unica (una per sessione): emette ogni pacchetto
        video `0xD0` (d1 02/d1 03) APPENA arriva (`yield data`), e `yield None` sui
        tick di housekeeping (timeout socket / e0 / f0 / 0x40 / d1 00). Mantiene:
        ack ritmico d103 (contatore proprio, come l'app), ack per-pacchetto con
        echo del wseq, heartbeat e0, risposta a e0/f0 e ai re-invito 0x40/0x41,
        check-online 0x18 ogni _CHECK_INTERVAL, TRIGGER_SYNC 0x03c0 ogni
        _SYNC_INTERVAL (come l'app), e ri-trigger 0x2345 SOLO dopo un gap frame.

        CRUCIALE: va chiamata UNA volta sola per sessione (non in un loop a 1s):
        i timer locali sono per-chiamata, quindi una chiamata lunga garantisce le
        cadenze corrette (0x18 ogni 5s, non ~1/s → niente rate-limit/mute del
        relay §7x-bis, che è ciò che fermava lo stream dopo pochi secondi)."""
        if not self.sock:
            return
        start = time.time()
        last_ack = 0.0
        last_sync = 0.0
        last_start = 0.0
        last_check = 0.0
        if not hasattr(self, "video_seq"):
            self.video_seq = 0            # ack-counter PERSISTENTE tra le chiamate
        if not hasattr(self, "_last_vframe"):
            self._last_vframe = 0.0        # ultimo frame video ricevuto (persistente)
        # ---- ARQ del canale media (replica ESATTA dell'app, pcap 15/11) ----
        # L'app: ack per-frame d1 03 (echo wseq), ack BATCH d1 02 dei frammenti
        # dell'I-frame, richieste d2 02/d2 03 del prossimo frame atteso su
        # gap/duplicati/cambi flusso, e NIENTE 0x03c0/0x18/ack-ritmici durante
        # lo stream. La camera usa questi ack come flow-control: senza i batch
        # d1 02 smette di inviare (il "burst-then-stop" del proxy).
        frag_acks: list[int] = []          # wseq frammenti d1 02 da ackare
        last_frag_flush = 0.0
        next_vseq: int | None = None       # prossimo wseq atteso (flusso d1 03)
        last_frag: int | None = None       # ultimo wseq frammento d1 02
        last_pull = 0.0
        self.sock.settimeout(0.2)
        while time.time() - start < seconds:
            now = time.time()
            if now - last_ack >= ack_interval:
                # SOLO heartbeat e0: l'app NON manda ack ritmici d103 coi
                # contatori propri (la camera li interpreta come ack di frame
                # inesistenti) né 0x18/0x03c0 mentre lo stream scorre.
                self.sock.sendto(b"\xf1\xe0\x00\x04\xa2\x05\x04\x00", self.server)
                last_ack = now
            # flush dei frammenti in sospeso (batch d1 02, come l'app)
            if frag_acks and (len(frag_acks) >= 16
                              or now - last_frag_flush >= 0.4):
                self.sock.sendto(build_frag_ack(frag_acks), self.server)
                frag_acks = []
                last_frag_flush = now
            # check-online 0x18 SOLO a flusso fermo da >10s (l'app non lo
            # manda durante lo stream — lo spam contribuiva al mute del relay)
            if (now - last_check >= _CHECK_INTERVAL and self.servers
                    and now - self._last_vframe > 10.0):
                for srv in self.servers:
                    try:
                        self.sock.sendto(build_check_online(self.p2pid),
                                         (srv, P2P_PORT))
                    except OSError:
                        pass
                last_check = now
            # TRIGGER_SYNC 0x03c0 OGNI ~10s ANCHE DURANTE lo stream — è ciò che
            # fa l'app nel pcap app-boot (3.9s, 13.9s, 14.0s mentre i frame
            # scorrono): è il keep-alive dell'encoder della camera.
            if (now - last_sync >= _SYNC_INTERVAL
                    and hasattr(self, "p2p_password")):
                self.send_control(IOCTRL_TRIGGER_SYNC, b"\x00" * 4, wait=0.0)
                last_sync = now
            # pull del prossimo frame atteso quando il flusso si ferma (l'app
            # manda d2 03 <next> in queste finestre — es. 3.56, 15.120).
            # Cap a 30s di stall: oltre, pensa il re-handshake (niente spam
            # d2 che può contribuire al mute del relay).
            if (next_vseq is not None and now - last_pull >= 0.5
                    and 0.3 <= now - self._last_vframe <= 30.0):
                self.sock.sendto(build_frame_request(0x03, next_vseq),
                                 self.server)
                last_pull = now
            # Ri-triggero il video con START_REALTIME SOLO se non arrivano frame
            # da >_RETRIGGER s (§7x-novies). FONDAMENTALE: NON ri-mandarlo mentre
            # lo stream scorre — ri-triggerare di continuo fa ripartire l'encoder
            # della camera e lo stream non si sostiene mai. Il timer è persistente
            # sulla sessione (_last_vframe). NIENTE flood/0xf0/SET_RESOLUTION:
            # resettano la sessione sana.
            if (now - self._last_vframe > _RETRIGGER_AFTER and now - last_start >= 3.0
                    and hasattr(self, "p2p_password")):
                self.send_control(IOCTRL_START_REALTIME,
                                  bytes.fromhex("01020100"), wait=0.0)
                last_start = now
            try:
                data, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                yield None                    # tick: il chiamante fa housekeeping
                continue
            if len(data) < 4 or data[0] != 0xF1:
                yield None
                continue
            if data[1] == MSG_ALIVE:
                self.sock.sendto(b"\xf1\xe1\x00\x00", self.server)
                yield None
                continue
            if data[1] == 0xF0:
                self.sock.sendto(b"\xf1\xf0\x00\x00", self.server)
                yield None
                continue
            if data[1] in (MSG_CHALLENGE, MSG_CONNECT):  # 0x40 re-invito / 0x41 relay
                # §7x-quater: quando la camera esce dallo sleep RE-INVITA con 0x40;
                # va rifirmato e risposto con 0x41 verso il target, o la sessione
                # resta "vecchia" e lo stream non parte mai. Lo stesso vale se il
                # relay rimanda una sua 0x41. DUAL-TARGET come l'app (§7x-octies):
                # 0x41 anche verso la camera LAN se raggiungibile — committa la
                # sessione media lato camera.
                r41 = build_connect_response(self.p2pid, self.license,
                                             b"", ts=int(time.time()))[4:]
                pkt41 = header(MSG_CONNECT, len(r41)) + r41
                for tgt in (getattr(self, "target", None), getattr(self, "lan_target", None)):
                    if tgt:
                        try:
                            self.sock.sendto(pkt41, tgt)
                        except OSError:
                            pass
                yield None
                continue
            if data[1] == 0x42:  # 0x42: sessione (ri)confermata
                yield None
                continue
            if data[1] == 0xD0:
                body = data[4:]
                if verbose:
                    print(f"  <- 0xd0 len={len(data)} {data[:28].hex()}")
                if body[:2] == b"\xd1\x00":
                    ctr = struct.unpack(">H", body[2:4])[0]
                    self.sock.sendto(ack_control_0xd1(ctr), self.server)
                    yield None
                elif body[:2] == b"\xd1\x02":
                    # frammento I-frame: si accumula e si acka in BATCH (d1 02)
                    seq = struct.unpack(">H", body[2:4])[0]
                    frag_acks.append(seq)
                    last_frag = seq
                    self._last_vframe = now
                    yield data
                elif body[:2] == b"\xd1\x03":
                    seq = struct.unpack(">H", body[2:4])[0]
                    if frag_acks:
                        # fine raffica frammenti → flush batch + richiesta del
                        # prossimo frammento (d2 02), come l'app al cambio flusso
                        self.sock.sendto(build_frag_ack(frag_acks), self.server)
                        frag_acks = []
                        last_frag_flush = now
                        if last_frag is not None:
                            self.sock.sendto(
                                build_frame_request(0x02, (last_frag + 1) & 0xFFFF),
                                self.server)
                    # gap/duplicato sul flusso video → richiesta del prossimo
                    # atteso (d2 03), come l'app (duplicato 5635 → d2 03 5637)
                    if next_vseq is not None and seq != next_vseq:
                        self.sock.sendto(build_frame_request(0x03, next_vseq),
                                         self.server)
                    next_vseq = (seq + 1) & 0xFFFF
                    self.sock.sendto(ack_video_0xd1(seq), self.server)
                    self._last_vframe = now       # stream vivo → non ri-triggerare
                    yield data                    # emetti il frame SUBITO
                else:
                    yield None
            else:
                if verbose and data[1] != MSG_ALIVE_ACK:
                    print(f"  <- tipo 0x{data[1]:02x} len={len(data)} {data[:28].hex()}")
                yield None

    def run_video_collect(self, seconds: float, ack_interval: float = 1.0,
                          verbose: bool = False) -> list[bytes]:
        """Wrapper a lista del generatore run_video (per test/one-shot)."""
        return [p for p in self.run_video(seconds, ack_interval, verbose)
                if p is not None]


if __name__ == "__main__":
    # test rapido: usa native_test.py (gestisce .env e credenziali)
    print("usa: python3 src/native_test.py")
