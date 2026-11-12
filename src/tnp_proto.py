"""TNP/PPPP wire protocol — structs, frame reassembly, media decryption.

Mapped from the captured session (findings §7/§7b, docs/api/p2p-protocol.md):
- UDP packets: `f1 <type:1B> <len:2B BE> <payload>` — types: 0x41 check-online,
  0xd0 data, 0xd1 ack, 0xd2 control, 0xe0/e1 heartbeat.
- Video packets (type 0xd0): wrapper (16 B) + TNPFrameHead (24 B) + H.264 payload.
- Media encryption: AES-128-ECB, key = first 16 ASCII bytes of (pwd + "0"),
  applied ONLY to I-frame header region [4..36) of the frame buffer. P-frames and
  the rest of each frame are plaintext.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

try:
    from Crypto.Cipher import AES
except ImportError:  # pycryptodome assente: decifratura disabilitata, recording raw
    AES = None

F1_MAGIC = 0xF1
F1_CHECK_ONLINE = 0x41
F1_DATA = 0xD0
F1_ACK = 0xD1
F1_CTRL = 0xD2
F1_HB = 0xE0
F1_HB_ACK = 0xE1

FRAME_HEAD_LEN = 24
# offset del TNPFrameHead relativo a pkt.payload (f1d0+len già strippati da F1Packet):
# UDP[0:4]=f1d0+len, UDP[4:16]=sub-header d1xx+meta, UDP[16:40]=frame head (pcap §7b)
VIDEO_WRAPPER_LEN = 12
CODEC_H264 = 0x4E


@dataclass
class FrameHead:
    codec_id: int = 0
    flags: int = 0
    live_flag: int = 0
    online_num: int = 0
    use_count: int = 0
    seq: int = 0
    width: int = 0
    height: int = 0
    timestamp: int = 0
    is_day: int = 0
    ref: int = 0
    in_loss: int = 0
    out_loss: int = 0
    ts_ms: int = 0

    @property
    def is_iframe(self) -> bool:
        return bool(self.flags & 1)

    @staticmethod
    def parse(buf: bytes, off: int = 0, big: bool = True) -> "FrameHead":
        e = "big" if big else "little"
        return FrameHead(
            codec_id=int.from_bytes(buf[off:off + 2], e),
            flags=buf[off + 2],
            live_flag=buf[off + 3],
            online_num=buf[off + 4],
            use_count=buf[off + 5],
            seq=int.from_bytes(buf[off + 6:off + 8], e),
            width=int.from_bytes(buf[off + 8:off + 10], e),
            height=int.from_bytes(buf[off + 10:off + 12], e),
            timestamp=int.from_bytes(buf[off + 12:off + 16], e),
            is_day=buf[off + 16],
            ref=buf[off + 17],
            in_loss=buf[off + 18],
            out_loss=buf[off + 19],
            ts_ms=int.from_bytes(buf[off + 20:off + 24], e),
        )


@dataclass
class F1Packet:
    ftype: int = 0
    payload: bytes = b""

    @staticmethod
    def parse(buf: bytes) -> "F1Packet | None":
        if len(buf) < 4 or buf[0] != F1_MAGIC:
            return None
        ln = int.from_bytes(buf[2:4], "big")
        return F1Packet(buf[1], buf[4:4 + ln])


@dataclass
class VideoFrame:
    head: FrameHead
    data: bytes          # payload H.264 (NAL stream), decifrato se possibile
    raw: bytes = b""     # frame buffer originale
    is_decrypted: bool = False

    def nals(self) -> bytes:
        return self.data


class MediaCrypto:
    """AES-128-ECB media decrypt: key = primi 16 byte ASCII di (password + '0').

    decryptIframe: blocchi [4..20) e [20..36) del frame buffer; P-frame intatti.
    """

    def __init__(self, password: str | None):
        self.cipher = None
        if password and AES is not None:
            key = (password + "0").encode("ascii")[:16]
            if len(key) == 16:
                self.cipher = AES.new(key, AES.MODE_ECB)

    def decrypt_iframe(self, frm: bytearray, off: int = 0) -> bool:
        if self.cipher is None or len(frm) < off + 36:
            return False
        try:
            frm[off + 4:off + 20] = self.cipher.decrypt(bytes(frm[off + 4:off + 20]))
            frm[off + 20:off + 36] = self.cipher.decrypt(bytes(frm[off + 20:off + 36]))
            return True
        except Exception:
            return False


class FrameReassembler:
    """Estrae i frame video dai pacchetti f1d0 UDP (header a offset 16, verificato)."""

    def __init__(self, password: str | None = None, big_endian: bool = True,
                 wrapper_len: int = VIDEO_WRAPPER_LEN):
        self.crypto = MediaCrypto(password)
        self.big = big_endian
        self.wrapper = wrapper_len
        self.frames: list[VideoFrame] = []
        self.stats = {"video": 0, "iframe": 0, "decrypted": 0, "audio": 0, "other": 0}

    def feed(self, udp_payload: bytes) -> VideoFrame | None:
        pkt = F1Packet.parse(udp_payload)
        if pkt is None:
            return None
        if pkt.ftype != F1_DATA:
            self.stats["other"] += 1
            return None
        off = self.wrapper
        if len(pkt.payload) < off + FRAME_HEAD_LEN:
            self.stats["other"] += 1
            return None
        head = FrameHead.parse(pkt.payload, off, self.big)
        if head.codec_id != CODEC_H264:
            self.stats["audio" if head.codec_id in (0x00, 0x4F, 0x50) else "other"] += 1
            return None
        buf = bytearray(pkt.payload[off:])
        dec = False
        if head.is_iframe:
            self.stats["iframe"] += 1
            dec = self.crypto.decrypt_iframe(buf)
            if dec:
                self.stats["decrypted"] += 1
        frame = VideoFrame(head=head, data=bytes(buf[FRAME_HEAD_LEN:]), raw=bytes(buf),
                           is_decrypted=dec)
        self.frames.append(frame)
        self.stats["video"] += 1
        return frame

    def h264(self) -> bytes:
        """Concatenazione NAL dei frame ricevuti (per dump/pipe a ffmpeg)."""
        out = []
        for f in self.frames:
            out.append(f.data)
        return b"".join(out)
