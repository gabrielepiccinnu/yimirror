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

# Codec audio (AVFrame/AVIOCTRLDEFs, com/tutk/IOTC): l'app decodifica l'audio della
# camera con DecodeAAC (AntsAudioPlayer.AUDIO_CODEID_AAC=138=0x8A). Il codec_id sta
# nei primi 2 byte del TNPFrameHead (in chiaro anche con p2p_encrypt).
CODEC_AUDIO_AAC = 0x8A
CODEC_AUDIO_ADPCM = 0x8B
CODEC_AUDIO_PCM = 0x8C      # G711/PCM (AntsAudioPlayer.G711_CODEC=140)
CODEC_AUDIO_SPEEX = 0x8D
CODEC_AUDIO_MP3 = 0x8E
CODEC_AUDIO_G726 = 0x8F
AUDIO_CODECS = {
    CODEC_AUDIO_AAC: "aac",
    CODEC_AUDIO_ADPCM: "adpcm",
    CODEC_AUDIO_PCM: "pcm",
    CODEC_AUDIO_SPEEX: "speex",
    CODEC_AUDIO_MP3: "mp3",
    CODEC_AUDIO_G726: "g726",
}


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


@dataclass
class AudioFrame:
    """Frame audio dal canale TNP 1 (d1 01, attivo dopo IOCTRL 0x0300 AUDIOSTART).

    L'app (ThreadRecvAudio→AVFrame ctor) parse il TNPFrameHead IN CHIARO dal
    pacchetto e decifra SOLO il payload (frmData = bytes[24:]) con AES-ECB a
    blocchi da 16 su TUTTO il frame (AntsUtil.decryptAudioFrame). Il byte
    `flags` dell'head codifica il sample rate: `flags >>> 2` = indice
    (AVFrame.getSamplerate: 0/3=16000, 1=11025, 2=12000, 4=22050, 5=24000,
    6=32000, 7=44100, 8=48000)."""
    head: FrameHead
    codec_id: int
    data: bytes          # payload audio (AAC grezzo senza ADTS di norma)
    is_decrypted: bool = False


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

    def decrypt_audio(self, buf: bytes) -> tuple[bytes, bool]:
        """AES-128-ECB a blocchi da 16 su TUTTO il payload audio (come
        AntsUtil.decryptAudioFrame: `length = frmData.length / 16` — il resto
        eventuale non multiplo di 16 resta com'è). Ritorna (dati, decifrato)."""
        if self.cipher is None:
            return buf, False
        try:
            n = len(buf) // 16
            if n == 0:
                return buf, False
            out = bytearray(buf)
            for i in range(n):
                blk = out[i * 16:(i + 1) * 16]
                out[i * 16:(i + 1) * 16] = self.cipher.decrypt(bytes(blk))
            return bytes(out), True
        except Exception:
            return buf, False


class FrameReassembler:
    """Estrae i frame video dai pacchetti f1d0 UDP (header a offset 16, verificato)."""

    def __init__(self, password: str | None = None, big_endian: bool = True,
                 wrapper_len: int = VIDEO_WRAPPER_LEN):
        self.crypto = MediaCrypto(password)
        self.big = big_endian
        self.wrapper = wrapper_len
        self.frames: list[VideoFrame] = []
        self.stats = {"video": 0, "iframe": 0, "decrypted": 0, "audio": 0,
                      "other": 0, "partial_drop": 0}
        self._parts: dict[int, dict] = {}   # frame frammentato in corso, per canale

    def feed(self, udp_payload: bytes) -> VideoFrame | AudioFrame | None:
        """Riassembla i frame dai pacchetti 0xd0 (§7x-undecies).

        Un frame inizia col pacchetto che porta il TNPFrameHead (codec 0x4E
        video o 0x8A AAC audio a offset `wrapper`); la sua lunghezza TOTALE è
        nei 2 byte [10:12] del sub-header. I frame piccoli (P, canale d1 03)
        stanno in un pacchetto; gli I-frame (canale d1 02) e l'audio (canale
        d1 01, attivo dopo IOCTRL 0x0300) sono FRAMMENTATI su più pacchetti:
        i frammenti di continuazione NON hanno head e seguono con wseq
        consecutivo. Lo stato di frammentazione è per-canale, così i canali
        video e audio interleaved non si buttano via a vicenda.
        Ritorna il frame (VideoFrame o AudioFrame) solo quando è COMPLETO."""
        pkt = F1Packet.parse(udp_payload)
        if pkt is None or pkt.ftype != F1_DATA:
            self.stats["other"] += 1
            return None
        p = pkt.payload
        off = self.wrapper
        if len(p) < 4:
            return None
        ch = p[1]                    # 0x00 ctrl, 0x01 audio, 0x02 I-video, 0x03 P-video
        wseq = int.from_bytes(p[2:4], "big")
        e = "big" if self.big else "little"
        codec = int.from_bytes(p[off:off + 2], e) if len(p) >= off + 2 else -1
        has_head = (len(p) >= off + FRAME_HEAD_LEN
                    and (codec == CODEC_H264 or codec in AUDIO_CODECS))
        if has_head:
            if ch in self._parts:                # scarta un frammentato incompleto
                self.stats["partial_drop"] += 1
                del self._parts[ch]
            head = FrameHead.parse(p, off, self.big)
            total = int.from_bytes(p[10:12], e)     # lunghezza totale del frame payload
            first = p[off:]                          # head(24) + primo chunk
            if len(first) >= total:                  # completo in un pacchetto (P-frame)
                return self._emit(head, bytes(first[:total]))
            self._parts[ch] = {"total": total, "buf": bytearray(first), "ch": ch,
                               "next": (wseq + 1) & 0xFFFF, "head": head}
            return None
        # frammento di continuazione (niente head)
        part = self._parts.get(ch)
        if part is not None and wseq == part["next"]:
            part["buf"] += p[4:]                     # dati dopo `d1 0X <wseq>`
            part["next"] = (wseq + 1) & 0xFFFF
            if len(part["buf"]) >= part["total"]:
                del self._parts[ch]
                return self._emit(part["head"], bytes(part["buf"][:part["total"]]))
            return None
        self.stats["other"] += 1
        return None

    def _emit(self, head: "FrameHead", payload: bytes) -> VideoFrame | AudioFrame | None:
        """payload = TNPFrameHead(24 B) + media. Video: decifra l'I-frame;
        audio: decifra TUTTO il payload a blocchi ECB e registra."""
        if head.codec_id == CODEC_H264:
            nal = bytearray(payload[FRAME_HEAD_LEN:])
            dec = False
            if head.is_iframe:
                self.stats["iframe"] += 1
                # §7w: regione cifrata = [4..36) del NAL (dopo decrypt: SPS+PPS+inizio IDR)
                dec = self.crypto.decrypt_iframe(nal, off=0)
                if dec:
                    self.stats["decrypted"] += 1
            frame = VideoFrame(head=head, data=bytes(nal), raw=bytes(payload),
                               is_decrypted=dec)
            self.frames.append(frame)
            self.stats["video"] += 1
            return frame
        if head.codec_id in AUDIO_CODECS:
            raw = payload[FRAME_HEAD_LEN:]
            data, dec = self.crypto.decrypt_audio(raw)
            self.stats["audio"] += 1
            return AudioFrame(head=head, codec_id=head.codec_id, data=data,
                              is_decrypted=dec)
        self.stats["other"] += 1
        return None

    def h264(self) -> bytes:
        """Concatenazione NAL dei frame ricevuti (per dump/pipe a ffmpeg)."""
        out = []
        for f in self.frames:
            out.append(f.data)
        return b"".join(out)


# ---------------------------------------------------------------- §7w: unwrap
# I-frame YI (NAL type 0x3D = 29, §7r): `00000001 3d` + prefisso fisso 40 B +
# IDR "nudo" (slice senza NAL header). I P-frame sono 0x41 annex-b standard.
# Nessun SPS/PPS come NAL separati → fino all'analisi completa del prefisso
# (Gate C) si SINTETIZZANO SPS/PPS minimi baseline con gli id dello slice.


class _BitReader:
    def __init__(self, data: bytes):
        self.bits = "".join(f"{b:08b}" for b in data)
        self.pos = 0

    def u(self, n: int) -> int | None:
        if self.pos + n > len(self.bits):
            return None
        v = int(self.bits[self.pos:self.pos + n], 2)
        self.pos += n
        return v

    def ue(self) -> int | None:
        z = 0
        while self.pos < len(self.bits) and self.bits[self.pos] == "0":
            z += 1
            self.pos += 1
        if self.pos >= len(self.bits):
            return None
        self.pos += 1  # bit '1' separatore
        if z == 0:
            return 0
        if self.pos + z > len(self.bits):
            return None
        v = int(self.bits[self.pos:self.pos + z], 2) + (1 << z) - 1
        self.pos += z
        return v


def _ue_bits(v: int) -> str:
    code = v + 1
    n = code.bit_length()
    return "0" * (n - 1) + bin(code)[2:]


def _bits_to_bytes(bits: str) -> bytes:
    """RBSP: aggiunge stop bit e padding a byte."""
    bits += "1"
    while len(bits) % 8:
        bits += "0"
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def _escape_rbsp(rbsp: bytes) -> bytes:
    """Emulation prevention (00 00 → 00 00 03 quando il byte dopo è ≤ 0x03)."""
    out = bytearray()
    zeros = 0
    for b in rbsp:
        if zeros >= 2 and b <= 3:
            out.append(3)
            zeros = 0
        out.append(b)
        zeros = zeros + 1 if b == 0 else 0
    return bytes(out)


def synthesize_sps(width: int, height: int, sps_id: int = 0) -> bytes:
    """Payload RBSP (senza NAL header/start code) di un SPS baseline minimale.
    Include cropping se l'altezza non è multipla di 16. Livello 3.0."""
    b = ""
    b += f"{66:08b}"                        # profile_idc = baseline
    b += "00000000"                         # constraint flags + reserved
    b += f"{30:08b}"                        # level_idc = 3.0
    b += _ue_bits(sps_id)
    b += _ue_bits(0)                        # log2_max_frame_num_minus4
    b += _ue_bits(0)                        # pic_order_cnt_type
    b += _ue_bits(6)                        # log2_max_pic_order_cnt_lsb_minus4
    b += _ue_bits(1)                        # max_num_ref_frames
    b += "0"                                # gaps_in_frame_num_value_allowed_flag
    b += _ue_bits(width // 16 - 1)          # pic_width_in_mbs_minus1
    b += _ue_bits((height + 15) // 16 - 1)  # pic_height_in_map_units_minus1
    b += "1"                                # frame_mbs_only_flag
    crop_bottom = ((height + 15) // 16) * 16 - height
    b += "1"                                # frame_cropping_flag
    b += _ue_bits(0)                        # crop_left
    b += _ue_bits(0)                        # crop_right
    b += _ue_bits(0)                        # crop_top
    b += _ue_bits(crop_bottom // 2)         # crop_bottom (unità 2 righe, frame mode)
    b += "0"                                # vui_parameters_present_flag
    return _escape_rbsp(_bits_to_bytes(b))


def synthesize_pps(sps_id: int = 0, pps_id: int = 0) -> bytes:
    """Payload RBSP di un PPS minimale (CAVLC, deblocking on, QP 26)."""
    b = ""
    b += _ue_bits(pps_id)
    b += _ue_bits(sps_id)
    b += "0"                                # entropy_coding_mode_flag = CAVLC
    b += "0"                                # bottom_field_pic_order_in_frame_present_flag
    b += _ue_bits(0)                        # num_slice_groups_minus1
    b += _ue_bits(0)                        # num_ref_idx_l0_default_active_minus1
    b += _ue_bits(0)                        # num_ref_idx_l1_default_active_minus1
    b += "0"                                # weighted_pred_flag
    b += "00"                               # weighted_bipred_idc (2 bit)
    b += _ue_bits(0)                        # pic_init_qp_minus26
    b += _ue_bits(0)                        # pic_init_qs_minus26
    b += _ue_bits(0)                        # chroma_qp_index_offset
    b += "1"                                # deblocking_filter_control_present_flag
    b += "0"                                # constrained_intra_pred_flag
    b += "0"                                # redundant_pic_cnt_present_flag
    return _escape_rbsp(_bits_to_bytes(b))


def parse_sps_dims(rbsp: bytes) -> tuple[int, int] | None:
    """SPS RBSP → (width, height) decodificati, o None se implausibile.
    Usato per validare candidati SPS estratti dal prefisso 40 B (§7w)."""
    r = _BitReader(rbsp)
    profile = r.u(8)
    r.u(8)                                  # constraint flags + reserved
    level = r.u(8)
    sps_id = r.ue()
    if None in (profile, level, sps_id) or profile not in (66, 77, 100) \
            or not 10 <= level <= 52 or sps_id > 31:
        return None
    log2_fn = r.ue()                        # log2_max_frame_num_minus4
    poc_type = r.ue()
    if poc_type == 0:
        r.ue()                              # log2_max_pic_order_cnt_lsb_minus4
    max_ref = r.ue()
    gaps = r.u(1)
    w_mbs = r.ue()                          # pic_width_in_mbs_minus1
    h_units = r.ue()                        # pic_height_in_map_units_minus1
    frame_mbs = r.u(1)
    if None in (log2_fn, poc_type, max_ref, gaps, w_mbs, h_units, frame_mbs):
        return None
    if not 1 <= w_mbs + 1 <= 256 or not 1 <= h_units + 1 <= 256:
        return None
    if not frame_mbs:
        r.u(1)                              # direct_8x8_inference_flag
    crop = r.u(1)
    crop_l = crop_r = crop_t = crop_b = 0
    if crop:
        crop_l = r.ue()
        crop_r = r.ue()
        crop_t = r.ue()
        crop_b = r.ue()
        if None in (crop_l, crop_r, crop_t, crop_b):
            return None
    w = (w_mbs + 1) * 16 - (crop_l + crop_r) * 2
    h = (2 - frame_mbs) * ((h_units + 1) * 16 - 2 * (crop_t + crop_b))
    return w, h


def extract_sps_pps(prefix: bytes,
                    expect: tuple[int, int] | None = None) -> tuple[bytes, bytes] | None:
    """Euristiche sui candidati SPS (0x67) dentro il prefisso 40 B degli I-frame.
    Ritorna (sps_rbsp, pps_rbsp) se ne trova uno plausibile (§7r/§7w, Gate C)."""
    for off in range(len(prefix)):
        if prefix[off] != 0x67:
            continue
        for end in range(off + 8, min(len(prefix), off + 32)):
            dims = parse_sps_dims(prefix[off + 1:end])
            if dims is None:
                continue
            if expect is not None and dims != expect:
                continue
            pps_off = end
            if pps_off < len(prefix) and prefix[pps_off] == 0x68:
                r = _BitReader(prefix[pps_off + 1:])
                pps_id = r.ue()
                sps_id = r.ue()
                if pps_id is not None and sps_id is not None:
                    return prefix[off + 1:end], prefix[pps_off + 1:]
    return None


def parse_idr_pps_id(body: bytes) -> int | None:
    """Slice header di un IDR nudo → pps_id (first_mb_in_slice=0, slice_type∈{2,7}).
    Da validare sul vivo (Gate C): se il layout differisce, la sintesi usa id 0."""
    r = _BitReader(body[:8])
    if r.ue() != 0:
        return None
    st = r.ue()
    if st not in (2, 7):
        return None
    pps_id = r.ue()
    return pps_id if pps_id is not None and pps_id <= 255 else None


def unwrap_frame(vf: "VideoFrame") -> bytes | None:
    """Frame video → NAL annex-b decodificabile.
    - P-frame (0x41) e altri NAL standard: passthrough.
    - I-frame YI (0x3D): prefisso 40 B scartato, IDR nudo → `00000001 65 <body>`,
      con SPS/PPS sintetizzati in testa (id letti dallo slice header se parsabile).
    - Frame di init/estradata (data non annex-b, es. i frame `00000000` del capture):
      None → da scartare.
    """
    data = vf.data
    if data.startswith(b"\x00\x00\x00\x01") and (data[4] & 0x1F) != 29:
        return data                             # NAL standard annex-b
    if data.startswith(b"\x00\x00\x00\x01\x3d"):
        prefix = data[5:45]
        body = data[45:]
        pps_id = parse_idr_pps_id(body)
        pps_id = pps_id if pps_id is not None else 0
        sps_id = 0                              # il vero sps_id: analisi prefisso (Gate C)
        w, h = vf.head.width or 640, vf.head.height or 360
        # TODO Gate C: se extract_sps_pps(prefix, (w, h)) trova SPS/PPS reali, usarli
        # al posto dei sintetici.
        return (b"\x00\x00\x00\x01\x67" + synthesize_sps(w, h, sps_id) +
                b"\x00\x00\x00\x01\x68" + synthesize_pps(sps_id, pps_id) +
                b"\x00\x00\x00\x01\x65" + body)
    return None                                 # frame di init: scartare


def unwrap_yi_stream(frames: list["VideoFrame"]) -> bytes:
    """Lista di VideoFrame → stream annex-b standard (per dump/pipe a ffmpeg)."""
    out = []
    for vf in frames:
        u = unwrap_frame(vf)
        if u:
            out.append(u)
    return b"".join(out)
