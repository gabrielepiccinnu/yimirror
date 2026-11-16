"""cloud_reader.py — legge la registrazione cloud in background della camera.

Catena VERIFICATA dal vivo (2026-11-16, §7x-quaterdecies-bis):
  /vas/v8/cloud/videos  (firma token&token_secret, canonical sorted CON vuoti)
      -> viewUrl = index.m3u8 sul gateway
      -> per episodio: #EXT-X-KEY AES-128, URI /v4/cloud/hlsKey (SENZA firma),
         IV fisso 0x61*16; segmenti .ts su OSS Alibaba (URL firmati, ~24h)
      -> decifra -> TS validi H.264 640x360 + AAC
I segmenti arrivano ~30s alla volta (piano Motion: solo eventi; piano
Continuous: contigui 24/7). Nomi file = timestamp `yyyyYMMddD...S00.30.ts`.
"""

from __future__ import annotations

import logging
import re
import urllib.request
import urllib.parse as up

log = logging.getLogger("yimirror.cloud_reader")

HLS_IV = bytes.fromhex("61616161616161616161616161616161")  # IV fisso dell'app

SEG_NAME_RE = re.compile(
    r"/(\d{4}Y\d{2}M\d{2}D\d{2}H\d{2}M\d{2}S\d{2}\.\d+\.ts)")


def parse_m3u8(text: str) -> list[dict]:
    """index.m3u8 → [{key_uri, iv, segments: [(url, duration_s), …]}, …].
    Un episodio = una #EXT-X-DISCONTINUITY con la sua #EXT-X-KEY."""
    episodes: list[dict] = []
    cur: dict | None = None
    pending_dur: float | None = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#EXT-X-KEY"):
            m = re.search(r'URI="([^"]+)"', line)
            cur = {"key_uri": m.group(1) if m else None,
                   "iv": HLS_IV, "segments": []}
            episodes.append(cur)
        elif line.startswith("#EXTINF:"):
            m = re.search(r"([\d.]+)", line)
            pending_dur = float(m.group(1)) if m else None
        elif line.startswith("http"):
            if cur is None:
                cur = {"key_uri": None, "iv": HLS_IV, "segments": []}
                episodes.append(cur)
            cur["segments"].append((line, pending_dur))
            pending_dur = None
    return episodes


def fetch_key(key_uri: str, secret: str) -> bytes | None:
    """Chiave AES-128 da /v4/cloud/hlsKey. La cattura mostra che basta l'URI
    del m3u8 (niente hmac); se il server la rifiuta si riprova con la firma
    (stesso schema /vas: sorted con vuoti, chiave token&token_secret)."""
    try:
        with urllib.request.urlopen(key_uri, timeout=15) as r:
            blob = r.read()
            return blob if len(blob) == 16 else None
    except urllib.error.HTTPError:
        from yi_client import hmac_sha1_base64
        parts = up.urlsplit(key_uri)
        q = dict(up.parse_qsl(parts.query, keep_blank_values=True))
        canon = "&".join(f"{k}={q[k]}" for k in sorted(q))
        q["hmac"] = hmac_sha1_base64(secret, canon)
        full = up.urlunsplit((parts.scheme, parts.netloc, parts.path,
                              up.urlencode(q), ""))
        with urllib.request.urlopen(full, timeout=15) as r:
            blob = r.read()
            return blob if len(blob) == 16 else None
    except Exception as exc:  # noqa: BLE001
        log.warning("fetch_key fallita: %s", exc)
        return None


def decrypt_segment(blob: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-128-CBC come da EXT-X-KEY (padding PKCS7 lasciato: il TS lo tollera)."""
    try:
        from Crypto.Cipher import AES
        return AES.new(key, AES.MODE_CBC, iv).decrypt(blob)
    except ImportError:
        # fallback puro (openssl via subprocess non disponibile): ritorna None
        log.error("pycryptodome non installato")
        raise


def segment_epoch(url: str) -> int:
    """Epoch del segmento dal nome file (`2026Y11M15D21H51M59S00.30.ts` —
    le lettere Y/M/D/H/S sono separatori letterali)."""
    m = SEG_NAME_RE.search(url)
    if not m:
        return 0
    nums = re.findall(r"\d+", m.group(1))
    if len(nums) >= 6:
        import calendar
        y, mo, dd, h, mi, sec = (int(x) for x in nums[:6])
        return calendar.timegm((y, mo, dd, h, mi, sec))
    return 0


def fetch_new_segments(yc, uid: str, since_t: int, end_t: int,
                       max_bytes: int = 50_000_000):
    """Scarica e decifra i segmenti cloud nuovi di (since_t, end_t].
    Yields (epoch_t, dur_s, bytes_decifrati) in ordine di tempo. Gli errori di
    rete sono loggati e il segmento viene saltato (ritentato al poll dopo)."""
    try:
        vids = yc.cloud_videos(uid, since_t - 60, end_t + 60)
    except Exception as exc:  # noqa: BLE001
        log.warning("cloud_videos fallito: %s", exc)
        return
    data = vids.get("data") or {}
    view = data.get("viewUrl")
    if not view:
        return
    try:
        with urllib.request.urlopen(view, timeout=20) as r:
            text = r.read().decode(errors="replace")
    except Exception as exc:  # noqa: BLE001
        log.warning("download m3u8 fallito: %s", exc)
        return
    total = 0
    for ep in parse_m3u8(text):
        key = None
        if ep["key_uri"]:
            key = fetch_key(ep["key_uri"], yc.secret)
            if not key:
                log.warning("chiave HLS mancante per %s", ep["key_uri"])
                continue
        # CBC CONCATENATA tra i file di un episodio (VERIFICATO: il segmento
        # N+1 si decifra con IV = ultimi 16 byte del ciphertext del segmento
        # N; solo il primo file parte dall'IV dell'EXT-X-KEY).
        rolling_iv = ep["iv"]
        for url, dur in ep["segments"]:
            t = segment_epoch(url)
            if t and t <= since_t:
                continue                      # già processato
            try:
                with urllib.request.urlopen(url, timeout=30) as r:
                    blob = r.read()
            except Exception as exc:  # noqa: BLE001
                log.warning("download segmento fallito (%s): %s — si riparte "
                            "da qui al prossimo poll (la CBC è concatenata)",
                            url[-60:], exc)
                break                       # non saltare: romperebbe la catena CBC
            total += len(blob)
            if total > max_bytes:
                log.warning("limite byte raggiunto: interrompo il ciclo")
                return
            if key:
                data = decrypt_segment(blob, key, rolling_iv)
                rolling_iv = blob[-16:] if len(blob) >= 16 else rolling_iv
            else:
                data = blob
                if data[:1] != b"\x47":
                    log.warning("segmento senza chiave e senza sync TS: skip %s",
                                url[-60:])
                    continue
            yield t, dur or 30.0, data
