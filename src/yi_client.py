"""Yi cloud API client — port of the app's HTTP surface.

Sources (decompiled, project findings §3/§6):
- base URLs per region: `e9/c.java` (`c.a/b/...`)
- signing: `d9/e.java` f/g (canonical `k=v&k=v`, insertion or sorted order)
  + `ra/c1.java` HmacSha1 -> Base64(HMAC-SHA1(key, data)),
  empty-key fallback "04b1aa5fb31e185f"
- endpoints: `d9/h.java` (v4 login), `d9/i.java` (v5 memomotion/hourglass,
  param `hmac`), `hm/a.java` (CloudApi.kt: /vas/v8/cloud/*), `e9/d.java`
  (alerts/devices)

Dynamic open questions (findings §6) that this module makes configurable:
- the production `secretA&secretB` values -> YI_CLIENT_SECRET env
- login password cipher `ra/d2` -> not ported yet; seed YI_SESSION_TOKEN
  to skip login (token param/header names also verified dynamically)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import time

import requests

log = logging.getLogger("yimirror")

DEFAULT_HMAC_KEY = "04b1aa5fb31e185f"  # ra/c1 fallback key


def decrypt_view_password(uid: str, password_hex: str) -> str:
    """viewPassword della camera dalla device list cloud (§7x).

    L'app (n8/u1.r2 → ra.k.a → ra.a AESEnc): la viewPassword è
    `AES-128-ECB/PKCS7-decrypt(key = UID[:16], ciphertext = hex(password))`.
    Se `password` è vuoto l'app usa il default "888888" (ra.k.d).
    Verificato live su 3 device dell'account (padding valido, 15 char alfanum).
    """
    if not password_hex:
        return "888888"
    from Crypto.Cipher import AES  # pycryptodome (già in requirements)
    raw = AES.new(uid[:16].encode(), AES.MODE_ECB).decrypt(bytes.fromhex(password_hex))
    pad = raw[-1]
    if 1 <= pad <= 16 and raw[-pad:] == bytes([pad]) * pad:
        raw = raw[:-pad]
    return raw.decode("ascii", errors="strict")

BASE_URLS = {
    "test": "http://test-api.us.xiaoyi.com",
    "cn": "https://api.xiaoyi.com",
    "us": "https://api.us.xiaoyi.com",
    "eu": "https://api.eu.xiaoyi.com",
    "tw": "https://api.xiaoyi.com.tw",
}

# I client v4/v5 e le API cloud/vas rispondono sul GATEWAY, non sull'api host
# (cattura dinamica findings §7: /v5/devices/list, /vas/v8/*, /v2/alert/* su gw-eu)
GATEWAY_URLS = {
    "cn": "https://gw.xiaoyi.com",
    "us": "https://gw-us.xiaoyi.com",
    "eu": "https://gw-eu.xiaoyi.com",
    "tw": "https://gw.xiaoyi.com.tw",
    "test": "https://gw-eu.xiaoyi.com",
}

APP_VERSION = "7.0.1_20261104115049"
APP_VERSION_CODE = "457"

# Header inviati dall'app a ogni richiesta sul gateway (cattura §7x) — alcuni
# endpoint li richiedono; il country code è configurabile via YI_COUNTRY.
HEADERS = {
    "User-Agent": f"yihome/{APP_VERSION} (docker-yimirror; Android 16; en-US)",
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
    "x-kamihome-apptype": "ANDROID",
    "x-kamihome-packagetype": "RELEASE",
    "x-xiaoyi-appversion": f"android;{APP_VERSION_CODE};{APP_VERSION}",
    "x-xiaoyi-appcountrycode": os.environ.get("YI_COUNTRY", "IT"),
}


def hmac_sha1_base64(key: str, data: str) -> str:
    """ra/c1.c: Base64(HMAC-SHA1(key, data)) — Android default Base64 == std alphabet."""
    digest = hmac.new(key.encode("utf-8"), data.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(digest).decode("ascii")


def canonical(params: dict, sort: bool = False) -> str:
    """d9/e.f (insertion order, empty values dropped) and d9/e.g (sorted).

    `params` is a dict; insertion order is preserved by Python 3.7+.
    """
    items = [(k, str(v)) for k, v in params.items() if v not in (None, "")]
    if sort:
        items.sort(key=lambda kv: kv[0])
    return "&".join(f"{k}={v}" for k, v in items)


def sign(params: dict, secret: str, sort: bool = False) -> str:
    return hmac_sha1_base64(secret, canonical(params, sort))


# ra/d2 (Sha256Util): cifratura della password di login — chiave fissa nell'app
LOGIN_PASSWORD_KEY = "KXLiUdAsO81ycDyEJAeETC$KklXdz3AC"


def encrypt_login_password(password: str) -> str:
    """ra/d2.a: Base64(NO_WRAP, HMAC-SHA256(chiave fissa, password))."""
    digest = hmac.new(LOGIN_PASSWORD_KEY.encode("utf-8"),
                      password.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


class YiCloudError(Exception):
    pass


class YiClient:
    def __init__(self, region: str = "eu", secret: str | None = None, timeout: int = 30):
        self.base = BASE_URLS.get(region.lower(), BASE_URLS["eu"])
        self.gateway = GATEWAY_URLS.get(region.lower(), GATEWAY_URLS["eu"])
        self.secret = secret or os.environ.get("YI_CLIENT_SECRET") or DEFAULT_HMAC_KEY
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.token: str | None = None
        self.userid: str | None = None

    # ------------------------------------------------------------------ helpers

    def _url(self, path: str, gateway: bool = False) -> str:
        return (self.gateway if gateway else self.base) + path

    def _request(self, method: str, path: str, params: dict | None = None,
                 signed: bool = False, sort: bool = False, gateway: bool = False,
                 app_params: bool = True, **kwargs) -> dict:
        params = dict(params or {})
        if app_params:
            params.setdefault("seq", "1")
            params.setdefault("timestamp", str(int(time.time())))
            if self.token:
                # the app sends the session token per-request; exact param name is
                # confirmed dynamically (query `token` is the historical v4 shape)
                params.setdefault("token", self.token)
        if signed:
            params["hmac"] = sign(params, self.secret, sort=sort)
        resp = self.session.request(
            method, self._url(path, gateway=gateway), params=params,
            timeout=self.timeout, **kwargs
        )
        if resp.status_code >= 400:
            raise YiCloudError(f"{method} {path} -> HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            return resp.json()
        except ValueError:
            raise YiCloudError(f"{method} {path} -> non-JSON body: {resp.text[:200]}")

    # ------------------------------------------------------------------ auth

    def login(self, account: str, password: str) -> dict:
        """d9/h.F: POST /v4/users/login (form body, NON firmato).

        Da jadx: params `account`/`email`/`mobile` + `password` (cifrata ra/d2,
        §7j) + `dev_name`/`dev_type`/`dev_os_version` + `seq`. Successo = envelope
        `{"code":20000,"data":{userid, token, token_secret, ...}}`. La chiave di
        firma delle API /v5 e /vas è `token + "&" + token_secret` (§7x,
        e9/d.s0 → e0.A()&e0.B()).
        """
        # d9/h.F (HttpClientV4): per l'internazionale (e8.d.M()==false, cioè
        # regione != "CHN") il login usa SEMPRE il campo "account", mai "email"/
        # "mobile" (quelli valgono solo per la Cina). Usare "email" per un indirizzo
        # email fa fallire il server con code -10003.
        region = os.environ.get("YI_REGION", "eu").upper()
        params = {"seq": "1"}
        if region in ("CHN", "CN", "CHINA"):
            import re
            is_email = bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", account))
            params["email" if is_email else "mobile"] = account
        else:
            params["account"] = account
        params["password"] = encrypt_login_password(password)
        params["dev_name"] = "docker-yimirror"
        params["dev_type"] = "yimirror"
        params["dev_os_version"] = "linux"
        data = self._request("POST", "/v4/users/login", data=params, gateway=True)
        self._adopt_session(data)
        return data

    def adopt_token(self, token: str, userid: str | None = None,
                    token_secret: str | None = None) -> None:
        self.token = token
        self.userid = userid
        if token and token_secret:
            self.secret = f"{token}&{token_secret}"

    def _adopt_session(self, data: dict) -> None:
        d = data.get("data") if isinstance(data.get("data"), dict) else data
        code = data.get("code")
        if code not in (None, 20000):
            raise YiCloudError(f"login code={code}: {str(data)[:200]}")
        token = d.get("token")
        token_secret = d.get("token_secret")
        if d.get("userid") not in (None, ""):
            self.userid = str(d["userid"])
        if token:
            self.token = token
        # chiave di firma per-utente (token&token_secret) — SOSTITUISCE il secret
        # placeholder; senza di essa le chiamate /v5 firmate falliscono (§7x)
        if token and token_secret:
            self.secret = f"{token}&{token_secret}"
        else:
            log.warning("_adopt_session: token/token_secret mancanti nella "
                        "risposta login (%s)", list(d.keys())[:10])

    def auth_token(self) -> dict:
        """d9/e: /v4/users/auth_token — refresh flow (params token/reftoken)."""
        if not self.token:
            raise YiCloudError("no session token to refresh")
        return self._request("POST", "/v4/users/auth_token",
                             params={"token": self.token})

    # ------------------------------------------------------------------ devices

    def devices(self) -> list:
        """Device list; each entry carries P2P creds (DeviceInfo -> P2PDevice, §3).

        Cattura live (§7x): GET /v5/devices/list?userid=..&seq=1&hmac=.. sul
        gateway, firmato su {userid, seq} (niente timestamp/token in query —
        la sessione viaggia via cookie/header). Richiede gli header app.
        """
        # ordine d'inserimento ESATTO di e9/d.s0 (m0 non scarta i vuoti, no sort)
        params = {"seq": "1", "userid": self.userid or ""}
        params["hmac"] = sign(params, self.secret, sort=False)
        data = self._request("GET", "/v5/devices/list", params=params,
                             gateway=True, app_params=False)
        for key in ("devices", "list", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        if isinstance(data, list):
            return data
        log.warning("devices(): unexpected shape: %s", str(data)[:200])
        return []

    def view_passwords(self) -> dict:
        """{UID: viewPassword} per ogni device dell'account (§7x).

        Deriva la viewPassword dal campo `password` cifrato della device list.
        È la credenziale che il client TNP usa per l'authInfo dei controlli e
        per il decrypt degli I-frame; ruota a ogni refresh della device list, per
        cui va riletta dal cloud quando la camera smette di rispondere."""
        out: dict[str, str] = {}
        for d in self.devices():
            uid = d.get("uid") or d.get("UID")
            if not uid:
                continue
            try:
                out[uid] = decrypt_view_password(uid, d.get("password", ""))
            except Exception as exc:  # pragma: no cover - diagnostica
                log.warning("view_passwords(): decrypt fallito per %s: %s", uid, exc)
        return out

    def view_password_for(self, uid_contains: str) -> str | None:
        """viewPassword del primo device il cui UID contiene `uid_contains`
        (es. il suffisso 'SYUPE'). None se non trovato."""
        for uid, pw in self.view_passwords().items():
            if uid_contains in uid:
                return pw
        return None

    # ------------------------------------------------------------------ cloud recording (CloudApi.kt, hm/a)

    def cloud_status(self) -> list:
        """GET /vas/v8/all/cloud/status -> [{...DeviceCloudInfo...}] per camera."""
        data = self._request("GET", "/vas/v8/all/cloud/status", gateway=True)
        for key in ("devices", "list", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        if isinstance(data, list):
            return data
        log.warning("cloud_status(): unexpected shape: %s", str(data)[:200])
        return []

    def cloud_videos(self, uid: str, start: int, end: int) -> dict:
        """GET /vas/v8/cloud/videos -> clip references for a time range.

        Exact param names and response shape are dynamic open questions (§6);
        the endpoint exists with GET/DELETE in hm/a (l/c methods).
        """
        return self._request("GET", "/vas/v8/cloud/videos",
                             params={"uid": uid, "start": start, "end": end}, gateway=True)

    def ts_metadata(self, uid: str, start: int, end: int,
                    speed: int = 1, ipc_type: int = 0) -> list:
        """GET /vas/v8/cloud/ts/metadata -> [{t: epoch_s, d: duration_s, b: flag}]."""
        data = self._request("GET", "/vas/v8/cloud/ts/metadata",
                             params={"uid": uid, "start": start, "end": end,
                                     "speed": speed, "ipc_type": ipc_type}, gateway=True)
        if isinstance(data, list):
            return data
        for key in ("ts", "list", "data", "metadata"):
            if isinstance(data.get(key), list):
                return data[key]
        log.warning("ts_metadata(): unexpected shape: %s", str(data)[:200])
        return []

    # ------------------------------------------------------------------ alerts

    def alert_events(self, uid: str | None = None, limit: int = 20) -> list:
        params = {"limit": limit}
        if uid:
            params["uid"] = uid
        data = self._request("GET", "/v5/alert/events", params=params, gateway=True)
        for key in ("events", "list", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        if isinstance(data, list):
            return data
        log.warning("alert_events(): unexpected shape: %s", str(data)[:200])
        return []

    # ------------------------------------------------------------------ v5 signed (d9/i)

    def memomotions(self, uid: str, start: int, limit: int,
                    states: str = "", mm: str = "", mn: str = "") -> dict:
        """GET /v5/cloud/memomotions — legacy video-event list, HMAC-signed."""
        params = {
            "userid": self.userid or "",
            "uid": uid,
            "mm": mm,
            "mn": mn,
            "states": states,
            "start": start,
            "limit": limit,
        }
        return self._request("GET", "/v5/cloud/memomotions", params=params, signed=True, gateway=True)
