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

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 16; YI Home) AppleWebKit/537.36",
    "Accept": "application/json",
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
                 **kwargs) -> dict:
        params = dict(params or {})
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
        """d9/h.F: POST /v4/users/login.

        NOTE: the app encrypts `password` with `ra/d2.b().a()` before sending; that
        cipher is not ported yet. If the server rejects a plain password, seed
        YI_SESSION_TOKEN instead (see README).
        """
        params = {
            "account": account,
            "password": password,
            "dev_name": "docker-yimirror",
            "dev_type": "yimirror",
            "dev_os_version": "linux",
        }
        data = self._request("POST", "/v4/users/login", params=params)
        self._adopt_session(data)
        return data

    def adopt_token(self, token: str, userid: str | None = None) -> None:
        self.token = token
        self.userid = userid

    def _adopt_session(self, data: dict) -> None:
        # response shape TBD dynamically; accept common spellings
        for key in ("token", "access_token", "session_token"):
            if isinstance(data.get(key), str) and data[key]:
                self.token = data[key]
                break
        for key in ("userid", "user_id", "uid"):
            if data.get(key) not in (None, ""):
                self.userid = str(data[key])
                break

    def auth_token(self) -> dict:
        """d9/e: /v4/users/auth_token — refresh flow (params token/reftoken)."""
        if not self.token:
            raise YiCloudError("no session token to refresh")
        return self._request("POST", "/v4/users/auth_token",
                             params={"token": self.token})

    # ------------------------------------------------------------------ devices

    def devices(self) -> list:
        """Device list; each entry carries P2P creds (DeviceInfo -> P2PDevice, §3)."""
        data = self._request("GET", "/v5/devices/list", gateway=True)
        for key in ("devices", "list", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        if isinstance(data, list):
            return data
        log.warning("devices(): unexpected shape: %s", str(data)[:200])
        return []

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
