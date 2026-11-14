"""control.py — stato condiviso del proxy + ponte MQTT con Frigate + API HTTP.

Obiettivo (§7y): accendere/spegnere la camera da Frigate.
- Frigate pubblica `frigate/<cam>/enabled/state` = ON/OFF quando si (dis)attiva la
  camera nella UI (richiede mqtt abilitato in Frigate). Il proxy vi si iscrive e
  imposta lo stato DESIDERATO.
- Il proxy esegue lo spegnimento REALE con CLOSE_CAMERA 0x1304 (privacy mode) e
  pubblica lo stato EFFETTIVO su `yimirror/<cam>/state` (retained) + availability.
- Una piccola API HTTP interna (solo rete del progetto) espone /health, /status,
  /camera/on, /camera/off per il controllo diretto (es. Home Assistant).

Tutto opzionale: senza MQTT_HOST il ponte MQTT non parte; senza YIMIRROR_API_PORT
l'API non parte. Il proxy funziona comunque (sempre ON).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("yimirror.control")

CAM = os.environ.get("YIMIRROR_CAMERA_NAME", "ingresso")


class ProxyState:
    """Stato condiviso tra il loop del proxy, MQTT e l'API (thread-safe)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._desired_on = True          # stato voluto (da Frigate/API)
        self.status = "starting"          # effettivo: starting|streaming|privacy|waking|error|idle
        self.close_camera: int | None = None
        self.last_frame_ts: float = 0.0
        self.server: str = ""
        self._on_change = threading.Event()
        self._mqtt = None                 # client MQTT per il publish di stato

    # --- stato desiderato -------------------------------------------------
    @property
    def desired_on(self) -> bool:
        with self._lock:
            return self._desired_on

    def set_desired(self, on: bool, source: str = "?") -> None:
        with self._lock:
            changed = on != self._desired_on
            self._desired_on = on
        if changed:
            log.info("stato desiderato -> %s (da %s)", "ON" if on else "OFF", source)
            self._on_change.set()
            self.publish()

    def wait_change(self, timeout: float) -> bool:
        got = self._on_change.wait(timeout)
        self._on_change.clear()
        return got

    # --- stato effettivo --------------------------------------------------
    def update(self, *, status: str | None = None, close_camera: int | None = None,
               frame: bool = False, server: str | None = None) -> None:
        with self._lock:
            if status is not None:
                self.status = status
            if close_camera is not None:
                self.close_camera = close_camera
            if server is not None:
                self.server = server
            if frame:
                self.last_frame_ts = time.time()
        self.publish()

    def snapshot(self) -> dict:
        with self._lock:
            age = round(time.time() - self.last_frame_ts, 1) if self.last_frame_ts else None
            return {
                "camera": CAM,
                "desired_on": self._desired_on,
                "status": self.status,
                "close_camera": self.close_camera,
                "last_frame_age_s": age,
                "server": self.server,
            }

    # --- publish MQTT -----------------------------------------------------
    def attach_mqtt(self, client) -> None:
        self._mqtt = client

    def publish(self) -> None:
        if self._mqtt is None:
            return
        try:
            self._mqtt.publish(f"yimirror/{CAM}/state",
                               json.dumps(self.snapshot()), retain=True)
        except Exception as exc:  # pragma: no cover
            log.debug("publish stato fallito: %s", exc)


# ---------------------------------------------------------------- MQTT bridge

def start_mqtt(state: ProxyState):
    """Avvia il client MQTT (se MQTT_HOST è impostato). Ritorna il client o None."""
    host = os.environ.get("MQTT_HOST", "")
    if not host:
        log.info("MQTT disattivato (MQTT_HOST non impostato)")
        return None
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        log.warning("paho-mqtt non installato: MQTT disattivato")
        return None

    port = int(os.environ.get("MQTT_PORT", "1883"))
    user = os.environ.get("MQTT_USER", "")
    pw = os.environ.get("MQTT_PASSWORD", "")
    avail = f"yimirror/{CAM}/availability"

    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                             client_id=f"yimirror-{CAM}")
    except (AttributeError, TypeError):  # paho < 2
        client = mqtt.Client(client_id=f"yimirror-{CAM}")
    if user:
        client.username_pw_set(user, pw)
    client.will_set(avail, "offline", retain=True)

    def on_connect(c, userdata, flags, reason_code, properties=None):
        log.info("MQTT connesso (%s)", reason_code)
        c.publish(avail, "online", retain=True)
        # Frigate: ON/OFF del toggle "enabled" della camera
        c.subscribe(f"frigate/{CAM}/enabled/state")
        # controllo diretto opzionale
        c.subscribe(f"yimirror/{CAM}/power/set")
        state.publish()

    def on_message(c, userdata, msg):
        payload = msg.payload.decode(errors="replace").strip().upper()
        if msg.topic == f"frigate/{CAM}/enabled/state":
            state.set_desired(payload == "ON", source="frigate")
        elif msg.topic == f"yimirror/{CAM}/power/set":
            on = payload in ("ON", "1", "TRUE")
            state.set_desired(on, source="mqtt/set")
            # tiene coerente anche il toggle di Frigate
            c.publish(f"frigate/{CAM}/enabled/set", "ON" if on else "OFF")

    client.on_connect = on_connect
    client.on_message = on_message
    try:
        client.connect(host, port, keepalive=60)
    except Exception as exc:
        log.warning("MQTT connect fallito (%s:%s): %s", host, port, exc)
        return None
    client.loop_start()
    state.attach_mqtt(client)
    return client


# ----------------------------------------------------------------- HTTP API

def start_api(state: ProxyState) -> None:
    """Avvia l'API HTTP di controllo (se YIMIRROR_API_PORT è impostato)."""
    port = int(os.environ.get("YIMIRROR_API_PORT", "0"))
    if not port:
        return
    token = os.environ.get("YIMIRROR_API_TOKEN", "")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silenzia il logging di default
            pass

        def _json(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authed(self) -> bool:
            if not token:
                return True
            return self.headers.get("Authorization", "") == f"Bearer {token}"

        def do_GET(self):
            if self.path == "/health":
                self._json(200, {"ok": True})
            elif self.path == "/status":
                self._json(200, state.snapshot())
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):
            if self.path not in ("/camera/on", "/camera/off"):
                self._json(404, {"error": "not found"})
                return
            if not self._authed():
                self._json(401, {"error": "unauthorized"})
                return
            on = self.path.endswith("/on")
            state.set_desired(on, source="api")
            self._json(200, {"ok": True, "desired_on": on})

    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log.info("API di controllo su :%d", port)
