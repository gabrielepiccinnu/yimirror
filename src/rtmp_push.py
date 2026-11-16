"""rtmp_push.py — modalità RTMP: la camera PUSHA il video direttamente verso
il nostro mediamtx (porta 1935 pubblica sul VPS) e Frigate continua a leggere
rtsp://mediamtx:8554/ingresso come sempre.

Perché: il motore RTMP della camera è la macchina della registrazione cloud
in background (SET_RTMP_ADDR 0x03B6 + START_RTMP 0x03B0 su sessione TNP
autenticata; l'app 7.0.1 non li chiama mai — li invia il server YI). Il
video NON passa dal canale media P2P → niente sustain problem (burst
4-12 s) e la camera si auto-sostiene come con il cloud recording attivo.

Uso:
  RTMP_URL=rtmp://bridge:PASS@164.68.119.188:1935/ingresso \
    python3 -m src.rtmp_push
Richiede: mediamtx sul VPS con porta 1935 esposta (deploy/docker-compose.video.yml).

Env opzionali:
  YIMIRROR_RTMP_PARAM    int BE di START_RTMP (default 0; significato da
                         determinare dal vivo: durata/qualità/canale)
  YIMIRROR_RTMP_POLL     secondi tra due QUERY_RTMP_STAT (default 20)
  YIMIRROR_RTMP_HOLD     durata di una hold di sessione (default 3600)
  YIMIRROR_RTMP_KEEPALIVE secondi tra due heartbeat e0 (default 5)
  + le stesse env del proxy nativo (YIMIRROR_P2PID/LICENSE/INIT_STRING,
    YI_TOKEN/…, MQTT, API, backoff)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

log = logging.getLogger("yimirror.rtmp_push")

RTMP_URL = os.environ.get("RTMP_URL", "")


def _sanitize(st: dict | None) -> dict | None:
    """Rimuove le credenziali dall'URL (che la camera echoa) prima di
    esporlo su API/MQTT."""
    if not st:
        return st
    import re
    out = dict(st)
    if isinstance(out.get("url"), str):
        out["url"] = re.sub(r"://[^@/]+@", "://***@", out["url"])
    return out


def push_rtmp_loop() -> None:
    """Macchina a stati come push_native_loop, ma il media passa dal push
    RTMP della camera (camera → mediamtx), non dal canale P2P. La sessione
    TNP serve solo a COMANDARE (auth → SET_RTMP_ADDR → START_RTMP) e a
    tenere caldo il canale comandi (hold_rtmp). Lo stato DESIDERATO arriva
    da Frigate via MQTT o dall'API HTTP; OFF = STOP_RTMP + privacy reale."""
    from tnp_client import TnpSession
    from control import ProxyState, start_mqtt, start_api
    from rtsp_push import _fresh_view_password

    p2pid = os.environ.get("YIMIRROR_P2PID", "")
    license_key = os.environ.get("YIMIRROR_LICENSE", "")
    init_string = os.environ.get("YIMIRROR_INIT_STRING", "")
    if not (p2pid and license_key and init_string):
        log.error("servono YIMIRROR_P2PID, YIMIRROR_LICENSE, YIMIRROR_INIT_STRING")
        raise SystemExit(1)
    rtmp_url = RTMP_URL or os.environ.get("YIMIRROR_RTMP_URL", "")
    if not rtmp_url:
        log.error("imposta RTMP_URL (rtmp://bridge:PASS@VPS:1935/ingresso)")
        raise SystemExit(1)

    state = ProxyState()
    start_mqtt(state)
    start_api(state)

    rtmp_param = int(os.environ.get("YIMIRROR_RTMP_PARAM", "0"))
    POLL = float(os.environ.get("YIMIRROR_RTMP_POLL", "20"))
    HOLD = float(os.environ.get("YIMIRROR_RTMP_HOLD", "3600"))
    # Anti-mute del relay (§7x-bis): niente spam di handshake; re-handshake
    # vero solo dopo REHANDSHAKE_AFTER senza risposte di stato, con backoff.
    REHANDSHAKE_AFTER = float(os.environ.get("YIMIRROR_REHANDSHAKE_AFTER", "120"))
    BACKOFF_BASE = float(os.environ.get("YIMIRROR_BACKOFF_BASE", "60"))
    BACKOFF_MAX = float(os.environ.get("YIMIRROR_BACKOFF_MAX", "300"))
    fail_streak = 0

    def backoff_wait() -> float:
        return min(BACKOFF_BASE * 2 ** max(fail_streak - 1, 0), BACKOFF_MAX)

    session: TnpSession | None = None
    privacy_done = False
    heartbeat = 15.0                    # ripubblica lo stato retained ogni 15 s

    while True:
        # --- stato desiderato OFF → STOP_RTMP + privacy REALE (0x1304) -----
        if not state.desired_on:
            if not privacy_done:
                try:
                    if session is None or not session.connected:
                        log.info("OFF richiesto → connessione per stop+privacy...")
                        session = TnpSession(p2pid, license_key, init_string)
                        session.desired_on = False
                        if not session.connect(timeout=10):
                            session = None
                            raise RuntimeError("connect per privacy fallito")
                    session.p2p_password = _fresh_view_password(p2pid)
                    session.rtmp_stop()                      # ferma il push
                    ok = session.set_camera_power(False)     # privacy reale
                    cc = session.devinfo.get("close_camera")
                    session.close()
                    session = None
                    if not ok:
                        raise RuntimeError(f"0x1304 non confermato (close_camera={cc})")
                    privacy_done = True
                    fail_streak = 0
                    log.info("privacy applicata: camera spenta (close_camera=%s)", cc)
                except Exception as exc:
                    fail_streak += 1
                    wait = backoff_wait()
                    log.warning("privacy OFF non applicata: %s — ritento tra %.0fs",
                                exc, wait)
                    session = None
                    state.update(status="error")
                    state.wait_change(wait)
                    continue
            state.update(status="privacy", close_camera=1)
            state.wait_change(600)
            continue

        # --- stato desiderato ON → sessione + avvio push RTMP -------------
        privacy_done = False
        if session is None or not session.connected:
            state.update(status="waking")
            log.info("connessione TNP...")
            session = TnpSession(p2pid, license_key, init_string)
            session.desired_on = True
            if not session.connect(timeout=10):
                fail_streak += 1
                wait = backoff_wait()
                log.warning("connect fallito — backoff %.0fs (tentativo %d)",
                            wait, fail_streak)
                session = None
                state.update(status="error")
                state.wait_change(wait)
                continue
            log.info("sessione attiva: %s — avvio push RTMP", session.server)
            try:
                info, st = session.start_rtmp_push(
                    rtmp_url, param=rtmp_param,
                    password=_fresh_view_password(p2pid))
            except RuntimeError as exc:
                log.warning("start_rtmp_push fallito: %s", exc)
                info, st = None, None
            if info is not None:
                state.update(server=str(session.server),
                             close_camera=session.devinfo.get("close_camera"))
            if st is not None:
                state.update(detail={"rtmp_start": _sanitize(st)})
            if st is not None and "left_time" in st:
                log.info("[rtmp] push avviato: left_time=%s url='%s'",
                         st.get("left_time"), st.get("url") or rtmp_url)
                state.update(status="streaming",
                             close_camera=session.devinfo.get("close_camera"))
            else:
                log.warning("[rtmp] start senza dati reali (st=%s) — si tiene "
                            "la sessione calda", st)

        # --- hold del canale comandi + poll dello stato del push -----------
        last_stat = time.time()
        last_pub = 0.0
        ctrl_events = []                   # ring: risposte di controllo non sollecitate
        try:
            for st in session.hold_rtmp(HOLD, stat_interval=POLL):
                if not state.desired_on:
                    break
                now = time.time()
                if st is not None and st.get("kind") == "ctrl":
                    ctrl_events.append({"t": time.strftime("%H:%M:%S"),
                                        "rtype": hex(st["rtype"]),
                                        "raw_head": st["raw_head"]})
                    ctrl_events = ctrl_events[-6:]
                    log.warning("[rtmp] risposta non sollecitata: type=%s head=%s",
                                hex(st["rtype"]), st["raw_head"])
                    state.update(detail={"ctrl_events": list(ctrl_events)},
                                 close_camera=session.devinfo.get("close_camera"))
                    continue
                if st is not None:
                    state.update(detail={"rtmp_query": _sanitize(st),
                                         "ctrl_events": list(ctrl_events)},
                                 close_camera=session.devinfo.get("close_camera"))
                    if "left_time" in st:
                        last_stat = now
                        log.info("[rtmp] stat: left_time=%s url='%s'",
                                 st.get("left_time"), st.get("url"))
                        state.update(status="streaming",
                                     close_camera=session.devinfo.get("close_camera"))
                    else:
                        log.warning("[rtmp] risposta senza dati reali: %s", st)
                if now - last_pub >= heartbeat:
                    state.publish()
                    last_pub = now
                if now - last_stat > REHANDSHAKE_AFTER:
                    log.warning("nessuna risposta rtmp stat da %.0fs — "
                                "riconnessione", now - last_stat)
                    break
        except Exception as exc:  # noqa: BLE001 — il loop deve sopravvivere
            log.warning("hold_rtmp interrotto: %s", exc)

        if not state.desired_on:
            continue                      # transizione a OFF gestita in testa
        if last_stat > time.time() - POLL * 2:
            fail_streak = 0              # push vivo → niente backoff
            log.warning("sessione comandi interrotta — riavvio")
        else:
            fail_streak += 1
            wait = backoff_wait()
            log.warning("push non confermato — re-handshake tra %.0fs "
                        "(tentativo %d)", wait, fail_streak)
            state.update(status="waking")
            state.wait_change(wait)
        if session is not None:
            session.close()
            session = None


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()
    logging.basicConfig(level=os.environ.get("YIMIRROR_LOG", "INFO").upper(),
                        format="%(asctime)s %(name)s: %(message)s")
    push_rtmp_loop()


if __name__ == "__main__":
    main()
