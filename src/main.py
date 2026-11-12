"""yimirror — mirror YI cloud recordings to a personal cloud (Backblaze B2).

Cycle:
  login -> devices -> cloud status per camera -> enumerate clips (last N days)
  -> download new clips (ts -> mp4) -> upload via rclone -> cleanup.

`--once` runs a single cycle (use with external cron); without it the loop
sleeps YIMIRROR_INTERVAL seconds between cycles.
"""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import os
import sys
import time
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()  # no-op when running under docker-compose env_file
except ImportError:
    pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import downloader, store, uploader  # noqa: E402
from src.yi_client import YiClient, YiCloudError  # noqa: E402

log = logging.getLogger("yimirror")

DATA_DIR = os.environ.get("YIMIRROR_DATA_DIR", "./data")
PENDING_DIR = Path(DATA_DIR) / "pending"


def _day_range(lookback_days: int) -> list[tuple[int, int, str]]:
    """[(t0, t1, 'YYYY-MM-DD')] for the last `lookback_days` UTC days."""
    today = dt.datetime.now(dt.timezone.utc).date()
    out = []
    for back in range(lookback_days - 1, -1, -1):
        day = today - dt.timedelta(days=back)
        t0 = int(dt.datetime(day.year, day.month, day.day, tzinfo=dt.timezone.utc).timestamp())
        t1 = t0 + 86400
        out.append((t0, t1, day.isoformat()))
    return out


def _login(client: YiClient, st: store.Store) -> bool:
    token = os.environ.get("YI_SESSION_TOKEN")
    if token:
        client.adopt_token(token)
        log.info("using seeded session token (YI_SESSION_TOKEN)")
        return True
    cached = st.get_kv("session_token")
    if cached:
        client.adopt_token(cached)
        log.info("using cached session token")
        return True
    user = os.environ.get("YI_USER")
    password = os.environ.get("YI_PASS")
    if not user or not password:
        log.error("YI_USER/YI_PASS not set and no session token available")
        return False
    data = client.login(user, password)
    if client.token:
        st.set_kv("session_token", client.token)
    log.info("login ok (userid=%s)", client.userid or "?")
    return True


def _device_cloud_active(info: dict) -> bool:
    """DeviceCloudInfo truth: isOpenCloud()/hasVideo() — key names TBD dynamically."""
    for key in ("isOpenCloud", "openCloud", "cloudOpen", "open_cloud"):
        if info.get(key) is True:
            return True
    for key in ("hasVideo", "has_video"):
        if info.get(key) is True:
            return True
    return False


def _uid_of(info: dict) -> str:
    for key in ("uid", "UID", "deviceUid", "device_uid"):
        if info.get(key):
            return str(info[key])
    return "?"


def run_cycle(client: YiClient, st: store.Store, lookback_days: int,
              keep_local: bool) -> dict:
    stats = {"devices": 0, "active": 0, "clips_seen": 0, "downloaded": 0,
             "uploaded": 0, "failed": 0}

    cloud_info = {_uid_of(d): d for d in client.cloud_status()}
    devices = client.devices()
    stats["devices"] = len(devices)
    if not devices:
        log.warning("no devices returned; is the session token valid?")

    for dev in devices:
        uid = _uid_of(dev)
        state = cloud_info.get(uid, {})
        active = _device_cloud_active(state)
        log.info("device %s: cloud recording %s", uid,
                 "ACTIVE" if active else "not active (no Yi Cloud subscription?)")
        if not active:
            continue
        stats["active"] += 1

        for t0, t1, day in _day_range(lookback_days):
            try:
                videos = client.cloud_videos(uid, t0, t1)
            except YiCloudError as e:
                log.warning("cloud_videos(%s, %s) failed: %s", uid, day, e)
                continue
            clips = _extract_clips(videos)
            stats["clips_seen"] += len(clips)
            for clip in clips:
                clip_id, ct0, ct1 = _clip_fields(clip, t0, t1)
                if not st.is_new(uid, day, clip_id):
                    continue
                dest = PENDING_DIR / uid / day / f"{clip_id}.mp4"
                try:
                    downloader.download_clip(client, uid, ct0, ct1, dest)
                    st.mark_downloaded(uid, day, clip_id, ct0, ct1, str(dest))
                    stats["downloaded"] += 1
                except Exception as e:  # noqa: BLE001 — one bad clip must not stop the cycle
                    log.error("download failed for %s/%s/%s: %s", uid, day, clip_id, e)
                    st.mark_failed(uid, day, clip_id, str(e))
                    stats["failed"] += 1

    # uploads: everything downloaded but not uploaded yet (retries included)
    for uid, day, clip_id, path in st.pending_uploads():
        if not os.path.exists(path):
            st.mark_failed(uid, day, clip_id, f"missing local file: {path}")
            stats["failed"] += 1
            continue
        try:
            uploader.upload_file(path, f"{uid}/{day}/{clip_id}.mp4")
            st.mark_uploaded(uid, day, clip_id)
            downloader.local_cleanup(path, keep_local)
            stats["uploaded"] += 1
        except Exception as e:  # noqa: BLE001 — retried on a later cycle
            log.error("upload failed for %s/%s/%s: %s", uid, day, clip_id, e)

    log.info("cycle done: %s (db: %s)", stats, st.stats())
    return stats


def _extract_clips(videos) -> list:
    """Pull clip entries out of the (dynamic, TBD) cloud_videos response shape."""
    if isinstance(videos, list):
        return videos
    if isinstance(videos, dict):
        for key in ("videos", "clips", "list", "data"):
            if isinstance(videos.get(key), list):
                return videos[key]
        # shape unknown: keep the raw entries for the log, return nothing yet
        log.warning("cloud_videos: unknown shape, raw: %s", str(videos)[:300])
    return []


def _clip_fields(clip, day_t0: int, day_t1: int) -> tuple[str, int, int]:
    """(clip_id, t0, t1) — field names TBD dynamically; several spellings tried."""
    if isinstance(clip, dict):
        clip_id = str(clip.get("id") or clip.get("videoId") or clip.get("video_id")
                      or clip.get("eventId") or clip.get("name") or
                      hash(str(sorted(clip.items()))))
        t0 = int(clip.get("t") or clip.get("t0") or clip.get("startTime")
                 or clip.get("start") or day_t0)
        t1 = int(clip.get("t1") or clip.get("endTime") or clip.get("end")
                 or (t0 + int(clip.get("d", clip.get("duration", 0))))
                 or day_t1)
        return clip_id, t0, t1
    clip_id = str(clip)
    return clip_id, day_t0, day_t1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true",
                        help="run one cycle and exit (external cron mode)")
    parser.add_argument("--interval", type=int,
                        help="seconds between cycles (overrides YIMIRROR_INTERVAL)")
    args = parser.parse_args()

    logging.basicConfig(
        level=os.environ.get("YIMIRROR_LOG", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    interval = args.interval or int(os.environ.get("YIMIRROR_INTERVAL", "1200"))
    lookback = int(os.environ.get("YIMIRROR_LOOKBACK_DAYS", "3"))
    keep_local = os.environ.get("YIMIRROR_KEEP_LOCAL", "0") == "1"

    st = store.Store(DATA_DIR)
    client = YiClient(region=os.environ.get("YI_REGION", "eu"))

    try:
        if not _login(client, st):
            sys.exit(1)
        while True:
            try:
                run_cycle(client, st, lookback, keep_local)
            except Exception as e:  # noqa: BLE001 — keep the loop alive
                log.error("cycle crashed: %s", e)
            if args.once:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        log.info("stopped")
    finally:
        st.close()


if __name__ == "__main__":
    main()
