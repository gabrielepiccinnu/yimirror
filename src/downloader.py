"""Clip downloader: ts metadata -> segments -> ffmpeg remux to MP4.

Mirrors the app's CloudVideoManager pipeline (im/r2.java):
1. GET /vas/v8/cloud/ts/metadata -> [{t, d, b}, ...]
2. each segment downloaded over HTTP (URL template is a dynamic open question,
   configurable via YIMIRROR_TS_URL_TEMPLATE)
3. ffmpeg concat demuxer remuxes the segments into one MP4 (copy, no re-encode)
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

log = logging.getLogger("yimirror")

TS_URL_TEMPLATE = os.environ.get(
    "YIMIRROR_TS_URL_TEMPLATE",
    # placeholders: {uid} {t} {d}; real CDN pattern confirmed dynamically (findings §6)
    "https://example.invalid/{uid}/{t}.ts",
)
MAX_SEGMENT_WORKERS = int(os.environ.get("YIMIRROR_SEGMENT_WORKERS", "4"))


def _segment_url(uid: str, seg: dict) -> str:
    return TS_URL_TEMPLATE.format(uid=uid, t=int(seg.get("t", 0)), d=seg.get("d", 0))


def _download_one(url: str, dest: Path, timeout: int = 60) -> Path:
    with requests.get(url, stream=True, timeout=timeout) as r:
        r.raise_for_status()
        with open(dest, "wb") as f:
            for chunk in r.iter_content(64 * 1024):
                f.write(chunk)
    return dest


def _remux(workdir: Path, dest_mp4: Path) -> None:
    """Concat the segments (workdir/*.ts, numeric order) into one MP4."""
    segments = sorted(workdir.glob("*.ts"), key=lambda p: int(p.stem))
    if not segments:
        raise RuntimeError("no segments downloaded")
    list_file = workdir / "concat.txt"
    with open(list_file, "w") as f:
        for seg in segments:
            f.write(f"file '{seg.name}'\n")
    cmd = ["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0",
           "-i", str(list_file), "-c", "copy", str(dest_mp4)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"ffmpeg failed: {proc.stderr[-400:]}")


def download_clip(client, uid: str, t0: int, t1: int,
                  dest_mp4: Path, speed: int = 1, ipc_type: int = 0) -> None:
    """Fetch metadata, pull all segments, remux to dest_mp4."""
    segments = client.ts_metadata(uid, t0, t1, speed=speed, ipc_type=ipc_type)
    if not segments:
        raise RuntimeError("ts_metadata returned no segments")

    dest_mp4.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="yimirror-") as tmp:
        workdir = Path(tmp)
        tasks = []
        with ThreadPoolExecutor(max_workers=MAX_SEGMENT_WORKERS) as pool:
            for i, seg in enumerate(segments):
                url = _segment_url(uid, seg)
                if url.startswith("https://example.invalid"):
                    raise RuntimeError(
                        "YIMIRROR_TS_URL_TEMPLATE not configured (dynamic step pending)"
                    )
                tasks.append(pool.submit(_download_one, url, workdir / f"{i:06d}.ts"))
            for fut in as_completed(tasks):
                fut.result()  # propagate errors
        _remux(workdir, dest_mp4)
    log.info("clip downloaded: %s (%.1f MB)", dest_mp4.name,
             dest_mp4.stat().st_size / 1e6)


def local_cleanup(path: str, keep: bool) -> None:
    if not keep and path and os.path.exists(path):
        os.remove(path)
