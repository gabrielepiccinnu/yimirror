"""Upload via rclone to the personal cloud (Backblaze B2 default).

The B2 remote is configured entirely from env (RCLONE_CONFIG_B2_TYPE/ACCOUNT/KEY),
so no config file is needed and no secret touches disk inside the container.
"""

from __future__ import annotations

import logging
import os
import subprocess

log = logging.getLogger("yimirror")

RCLONE = os.environ.get("YIMIRROR_RCLONE", "rclone")


def upload_file(local_path: str, dest_rel: str, bucket: str | None = None,
                remote_name: str = "b2") -> str:
    """rclone copy local_path -> {remote}:{bucket}/yi-home/{dest_rel}.

    Returns the destination path. Raises RuntimeError on rclone failure.
    """
    bucket = bucket or os.environ.get("B2_BUCKET")
    if not bucket:
        raise RuntimeError("B2_BUCKET not set")
    dest = f"{remote_name}:{bucket}/yi-home/{dest_rel}"
    cmd = [RCLONE, "copy", "--retries", "3", "--low-level-retries", "5",
           local_path, dest]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"rclone failed: {proc.stderr[-400:]}")
    log.info("uploaded %s -> %s", local_path, dest)
    return dest
