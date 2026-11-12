# yimirror — Yi cloud recording mirror
# python:3.12-slim + ffmpeg (remux) + rclone (upload to personal cloud)
FROM python:3.12-slim

# ffmpeg
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# rclone (official install script pins the latest release)
RUN curl -fsSL https://rclone.org/install.sh | bash

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# data dir: sqlite state + pending recordings
RUN mkdir -p /data/pending
ENV YIMIRROR_DATA_DIR=/data

ENTRYPOINT ["python", "-m", "src.main"]
CMD []
