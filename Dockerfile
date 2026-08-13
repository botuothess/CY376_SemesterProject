# distributed_ids — single image used for both the collector and the
# simulated sensor agents (docker-compose runs it twice with different
# commands). Kept as one image so there's only one thing to build.

FROM python:3.12-slim

WORKDIR /app

# System deps: libpcap is needed only if someone later runs a --mode live
# sensor with scapy inside the container. Cheap to include, keeps the
# image usable for that case without a rebuild.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Collector's default port (see config.yaml)
EXPOSE 5000

# No CMD here on purpose — docker-compose.yml sets the command per
# service (collector vs. simulator). Running the image with no override
# just starts the collector, which is the sensible default.
CMD ["python", "collector/app.py"]
