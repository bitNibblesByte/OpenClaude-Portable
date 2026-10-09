# PacketBlocks — visual packet crafting & fuzzing with Scapy.
# Single image, runs the same on Windows, macOS and Linux via Docker.
FROM python:3.12-slim

# libpcap is what Scapy uses for sniffing / sending on a real interface.
# tcpdump is handy inside the container for capturing pcaps to import.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY samples/ ./samples/

EXPOSE 8089

ENV PORT=8089
# Sending real frames is OFF by default. Opt in at run time (see README) and only
# against networks/devices you own or are authorized to test.
ENV PACKETBLOCKS_ALLOW_SEND=0

WORKDIR /app/backend
CMD ["python", "app.py"]
