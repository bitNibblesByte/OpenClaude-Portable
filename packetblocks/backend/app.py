"""
PacketBlocks backend — a small Flask API behind the Scratch-style visual editor.

Endpoints
---------
  GET  /api/protocols            -> the block catalogue (common + specialist)
  POST /api/build                -> block stack  -> {hex, summary, layers, length}
  POST /api/import-pcap          -> uploaded .pcap/.pcapng -> list of block stacks
  POST /api/export-pcap          -> list of block stacks -> downloadable .pcap
  POST /api/fuzz                  -> base stack + rules   -> mutated stacks (+ hex)
  POST /api/send                  -> transmit built packets on an interface
                                      (disabled unless PACKETBLOCKS_ALLOW_SEND=1)
  GET  /api/interfaces            -> interfaces available for sending
  GET  /healthz                   -> health probe

Sending real frames is OFF by default. It is meant for use only against networks
and devices you own or are explicitly authorized to test; the container must be
started with --cap-add=NET_RAW --net=host and PACKETBLOCKS_ALLOW_SEND=1 before the
endpoint will do anything.
"""

from __future__ import annotations

import io
import os
import tempfile

from flask import Flask, jsonify, request, send_file, send_from_directory
from scapy.all import rdpcap, wrpcap

import builder
import fuzzer
from protocols import raw_protocols
from protocols.registry import all_protocols

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
ALLOW_SEND = os.environ.get("PACKETBLOCKS_ALLOW_SEND") == "1"
MAX_SEND = int(os.environ.get("PACKETBLOCKS_MAX_SEND", "500"))

app = Flask(__name__, static_folder=None)


# --------------------------------------------------------------------------- #
#  Static frontend                                                            #
# --------------------------------------------------------------------------- #

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(FRONTEND_DIR, path)


# --------------------------------------------------------------------------- #
#  API                                                                        #
# --------------------------------------------------------------------------- #

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "send_enabled": ALLOW_SEND})


@app.get("/api/protocols")
def protocols():
    return jsonify(all_protocols())


def _describe_built(pkt, stack):
    raw = bytes(pkt)
    layers = []
    for block in stack:
        if block["proto"] in raw_protocols.RAW_PROTOCOLS:
            packed = raw_protocols.pack(block["proto"], block.get("fields", {}))
            layers.append({
                "proto": block["proto"],
                "decoded": raw_protocols.describe(block["proto"], packed),
            })
        else:
            layers.append({"proto": block["proto"]})
    return {
        "hex": raw.hex(),
        "length": len(raw),
        "summary": pkt.summary(),
        "layers": layers,
    }


@app.post("/api/build")
def build():
    data = request.get_json(force=True)
    stack = data.get("stack", [])
    try:
        pkt = builder.build_packet(stack)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(_describe_built(pkt, stack))


@app.post("/api/import-pcap")
def import_pcap():
    if "file" not in request.files:
        return jsonify({"error": "no file uploaded (field name must be 'file')"}), 400
    upload = request.files["file"]
    limit = int(request.form.get("limit", "200"))

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        upload.save(tmp.name)
        tmp_path = tmp.name
    try:
        packets = rdpcap(tmp_path)
    except Exception as exc:
        return jsonify({"error": f"could not parse capture: {exc}"}), 400
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    out = []
    for pkt in list(packets)[:limit]:
        try:
            out.append(builder.packet_to_stack(pkt))
        except Exception as exc:
            out.append({"error": str(exc), "summary": repr(pkt)[:120]})
    return jsonify({"count": len(out), "total_in_file": len(packets), "packets": out})


@app.post("/api/export-pcap")
def export_pcap():
    data = request.get_json(force=True)
    stacks = data.get("stacks", [])
    packets = []
    for stack in stacks:
        try:
            packets.append(builder.build_packet(stack))
        except Exception as exc:
            return jsonify({"error": f"stack failed to build: {exc}"}), 400
    if not packets:
        return jsonify({"error": "no packets to export"}), 400

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = tmp.name
    wrpcap(tmp_path, packets)
    with open(tmp_path, "rb") as fh:
        blob = fh.read()
    os.unlink(tmp_path)
    return send_file(io.BytesIO(blob), mimetype="application/vnd.tcpdump.pcap",
                     as_attachment=True, download_name="packetblocks_export.pcap")


@app.post("/api/fuzz")
def fuzz_endpoint():
    data = request.get_json(force=True)
    base = data.get("stack", [])
    rules = data.get("rules", [])
    count = min(int(data.get("count", 20)), 1000)
    seed = data.get("seed")

    cases = fuzzer.fuzz(base, rules, count=count, seed=seed)
    # Attach a built hex preview to each case so the UI can show it immediately.
    for case in cases:
        try:
            pkt = builder.build_packet(case["stack"])
            case["hex"] = bytes(pkt).hex()
            case["summary"] = pkt.summary()
            case["length"] = len(bytes(pkt))
        except Exception as exc:
            case["error"] = str(exc)
    return jsonify({"count": len(cases), "cases": cases})


@app.get("/api/interfaces")
def interfaces():
    try:
        from scapy.all import get_if_list
        return jsonify({"interfaces": get_if_list(), "send_enabled": ALLOW_SEND})
    except Exception as exc:
        return jsonify({"interfaces": [], "error": str(exc), "send_enabled": ALLOW_SEND})


@app.post("/api/send")
def send():
    """
    Transmit built packets. Off unless PACKETBLOCKS_ALLOW_SEND=1 in the container.
    Intended for authorized testing against your own equipment only.
    """
    if not ALLOW_SEND:
        return jsonify({
            "error": "sending is disabled. Start the container with "
                     "PACKETBLOCKS_ALLOW_SEND=1 (and --cap-add=NET_RAW --net=host) "
                     "to transmit, and only against networks you are authorized to test."
        }), 403

    data = request.get_json(force=True)
    stacks = data.get("stacks", [])
    iface = data.get("iface")
    count = min(int(data.get("count", 1)), MAX_SEND)

    if len(stacks) * count > MAX_SEND:
        return jsonify({"error": f"refusing to send more than {MAX_SEND} frames"}), 400

    try:
        from scapy.all import sendp, send as l3send
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    sent = 0
    for stack in stacks:
        pkt = builder.build_packet(stack)
        has_l2 = stack and stack[0]["proto"] in ("Ether", "Dot1Q", "ARP")
        try:
            if has_l2:
                sendp(pkt, iface=iface, count=count, verbose=False)
            else:
                l3send(pkt, count=count, verbose=False)
            sent += count
        except Exception as exc:
            return jsonify({"error": str(exc), "sent": sent}), 500
    return jsonify({"sent": sent, "iface": iface})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8089"))
    app.run(host="0.0.0.0", port=port, debug=bool(os.environ.get("PACKETBLOCKS_DEBUG")))
