"""
Turn a block stack (list of layer dicts, top of the network stack first) into a
real packet, and turn captured packets back into block stacks for display.

A block stack looks like:

    [
      {"proto": "Ether", "fields": {"dst": "...", "type": 2048}},
      {"proto": "IP",    "fields": {"src": "10.0.0.1", "dst": "10.0.0.2"}},
      {"proto": "TCP",   "fields": {"dport": 80, "flags": ["S"]}},
      {"proto": "Raw",   "fields": {"load": "GET / HTTP/1.0\\r\\n\\r\\n"}},
    ]

Scapy layers are composed with '/'. Raw/specialist layers are packed to bytes and
appended as a Raw payload so the whole thing stays a single sendable/visualizable
packet.
"""

from __future__ import annotations

from scapy.all import (  # noqa: F401  (names resolved dynamically)
    Ether, Dot1Q, ARP, IP, IPv6, ICMP, TCP, UDP, SCTP, DNS, DNSQR, Raw,
)
from scapy.all import Packet

from protocols import raw_protocols
from protocols.registry import SCAPY_PROTOCOLS

_SCAPY_CLASSES = {
    "Ether": Ether, "Dot1Q": Dot1Q, "ARP": ARP, "IP": IP, "IPv6": IPv6,
    "ICMP": ICMP, "TCP": TCP, "UDP": UDP, "SCTP": SCTP, "DNS": DNS, "Raw": Raw,
}


def _coerce_field(ftype: str, value):
    """Convert a value coming from JSON into what Scapy expects."""
    if ftype == "int":
        if isinstance(value, str):
            value = value.strip()
            return int(value, 0) if value else 0
        return int(value)
    if ftype == "bytes":
        return raw_protocols._coerce_bytes(value)
    if ftype == "flags":
        # Scapy accepts a '+'-joined string or a list for FlagsField.
        if isinstance(value, (list, tuple)):
            return "+".join(str(v) for v in value) if value else 0
        return value
    return value


def _build_scapy_layer(proto: str, fields: dict) -> Packet:
    spec = SCAPY_PROTOCOLS[proto]
    cls = _SCAPY_CLASSES[proto]

    # Special-cased convenience builders.
    if spec.get("custom_build") == "dns":
        qname = fields.get("qd_qname", "example.com")
        qr = int(fields.get("qr", 0))
        return DNS(qr=qr, qd=DNSQR(qname=qname), rd=1)

    kwargs = {}
    field_types = {f["name"]: f["type"] for f in spec["fields"]}
    for key, val in (fields or {}).items():
        if key not in field_types:
            continue
        if val is None or val == "":
            continue
        kwargs[key] = _coerce_field(field_types[key], val)

    if proto == "Raw":
        return Raw(load=kwargs.get("load", b""))
    return cls(**kwargs)


def build_packet(stack: list) -> Packet:
    """Compose a block stack into a single Scapy packet."""
    if not stack:
        raise ValueError("Empty block stack")

    layers = []
    for block in stack:
        proto = block["proto"]
        fields = block.get("fields", {})
        if proto in _SCAPY_CLASSES or proto == "DNS":
            layers.append(_build_scapy_layer(proto, fields))
        elif proto in raw_protocols.RAW_PROTOCOLS:
            blob = raw_protocols.pack(proto, fields)
            layers.append(Raw(load=blob))
        else:
            raise ValueError(f"Unknown protocol in stack: {proto}")

    packet = layers[0]
    for layer in layers[1:]:
        packet = packet / layer
    return packet


def packet_to_stack(pkt: Packet) -> dict:
    """Decompose a captured Scapy packet into a block stack + a text summary."""
    stack = []
    layer = pkt
    while layer:
        name = layer.__class__.__name__
        if name in SCAPY_PROTOCOLS:
            spec = SCAPY_PROTOCOLS[name]
            fields = {}
            for fdesc in spec["fields"]:
                fname = fdesc["name"]
                if fname in ("qd_qname",):
                    continue
                try:
                    val = layer.getfieldval(fname)
                except Exception:
                    continue
                if isinstance(val, bytes):
                    val = val.decode("latin-1", errors="replace")
                elif hasattr(val, "__iter__") and not isinstance(val, str):
                    val = list(val)
                fields[fname] = val
            stack.append({"proto": name, "fields": fields})
        elif name == "Raw":
            load = bytes(layer.load)
            stack.append({"proto": "Raw", "fields": {"load": load.hex()},
                          "note": "raw bytes (hex)"})
        # Move to the payload layer.
        layer = layer.payload if layer.payload else None
        if layer is not None and layer.__class__.__name__ == "NoPayload":
            break
    return {"stack": stack, "summary": pkt.summary(), "length": len(bytes(pkt))}
