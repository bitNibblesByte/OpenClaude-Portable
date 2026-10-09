"""
Specialist / uncommon protocols that Scapy does not ship out of the box.

These are the kind of buses you find in avionics, defense and industrial systems
rather than on a home network. Each has a declarative field list (so the frontend
can render blocks for it) and a `pack()` / `unpack()` implementation so a block
stack can be turned into real bytes — which can then be visualized, written into a
pcap, or carried as the payload of an Ethernet/UDP frame (e.g. ARINC 664 is
literally UDP-over-Ethernet).

Everything here is pure-Python bit/byte packing. Nothing here transmits on a
physical bus; the output is a bytes object.
"""

from __future__ import annotations

import struct

# --------------------------------------------------------------------------- #
#  Descriptors                                                                #
# --------------------------------------------------------------------------- #

RAW_PROTOCOLS = {
    "ARINC429": {
        "label": "ARINC 429 word",
        "category": "Avionics",
        "color": "#FF6680",
        "help": "32-bit avionics data word: label + SDI + data + SSM + parity",
        "fields": [
            {"name": "label", "label": "Label (octal)", "type": "int", "default": 0o205, "bits": 8,
             "help": "8-bit equipment label, conventionally written in octal"},
            {"name": "sdi", "label": "SDI", "type": "int", "default": 0, "bits": 2,
             "help": "Source/Destination Identifier (2 bits)"},
            {"name": "data", "label": "Data", "type": "int", "default": 0, "bits": 19,
             "help": "19-bit data field (BNR/BCD/discrete)"},
            {"name": "ssm", "label": "SSM", "type": "int", "default": 3, "bits": 2,
             "help": "Sign/Status Matrix (2 bits)"},
            {"name": "parity", "label": "Parity", "type": "enum", "default": -1, "bits": 1,
             "options": [[-1, "auto (odd)"], [0, "force 0"], [1, "force 1"]],
             "help": "Bit 32. 'auto' computes odd parity over the word."},
        ],
    },
    "ARINC664": {
        "label": "ARINC 664 / AFDX",
        "category": "Avionics",
        "color": "#FF6680",
        "help": "AFDX frame identity: Virtual Link ID + sequence number. Rides on "
                "UDP/IP/Ethernet, so stack it under those blocks.",
        "fields": [
            {"name": "vlid", "label": "Virtual Link ID", "type": "int", "default": 0x0001, "bits": 16,
             "help": "16-bit Virtual Link identifier (part of the dst MAC 03:00:00:00:VV:VV)"},
            {"name": "network", "label": "Network", "type": "enum", "default": 0, "bits": 1,
             "options": [[0, "A"], [1, "B"]], "help": "Redundant network A or B"},
            {"name": "payload", "label": "Payload", "type": "bytes", "default": "",
             "help": "Application payload bytes"},
            {"name": "seqnum", "label": "Sequence #", "type": "int", "default": 0, "bits": 8,
             "help": "AFDX sequence number appended as the final octet (wraps 1..255)"},
        ],
    },
    "MIL1553": {
        "label": "MIL-STD-1553 command",
        "category": "Avionics",
        "color": "#FF6680",
        "help": "1553 command word: RT address, T/R bit, subaddress, word count",
        "fields": [
            {"name": "rt", "label": "RT address", "type": "int", "default": 1, "bits": 5},
            {"name": "tr", "label": "T/R bit", "type": "enum", "default": 1, "bits": 1,
             "options": [[0, "receive"], [1, "transmit"]]},
            {"name": "sa", "label": "Subaddress", "type": "int", "default": 1, "bits": 5},
            {"name": "wc", "label": "Word count / mode", "type": "int", "default": 1, "bits": 5},
        ],
    },
    "CAN": {
        "label": "CAN bus frame",
        "category": "Industrial",
        "color": "#FF8C19",
        "help": "Controller Area Network frame (SocketCAN-compatible layout)",
        "fields": [
            {"name": "can_id", "label": "CAN ID", "type": "int", "default": 0x123, "bits": 29},
            {"name": "extended", "label": "Extended (29-bit) ID", "type": "enum", "default": 0, "bits": 1,
             "options": [[0, "no (11-bit)"], [1, "yes (29-bit)"]]},
            {"name": "data", "label": "Data (<=8 bytes)", "type": "bytes", "default": "0011223344556677"},
        ],
    },
    "Modbus": {
        "label": "Modbus/TCP",
        "category": "Industrial",
        "color": "#FF8C19",
        "help": "Modbus application PDU over TCP (stack under TCP, dport 502)",
        "fields": [
            {"name": "transid", "label": "Transaction ID", "type": "int", "default": 1, "bits": 16},
            {"name": "unitid", "label": "Unit ID", "type": "int", "default": 1, "bits": 8},
            {"name": "func", "label": "Function", "type": "enum", "default": 3, "bits": 8,
             "options": [[1, "Read Coils"], [3, "Read Holding Registers"],
                         [6, "Write Single Register"], [16, "Write Multiple Registers"]]},
            {"name": "payload", "label": "Data", "type": "bytes", "default": "00000001"},
        ],
    },
    "ProfinetRT": {
        "label": "PROFINET RT",
        "category": "Industrial",
        "color": "#FF8C19",
        "help": "PROFINET real-time cyclic frame (EtherType 0x8892). Stack under Ethernet.",
        "fields": [
            {"name": "frameid", "label": "Frame ID", "type": "int", "default": 0x8000, "bits": 16},
            {"name": "data", "label": "Cyclic data", "type": "bytes", "default": ""},
            {"name": "cycle", "label": "Cycle counter", "type": "int", "default": 0, "bits": 16},
        ],
    },
}


# --------------------------------------------------------------------------- #
#  Packers                                                                     #
# --------------------------------------------------------------------------- #

def _odd_parity(value: int, width: int) -> int:
    """Return the parity bit that makes the total number of 1s odd over `width` bits."""
    ones = bin(value & ((1 << width) - 1)).count("1")
    return 0 if (ones % 2 == 1) else 1


def _coerce_bytes(value) -> bytes:
    """Accept text, hex strings (with or without 0x / spaces), or raw bytes."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if value is None:
        return b""
    s = str(value).strip()
    if not s:
        return b""
    compact = s.replace("0x", "").replace(" ", "").replace(":", "")
    if compact and all(c in "0123456789abcdefABCDEF" for c in compact) and len(compact) % 2 == 0:
        try:
            return bytes.fromhex(compact)
        except ValueError:
            pass
    return s.encode("latin-1", errors="replace")


def pack(name: str, fields: dict) -> bytes:
    """Serialize a raw protocol block into bytes."""
    if name == "ARINC429":
        label = int(fields.get("label", 0)) & 0xFF
        sdi = int(fields.get("sdi", 0)) & 0x3
        data = int(fields.get("data", 0)) & 0x7FFFF
        ssm = int(fields.get("ssm", 0)) & 0x3
        parity_choice = int(fields.get("parity", -1))

        # Bit layout (LSB-first transmission order): bits 1-8 label, 9-10 SDI,
        # 11-29 data, 30-31 SSM, 32 parity.
        word = label | (sdi << 8) | (data << 10) | (ssm << 29)
        if parity_choice < 0:
            pbit = _odd_parity(word, 31)
        else:
            pbit = parity_choice & 1
        word |= (pbit << 31)
        return struct.pack("<I", word)

    if name == "ARINC664":
        payload = _coerce_bytes(fields.get("payload", b""))
        seqnum = int(fields.get("seqnum", 0)) & 0xFF
        # AFDX appends a 1-byte sequence number to the payload before UDP.
        return payload + bytes([seqnum])

    if name == "MIL1553":
        rt = int(fields.get("rt", 0)) & 0x1F
        tr = int(fields.get("tr", 0)) & 0x1
        sa = int(fields.get("sa", 0)) & 0x1F
        wc = int(fields.get("wc", 0)) & 0x1F
        word = (rt << 11) | (tr << 10) | (sa << 5) | wc
        return struct.pack(">H", word)

    if name == "CAN":
        can_id = int(fields.get("can_id", 0))
        extended = int(fields.get("extended", 0))
        data = _coerce_bytes(fields.get("data", b""))[:8]
        if extended:
            can_id = (can_id & 0x1FFFFFFF) | 0x80000000
        else:
            can_id &= 0x7FF
        frame = struct.pack("<IB", can_id, len(data)) + b"\x00\x00\x00"
        frame += data + b"\x00" * (8 - len(data))
        return frame

    if name == "Modbus":
        transid = int(fields.get("transid", 0)) & 0xFFFF
        unitid = int(fields.get("unitid", 0)) & 0xFF
        func = int(fields.get("func", 0)) & 0xFF
        payload = _coerce_bytes(fields.get("payload", b""))
        length = 2 + len(payload)  # unit id + function + data
        return struct.pack(">HHHBB", transid, 0, length, unitid, func) + payload

    if name == "ProfinetRT":
        frameid = int(fields.get("frameid", 0)) & 0xFFFF
        data = _coerce_bytes(fields.get("data", b""))
        cycle = int(fields.get("cycle", 0)) & 0xFFFF
        # FrameID + data + cycle counter + data-status + transfer-status
        return struct.pack(">H", frameid) + data + struct.pack(">HBB", cycle, 0x35, 0x00)

    raise ValueError(f"Unknown raw protocol: {name}")


def describe(name: str, raw: bytes) -> dict:
    """Best-effort decode of packed bytes back into fields (for the inspector)."""
    out = {"hex": raw.hex(), "length": len(raw)}
    try:
        if name == "ARINC429" and len(raw) == 4:
            word = struct.unpack("<I", raw)[0]
            out.update({
                "label_octal": oct(word & 0xFF),
                "sdi": (word >> 8) & 0x3,
                "data": (word >> 10) & 0x7FFFF,
                "ssm": (word >> 29) & 0x3,
                "parity": (word >> 31) & 0x1,
            })
        elif name == "MIL1553" and len(raw) == 2:
            word = struct.unpack(">H", raw)[0]
            out.update({
                "rt": (word >> 11) & 0x1F,
                "tr": (word >> 10) & 0x1,
                "sa": (word >> 5) & 0x1F,
                "wc": word & 0x1F,
            })
    except Exception:  # pragma: no cover - decode is best-effort
        pass
    return out
