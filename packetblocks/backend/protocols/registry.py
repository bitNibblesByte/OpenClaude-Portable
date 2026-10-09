"""
Protocol registry for PacketBlocks.

Each protocol is described declaratively as a list of fields. The frontend turns
these descriptions into draggable "blocks" (Scratch-style), and the backend turns
a stack of blocks into a real packet.

Two families of protocols live here:

  * "scapy"  -> layers that map directly onto a Scapy class. Building and parsing
               is delegated to Scapy, so we get the full power of its dissectors.
  * "raw"    -> unusual / specialist protocols that Scapy does not ship (ARINC 429,
               ARINC 664/AFDX, MIL-STD-1553, etc). These are packed/unpacked by the
               helpers in raw_protocols.py into a bytes blob that can be carried as
               a payload or written to a pcap for visualization.

A field descriptor is a dict:
    {
      "name":   machine name used in the block,
      "label":  human label shown in the UI,
      "type":   one of int | str | bytes | enum | ip | mac | flags,
      "default": default value (shown pre-filled in the block),
      "bits":   (raw protocols only) width in bits, used for bit-packing,
      "help":   short tooltip,
      "options": (enum/flags) list of [value, label] pairs,
    }
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
#  Common protocols, delegated to Scapy                                       #
# --------------------------------------------------------------------------- #

SCAPY_PROTOCOLS = {
    "Ether": {
        "label": "Ethernet",
        "category": "Link",
        "scapy_class": "Ether",
        "color": "#4C97FF",
        "fields": [
            {"name": "dst", "label": "Destination MAC", "type": "mac",
             "default": "ff:ff:ff:ff:ff:ff", "help": "Destination hardware address"},
            {"name": "src", "label": "Source MAC", "type": "mac",
             "default": "00:00:00:00:00:00", "help": "Source hardware address"},
            {"name": "type", "label": "EtherType", "type": "int",
             "default": 0x0800, "help": "Payload protocol (0x0800 = IPv4)"},
        ],
    },
    "Dot1Q": {
        "label": "802.1Q VLAN",
        "category": "Link",
        "scapy_class": "Dot1Q",
        "color": "#4C97FF",
        "fields": [
            {"name": "vlan", "label": "VLAN ID", "type": "int", "default": 1},
            {"name": "prio", "label": "Priority", "type": "int", "default": 0},
        ],
    },
    "ARP": {
        "label": "ARP",
        "category": "Link",
        "scapy_class": "ARP",
        "color": "#4C97FF",
        "fields": [
            {"name": "op", "label": "Operation", "type": "enum", "default": 1,
             "options": [[1, "who-has (request)"], [2, "is-at (reply)"]]},
            {"name": "hwsrc", "label": "Sender MAC", "type": "mac", "default": "00:00:00:00:00:00"},
            {"name": "psrc", "label": "Sender IP", "type": "ip", "default": "0.0.0.0"},
            {"name": "hwdst", "label": "Target MAC", "type": "mac", "default": "00:00:00:00:00:00"},
            {"name": "pdst", "label": "Target IP", "type": "ip", "default": "0.0.0.0"},
        ],
    },
    "IP": {
        "label": "IPv4",
        "category": "Network",
        "scapy_class": "IP",
        "color": "#9966FF",
        "fields": [
            {"name": "version", "label": "Version", "type": "int", "default": 4},
            {"name": "ttl", "label": "TTL", "type": "int", "default": 64, "bits": 8},
            {"name": "proto", "label": "Protocol", "type": "enum", "default": 6,
             "options": [[1, "ICMP"], [6, "TCP"], [17, "UDP"], [132, "SCTP"]]},
            {"name": "src", "label": "Source IP", "type": "ip", "default": "127.0.0.1"},
            {"name": "dst", "label": "Destination IP", "type": "ip", "default": "127.0.0.1"},
            {"name": "flags", "label": "Flags", "type": "flags", "default": [],
             "options": [["MF", "More Fragments"], ["DF", "Don't Fragment"], ["evil", "Reserved"]]},
        ],
    },
    "IPv6": {
        "label": "IPv6",
        "category": "Network",
        "scapy_class": "IPv6",
        "color": "#9966FF",
        "fields": [
            {"name": "hlim", "label": "Hop Limit", "type": "int", "default": 64, "bits": 8},
            {"name": "src", "label": "Source IP", "type": "str", "default": "::1"},
            {"name": "dst", "label": "Destination IP", "type": "str", "default": "::1"},
        ],
    },
    "ICMP": {
        "label": "ICMP",
        "category": "Network",
        "scapy_class": "ICMP",
        "color": "#9966FF",
        "fields": [
            {"name": "type", "label": "Type", "type": "enum", "default": 8,
             "options": [[0, "echo-reply"], [8, "echo-request"], [3, "dest-unreachable"],
                         [11, "time-exceeded"]]},
            {"name": "code", "label": "Code", "type": "int", "default": 0},
        ],
    },
    "TCP": {
        "label": "TCP",
        "category": "Transport",
        "scapy_class": "TCP",
        "color": "#FFAB19",
        "fields": [
            {"name": "sport", "label": "Source Port", "type": "int", "default": 1024, "bits": 16},
            {"name": "dport", "label": "Dest Port", "type": "int", "default": 80, "bits": 16},
            {"name": "seq", "label": "Sequence", "type": "int", "default": 0},
            {"name": "ack", "label": "Ack", "type": "int", "default": 0},
            {"name": "flags", "label": "Flags", "type": "flags", "default": ["S"],
             "options": [["F", "FIN"], ["S", "SYN"], ["R", "RST"], ["P", "PSH"],
                         ["A", "ACK"], ["U", "URG"], ["E", "ECE"], ["C", "CWR"]]},
            {"name": "window", "label": "Window", "type": "int", "default": 8192, "bits": 16},
        ],
    },
    "UDP": {
        "label": "UDP",
        "category": "Transport",
        "scapy_class": "UDP",
        "color": "#FFAB19",
        "fields": [
            {"name": "sport", "label": "Source Port", "type": "int", "default": 1024, "bits": 16},
            {"name": "dport", "label": "Dest Port", "type": "int", "default": 53, "bits": 16},
        ],
    },
    "SCTP": {
        "label": "SCTP",
        "category": "Transport",
        "scapy_class": "SCTP",
        "color": "#FFAB19",
        "fields": [
            {"name": "sport", "label": "Source Port", "type": "int", "default": 1024, "bits": 16},
            {"name": "dport", "label": "Dest Port", "type": "int", "default": 80, "bits": 16},
        ],
    },
    "DNS": {
        "label": "DNS",
        "category": "Application",
        "scapy_class": "DNS",
        "color": "#40BF4A",
        "fields": [
            {"name": "qr", "label": "Query/Response", "type": "enum", "default": 0,
             "options": [[0, "query"], [1, "response"]]},
            {"name": "qd_qname", "label": "Question Name", "type": "str", "default": "example.com",
             "help": "Convenience: builds a DNSQR for this name"},
        ],
        "custom_build": "dns",
    },
    "Raw": {
        "label": "Raw Payload",
        "category": "Application",
        "scapy_class": "Raw",
        "color": "#40BF4A",
        "fields": [
            {"name": "load", "label": "Bytes / text", "type": "bytes", "default": "hello",
             "help": "Text, or \\xNN hex escapes, or 0x.. hex string"},
        ],
    },
}


def all_protocols():
    """Return the merged protocol catalogue (scapy + raw) for the frontend."""
    from . import raw_protocols

    catalogue = {}
    for name, spec in SCAPY_PROTOCOLS.items():
        catalogue[name] = {**spec, "family": "scapy", "name": name}
    for name, spec in raw_protocols.RAW_PROTOCOLS.items():
        catalogue[name] = {**spec, "family": "raw", "name": name}
    return catalogue
