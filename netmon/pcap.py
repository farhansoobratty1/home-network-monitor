"""Read (and write) classic .pcap files and decode IPv4 TCP/UDP/ICMP packets.

Written from the file-format specs with only the standard library, so there is nothing
to install. Supports the link types that Wireshark, tcpdump and most home-lab tools save:
Ethernet, raw IPv4 and Linux "cooked" captures.
"""
import ipaddress
import struct
from dataclasses import dataclass

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

# TCP flag bits
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass(frozen=True)
class Packet:
    ts: float          # seconds since the epoch
    src: str
    dst: str
    proto: str         # "TCP", "UDP", "ICMP" or "IP/<n>"
    sport: int | None
    dport: int | None
    flags: int         # TCP flags, 0 for other protocols
    length: int        # bytes on the wire

    @property
    def is_syn(self):
        """A connection attempt: SYN set, ACK not set."""
        return self.proto == "TCP" and self.flags & SYN and not self.flags & ACK


class PcapError(ValueError):
    pass


def read_pcap(path):
    """Yield a Packet for every IPv4 packet in the file. Other traffic (ARP, IPv6...) is skipped."""
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            raise PcapError("file is too short to be a pcap")
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        elif magic == b"\x0a\x0d\x0d\x0a":
            raise PcapError("this is a pcapng file; save it as 'Wireshark/tcpdump - pcap' instead")
        else:
            raise PcapError("not a pcap file")
        nanos = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF

        record = struct.Struct(endian + "IIII")
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl_len, orig_len = record.unpack(rec)
            data = f.read(incl_len)
            if len(data) < incl_len:
                return                                  # truncated final packet
            ts = sec + frac / (1e9 if nanos else 1e6)
            ip = _strip_link_layer(data, linktype)
            if ip is not None:
                pkt = decode_ipv4(ip, ts, orig_len)
                if pkt is not None:
                    yield pkt


def _strip_link_layer(data, linktype):
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        ethertype = struct.unpack("!H", data[12:14])[0]
        offset = 14
        if ethertype == 0x8100 and len(data) >= 18:     # 802.1Q VLAN tag
            ethertype = struct.unpack("!H", data[16:18])[0]
            offset = 18
        return data[offset:] if ethertype == 0x0800 else None
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4):
        return data if data and data[0] >> 4 == 4 else None
    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16 or struct.unpack("!H", data[14:16])[0] != 0x0800:
            return None
        return data[16:]
    raise PcapError(f"unsupported link type {linktype}")


def decode_ipv4(ip, ts=0.0, wire_len=None):
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto_num = ip[9]
    src = str(ipaddress.IPv4Address(ip[12:16]))
    dst = str(ipaddress.IPv4Address(ip[16:20]))
    payload = ip[ihl:]
    sport = dport = None
    flags = 0
    if proto_num in (6, 17) and len(payload) >= 4:
        sport, dport = struct.unpack("!HH", payload[:4])
        if proto_num == 6 and len(payload) >= 14:
            flags = payload[13]
    return Packet(ts, src, dst, PROTO_NAMES.get(proto_num, f"IP/{proto_num}"),
                  sport, dport, flags, wire_len if wire_len is not None else len(ip))


# --- writing, used for the demo capture and the tests --------------------------

def build_ipv4(src, dst, proto, sport=0, dport=0, flags=0, payload=b""):
    proto_num = {"TCP": 6, "UDP": 17, "ICMP": 1}[proto]
    if proto == "TCP":
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload
    elif proto == "UDP":
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    else:
        l4 = struct.pack("!BBHI", 8, 0, 0, 0) + payload       # echo request
    total = 20 + len(l4)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto_num, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return header + l4


def write_pcap(path, frames):
    """frames: iterable of (timestamp, ipv4_bytes). Written as Ethernet frames."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts, ip in frames:
            frame = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + ip
            sec = int(ts)
            f.write(struct.pack("<IIII", sec, int(round((ts - sec) * 1e6)), len(frame), len(frame)))
            f.write(frame)
