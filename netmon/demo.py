"""Generate a synthetic home-network capture with some attacks mixed into normal traffic.

Everything here is made up: the "internet" addresses come from the documentation ranges
(198.51.100.0/24 and 203.0.113.0/24), which never appear on the real internet.
"""
import random

from .pcap import ACK, PSH, SYN, build_ipv4, write_pcap

ROUTER, LAPTOP, PHONE, TV, PLUG, ATTACKER = (
    "192.168.1.1", "192.168.1.20", "192.168.1.21", "192.168.1.30", "192.168.1.45", "192.168.1.66")
WEB = ["198.51.100.10", "198.51.100.11", "198.51.100.12", "203.0.113.80"]


def demo_frames(start=1_764_000_000.0, seed=42):
    rng = random.Random(seed)
    frames = []

    def add(t, *args, **kw):
        frames.append((start + t, build_ipv4(*args, **kw)))

    # --- 2 minutes of normal background traffic -------------------------------------
    for i in range(240):
        t = i * 0.5 + rng.random() * 0.3
        client = rng.choice([LAPTOP, PHONE, TV])
        server = rng.choice(WEB)
        port = rng.randint(49152, 65535)
        add(t, client, ROUTER, "UDP", port, 53, payload=b"\x00" * 30)                 # DNS lookup
        add(t + 0.02, client, server, "TCP", port, 443, SYN)                           # HTTPS
        add(t + 0.05, server, client, "TCP", 443, port, SYN | ACK)
        add(t + 0.06, client, server, "TCP", port, 443, ACK | PSH, payload=b"\x17" * 400)
    add(5.0, TV, "203.0.113.123", "UDP", 50123, 123, payload=b"\x1b" + b"\x00" * 47)  # NTP

    # --- attack 1: a compromised device port-scans the laptop (ports 1-100 in 3 s) ------
    for i, port in enumerate(range(1, 101)):
        add(30 + i * 0.03, ATTACKER, LAPTOP, "TCP", 40000 + i, port, SYN)

    # --- attack 2: it then sweeps the network for SSH ----------------------------------
    for host in range(2, 40):
        add(45 + host * 0.2, ATTACKER, f"192.168.1.{host}", "TCP", 41000 + host, 22, SYN)

    # --- attack 3: someone on the internet tries RDP on the laptop (port forwarded) ------
    add(60, "203.0.113.200", LAPTOP, "TCP", 51515, 3389, SYN)

    # --- attack 4: the smart plug phones home to an IRC server and an odd port ---------
    add(75, PLUG, "198.51.100.66", "TCP", 50001, 6667, SYN)
    add(90, PLUG, "198.51.100.77", "TCP", 50002, 8333, SYN)

    frames.sort(key=lambda f: f[0])
    return frames


def write_demo(path):
    frames = demo_frames()
    write_pcap(path, frames)
    return len(frames)
