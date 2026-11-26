"""Rule-based detectors. Each one looks at packets in time order and raises alerts.

The rules are deliberately simple and explainable, so it's clear why each alert fired:

* Port scan      - one host probes many different ports on another host in a short time.
* Host sweep     - one host probes the same port on many different hosts (looking for targets).
* Risky service  - a connection attempt to a port commonly abused by attackers (Telnet, RDP,
                   SMB, VNC, well-known backdoor ports).
* Unusual egress - a device on the local network starts talking to the internet on a port
                   normal home traffic doesn't use.
"""
import ipaddress
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass

RISKY_PORTS = {
    23: "Telnet", 445: "SMB", 3389: "RDP", 5900: "VNC", 2323: "Telnet (alt)",
    4444: "Metasploit default", 1337: "common backdoor", 31337: "Back Orifice", 6667: "IRC (botnet C2)",
}
COMMON_EGRESS_PORTS = {
    53, 80, 123, 443, 853,            # DNS, web, NTP, DNS-over-TLS
    22, 465, 587, 993, 995,           # SSH, mail
    3478, 5228, 5223, 19302,          # STUN / push notifications / video calls
}


@dataclass
class Alert:
    ts: float
    severity: str      # "high", "medium" or "low"
    kind: str
    src: str
    dst: str
    detail: str

    def to_dict(self):
        return asdict(self)


LOCAL_NETWORKS = [ipaddress.ip_network(n) for n in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]


def is_local(ip):
    """True for home/LAN addresses (RFC 1918, loopback, link-local)."""
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in LOCAL_NETWORKS)


def _probe(pkt):
    """Packets that start a conversation: TCP SYNs and UDP datagrams."""
    return pkt.is_syn or (pkt.proto == "UDP" and pkt.dport is not None)


class PortScanDetector:
    def __init__(self, threshold=15, window=10.0):
        self.threshold, self.window = threshold, window
        self.seen = defaultdict(deque)            # (src, dst) -> deque[(ts, port)]
        self.open = {}                            # (src, dst) -> [alert, set of ports probed]

    def feed(self, pkt):
        if not _probe(pkt):
            return None
        key = (pkt.src, pkt.dst)
        if key in self.open:                      # scan already reported: keep its totals up to date
            alert, ports = self.open[key]
            ports.add(pkt.dport)
            alert.detail = self._detail(pkt, ports, pkt.ts - alert.ts)
            return None
        q = self.seen[key]
        q.append((pkt.ts, pkt.dport))
        while q and pkt.ts - q[0][0] > self.window:
            q.popleft()
        ports = {p for _, p in q}
        if len(ports) >= self.threshold:
            alert = Alert(q[0][0], "high", "Port scan", pkt.src, pkt.dst, "")
            alert.detail = self._detail(pkt, ports, pkt.ts - alert.ts)
            self.open[key] = [alert, ports]
            return alert
        return None

    @staticmethod
    def _detail(pkt, ports, seconds):
        return (f"{len(ports)} different {pkt.proto} ports probed in {seconds:.1f}s "
                f"(ports {min(ports)}-{max(ports)})")


class HostSweepDetector:
    def __init__(self, threshold=10, window=30.0):
        self.threshold, self.window = threshold, window
        self.seen = defaultdict(deque)            # (src, port) -> deque[(ts, dst)]
        self.open = {}                            # (src, port) -> [alert, set of hosts probed]

    def feed(self, pkt):
        if not _probe(pkt) or pkt.dport in (53, 123, 137, 1900, 5353):   # DNS/NTP/discovery are normal fan-out
            return None
        key = (pkt.src, pkt.dport)
        if key in self.open:
            alert, hosts = self.open[key]
            hosts.add(pkt.dst)
            self._update(alert, pkt, hosts)
            return None
        q = self.seen[key]
        q.append((pkt.ts, pkt.dst))
        while q and pkt.ts - q[0][0] > self.window:
            q.popleft()
        hosts = {h for _, h in q}
        if len(hosts) >= self.threshold:
            alert = Alert(q[0][0], "high", "Host sweep", pkt.src, "", "")
            self._update(alert, pkt, hosts)
            self.open[key] = [alert, hosts]
            return alert
        return None

    @staticmethod
    def _update(alert, pkt, hosts):
        alert.dst = f"{len(hosts)} hosts"
        alert.detail = f"port {pkt.dport}/{pkt.proto} probed on {len(hosts)} hosts in {pkt.ts - alert.ts:.1f}s"


class RiskyServiceDetector:
    def __init__(self):
        self.alerted = set()

    def feed(self, pkt):
        if not _probe(pkt) or pkt.dport not in RISKY_PORTS:
            return None
        key = (pkt.src, pkt.dst, pkt.dport)
        if key in self.alerted:
            return None
        self.alerted.add(key)
        inbound = not is_local(pkt.src) and is_local(pkt.dst)
        return Alert(pkt.ts, "high" if inbound else "medium", "Risky service", pkt.src, pkt.dst,
                     f"connection attempt to port {pkt.dport} ({RISKY_PORTS[pkt.dport]})"
                     + (" from the internet" if inbound else ""))


class UnusualEgressDetector:
    def __init__(self, allowed=COMMON_EGRESS_PORTS):
        self.allowed = set(allowed)
        self.alerted = set()

    def feed(self, pkt):
        if not _probe(pkt) or pkt.dport is None or pkt.dport in self.allowed or pkt.dport in RISKY_PORTS:
            return None
        if not (is_local(pkt.src) and not is_local(pkt.dst)):
            return None
        key = (pkt.src, pkt.dst, pkt.dport)
        if key in self.alerted:
            return None
        self.alerted.add(key)
        return Alert(pkt.ts, "low", "Unusual connection", pkt.src, pkt.dst,
                     f"outbound {pkt.proto} to port {pkt.dport}, which normal home traffic doesn't use")


def default_detectors():
    return [PortScanDetector(), HostSweepDetector(), RiskyServiceDetector(), UnusualEgressDetector()]


def analyse(packets, detectors=None):
    """Run every detector over the packets. Returns (alerts, summary)."""
    detectors = detectors or default_detectors()
    alerts = []
    protocols = Counter()
    talkers = Counter()
    first = last = None
    count = 0
    for pkt in packets:
        count += 1
        first = pkt.ts if first is None else first
        last = pkt.ts
        protocols[pkt.proto] += 1
        talkers[pkt.src] += pkt.length
        for d in detectors:
            alert = d.feed(pkt)
            if alert:
                alerts.append(alert)
    # a scan that happens to touch Telnet/SMB/etc. is already covered by the scan alert
    scanned = {(a.src, a.dst) for a in alerts if a.kind == "Port scan"}
    alerts = [a for a in alerts if not (a.kind == "Risky service" and (a.src, a.dst) in scanned)]
    summary = {
        "packets": count,
        "duration_s": round((last - first), 1) if count else 0,
        "protocols": dict(protocols.most_common()),
        "top_talkers": [{"host": h, "bytes": b} for h, b in talkers.most_common(5)],
    }
    return alerts, summary
