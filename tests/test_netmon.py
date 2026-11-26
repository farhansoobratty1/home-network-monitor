import json
import struct
import tempfile
import unittest
from pathlib import Path

from netmon import dashboard, demo, detect
from netmon.pcap import ACK, SYN, PcapError, build_ipv4, decode_ipv4, read_pcap, write_pcap


class PcapParsing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_round_trip(self):
        frames = [(100.25, build_ipv4("192.168.1.5", "198.51.100.1", "TCP", 50000, 443, SYN)),
                  (101.5, build_ipv4("192.168.1.5", "192.168.1.1", "UDP", 50001, 53, payload=b"x" * 20)),
                  (102.0, build_ipv4("192.168.1.5", "192.168.1.1", "ICMP"))]
        path = self.dir / "t.pcap"
        write_pcap(path, frames)
        pkts = list(read_pcap(path))
        self.assertEqual([p.proto for p in pkts], ["TCP", "UDP", "ICMP"])
        self.assertEqual((pkts[0].src, pkts[0].dst, pkts[0].sport, pkts[0].dport), ("192.168.1.5", "198.51.100.1", 50000, 443))
        self.assertTrue(pkts[0].is_syn)
        self.assertAlmostEqual(pkts[0].ts, 100.25, places=5)
        self.assertEqual(pkts[1].dport, 53)
        self.assertIsNone(pkts[2].dport)

    def test_syn_ack_is_not_a_new_connection(self):
        pkt = decode_ipv4(build_ipv4("1.1.1.1", "192.168.1.2", "TCP", 443, 5000, SYN | ACK))
        self.assertFalse(pkt.is_syn)

    def test_ip_options_are_skipped(self):
        ip = bytearray(build_ipv4("192.168.1.2", "192.168.1.3", "TCP", 1234, 80, SYN))
        ip[0] = 0x46                                     # header length 24 bytes
        ip[20:20] = b"\x01\x01\x01\x01"                  # 4 bytes of NOP options
        pkt = decode_ipv4(bytes(ip))
        self.assertEqual((pkt.sport, pkt.dport), (1234, 80))

    def test_big_endian_file(self):
        path = self.dir / "be.pcap"
        ip = build_ipv4("10.0.0.1", "10.0.0.2", "TCP", 1, 2, SYN)
        with open(path, "wb") as f:
            f.write(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))   # raw IP link type
            f.write(struct.pack(">IIII", 5, 0, len(ip), len(ip)) + ip)
        self.assertEqual(list(read_pcap(path))[0].dst, "10.0.0.2")

    def test_rejects_pcapng(self):
        path = self.dir / "x.pcapng"
        path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
        with self.assertRaises(PcapError):
            list(read_pcap(path))


def syn(ts, src, dst, dport):
    return decode_ipv4(build_ipv4(src, dst, "TCP", 40000, dport, SYN), ts)


class Detectors(unittest.TestCase):
    def test_port_scan(self):
        pkts = [syn(i * 0.1, "192.168.1.66", "192.168.1.20", p) for i, p in enumerate(range(1, 31))]
        alerts, _ = detect.analyse(pkts, [detect.PortScanDetector()])
        self.assertEqual(len(alerts), 1)                 # reported once, not 16 times
        self.assertEqual(alerts[0].kind, "Port scan")
        self.assertIn("30 different TCP ports", alerts[0].detail)   # totals cover the whole scan
        self.assertIn("ports 1-30", alerts[0].detail)

    def test_scan_hitting_telnet_is_one_alert_not_two(self):
        pkts = [syn(i * 0.1, "192.168.1.66", "192.168.1.20", p) for i, p in enumerate(range(1, 31))]
        alerts, _ = detect.analyse(pkts)
        self.assertEqual([a.kind for a in alerts], ["Port scan"])

    def test_slow_connections_are_not_a_scan(self):
        pkts = [syn(i * 5.0, "192.168.1.66", "192.168.1.20", p) for i, p in enumerate(range(1, 31))]
        alerts, _ = detect.analyse(pkts, [detect.PortScanDetector()])
        self.assertEqual(alerts, [])

    def test_host_sweep(self):
        pkts = [syn(i * 0.2, "192.168.1.66", f"192.168.1.{h}", 22) for i, h in enumerate(range(2, 20))]
        alerts, _ = detect.analyse(pkts, [detect.HostSweepDetector()])
        self.assertEqual([a.kind for a in alerts], ["Host sweep"])

    def test_dns_fan_out_is_normal(self):
        pkts = [decode_ipv4(build_ipv4("192.168.1.20", f"198.51.100.{h}", "UDP", 5000, 53), h * 0.1) for h in range(1, 30)]
        alerts, _ = detect.analyse(pkts, [detect.HostSweepDetector()])
        self.assertEqual(alerts, [])

    def test_inbound_rdp_is_high_severity(self):
        alerts, _ = detect.analyse([syn(0, "203.0.113.200", "192.168.1.20", 3389)])
        self.assertEqual([(a.kind, a.severity) for a in alerts], [("Risky service", "high")])

    def test_unusual_egress_only_for_outbound(self):
        out = syn(0, "192.168.1.45", "198.51.100.77", 8333)
        lan = syn(1, "192.168.1.45", "192.168.1.20", 8333)
        web = syn(2, "192.168.1.45", "198.51.100.77", 443)
        alerts, _ = detect.analyse([out, lan, web], [detect.UnusualEgressDetector()])
        self.assertEqual([(a.dst, a.kind) for a in alerts], [("198.51.100.77", "Unusual connection")])


class DemoEndToEnd(unittest.TestCase):
    def test_demo_capture_finds_every_planted_attack(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "demo.pcap"
            demo.write_demo(path)
            alerts, summary = detect.analyse(read_pcap(path))
        kinds = sorted((a.kind, a.src, a.dst) for a in alerts)
        self.assertEqual(kinds, sorted([
            ("Port scan", demo.ATTACKER, demo.LAPTOP),
            ("Host sweep", demo.ATTACKER, "38 hosts"),
            ("Risky service", "203.0.113.200", demo.LAPTOP),
            ("Risky service", demo.PLUG, "198.51.100.66"),
            ("Unusual connection", demo.PLUG, "198.51.100.77"),
        ]))
        self.assertGreater(summary["packets"], 1000)

    def test_dashboard_renders_and_escapes(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "alerts.jsonl"
            log.write_text(json.dumps({"ts": 1764000000, "severity": "high", "kind": "Port scan",
                                       "src": "<script>", "dst": "192.168.1.20", "detail": "x"}) + "\n{broken\n")
            page = dashboard.render(log, Path(d) / "summary.json")
        self.assertIn("Port scan", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>", page)


if __name__ == "__main__":
    unittest.main()
