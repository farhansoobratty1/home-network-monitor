"""Command line: analyse a capture, run the dashboard, or generate the demo capture.

  python -m netmon demo                         write demo/demo_capture.pcap
  python -m netmon analyse capture.pcap         detect suspicious activity and log alerts
  python -m netmon dashboard                    view the alert log in a browser
"""
import argparse
import json
import sys
from pathlib import Path

from . import dashboard, demo, detect
from .pcap import PcapError, read_pcap

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG = ROOT / "logs" / "alerts.jsonl"


def cmd_analyse(args):
    log = Path(args.log)
    log.parent.mkdir(parents=True, exist_ok=True)
    try:
        alerts, summary = detect.analyse(read_pcap(args.capture))
    except (OSError, PcapError) as e:
        sys.exit(f"Could not read {args.capture}: {e}")
    summary["file"] = Path(args.capture).name
    with log.open("a", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a.to_dict()) + "\n")
    (log.parent / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"{summary['packets']:,} packets over {summary['duration_s']} s "
          f"({', '.join(f'{k} {v}' for k, v in summary['protocols'].items())})")
    if not alerts:
        print("No suspicious activity found.")
    for a in alerts:
        print(f"[{a.severity.upper():6}] {a.kind:<18} {a.src} -> {a.dst}: {a.detail}")
    print(f"\n{len(alerts)} alert(s) appended to {log}")


def cmd_dashboard(args):
    log = Path(args.log)
    dashboard.serve(log, log.parent / "summary.json", port=args.port)


def cmd_demo(args):
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    n = demo.write_demo(out)
    print(f"Wrote {n:,} packets to {out}")
    print(f"Next: python -m netmon analyse {out}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="netmon", description="Home network security monitor")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyse", aliases=["analyze"], help="scan a .pcap capture for suspicious activity")
    a.add_argument("capture")
    a.add_argument("--log", default=DEFAULT_LOG, help="alert log to append to (JSON lines)")
    a.set_defaults(func=cmd_analyse)

    d = sub.add_parser("dashboard", help="serve the alert dashboard on localhost")
    d.add_argument("--log", default=DEFAULT_LOG)
    d.add_argument("--port", type=int, default=8050)
    d.set_defaults(func=cmd_dashboard)

    g = sub.add_parser("demo", help="generate a synthetic capture with example attacks")
    g.add_argument("--out", default=ROOT / "demo" / "demo_capture.pcap")
    g.set_defaults(func=cmd_demo)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
