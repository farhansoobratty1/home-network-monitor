"""A small web dashboard for the alert log, built on the standard library's http.server."""
import html
import json
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="10">
<title>Home Network Monitor</title>
<style>
 body {{ margin: 0; font: 14px/1.5 system-ui, "Segoe UI", sans-serif; background: #0f1720; color: #dde3ea; }}
 main {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
 h1 {{ font-size: 20px; margin: 0 0 4px; }} .muted {{ color: #8a96a3; }}
 .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }}
 .card {{ background: #17212c; border: 1px solid #243140; border-radius: 6px; padding: 12px 14px; }}
 .card b {{ display: block; font-size: 24px; }}
 table {{ width: 100%; border-collapse: collapse; background: #17212c; border: 1px solid #243140; }}
 th, td {{ text-align: left; padding: 7px 10px; border-bottom: 1px solid #243140; }}
 th {{ font-size: 12px; text-transform: uppercase; color: #8a96a3; }}
 .sev {{ padding: 1px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; }}
 .high {{ background: #5c1f1f; color: #ffb3b3; }} .medium {{ background: #5a4415; color: #ffd98a; }}
 .low {{ background: #1f3a5c; color: #a9cdff; }}
 h2 {{ font-size: 15px; margin-top: 28px; }}
</style></head><body><main>
<h1>Home Network Monitor</h1>
<div class="muted">Alert log: {log} &middot; refreshes every 10 s</div>
<div class="cards">
 <div class="card"><b>{total}</b>alerts</div>
 <div class="card"><b>{high}</b>high severity</div>
 <div class="card"><b>{packets}</b>packets in last capture</div>
 <div class="card"><b>{hosts}</b>hosts raising alerts</div>
</div>
<h2>Alerts (newest first)</h2>
<table><thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Source</th><th>Target</th><th>Detail</th></tr></thead>
<tbody>{rows}</tbody></table>
<h2>Last capture</h2>
<p class="muted">{capture}</p>
</main></body></html>"""


def load_alerts(log_path):
    path = Path(log_path)
    if not path.exists():
        return []
    alerts = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue                                    # skip a half-written line
    return alerts


def render(log_path, summary_path):
    alerts = load_alerts(log_path)
    summary = {}
    if Path(summary_path).exists():
        summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    alerts.sort(key=lambda a: (-a["ts"], SEVERITY_ORDER.get(a["severity"], 9)))
    e = html.escape
    rows = "".join(
        f"<tr><td>{datetime.fromtimestamp(a['ts']):%d %b %H:%M:%S}</td>"
        f"<td><span class='sev {e(a['severity'])}'>{e(a['severity'])}</span></td>"
        f"<td>{e(a['kind'])}</td><td>{e(a['src'])}</td><td>{e(a['dst'])}</td><td>{e(a['detail'])}</td></tr>"
        for a in alerts
    ) or "<tr><td colspan='6' class='muted'>No alerts yet.</td></tr>"
    if summary:
        protos = ", ".join(f"{e(k)} {v}" for k, v in summary.get("protocols", {}).items())
        talkers = ", ".join(f"{e(t['host'])} ({t['bytes']:,} B)" for t in summary.get("top_talkers", []))
        capture = (f"{e(summary.get('file', ''))}: {summary.get('packets', 0):,} packets over "
                   f"{summary.get('duration_s', 0)} s &middot; {protos}<br>Top talkers: {talkers}")
    else:
        capture = "No capture analysed yet."
    return PAGE.format(
        log=e(Path(log_path).name), total=len(alerts),
        high=sum(a["severity"] == "high" for a in alerts),
        packets=f"{summary.get('packets', 0):,}", hosts=len({a["src"] for a in alerts}),
        rows=rows, capture=capture,
    )


def serve(log_path, summary_path, port=8050):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/api/alerts":
                body = json.dumps(load_alerts(log_path)).encode()
                ctype = "application/json"
            elif self.path in ("/", "/index.html"):
                body = render(log_path, summary_path).encode()
                ctype = "text/html; charset=utf-8"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    # bound to localhost only: the dashboard shows details of your network
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Dashboard running at http://127.0.0.1:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
