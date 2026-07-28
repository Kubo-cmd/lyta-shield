#!/usr/bin/env python3
"""Export LYTA Shield guard events as Prometheus metrics.

Usage:
    python3 scripts/export-metrics.py [event_log] [port]

Default event log: /var/hermes-guard-events.jsonl
Default port: 9101
"""

import json
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

LYTA_DIR = Path(__file__).resolve().parent.parent
EVENT_LOG = Path(sys.argv[1]) if len(sys.argv) > 1 else LYTA_DIR / "var" / "hermes-guard-events.jsonl"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9101


def read_events():
    if not EVENT_LOG.exists():
        return []
    events = []
    with open(EVENT_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        events = read_events()
        total = len(events)
        dangerous = len([e for e in events if e.get("verdict") == "DANGEROUS"])
        suspicious = len([e for e in events if e.get("verdict") == "SUSPICIOUS"])
        safe = total - dangerous - suspicious

        body = f"""# HELP lyta_shield_events_total Total guard events.
# TYPE lyta_shield_events_total counter
lyta_shield_events_total{{verdict="dangerous"}} {dangerous}
lyta_shield_events_total{{verdict="suspicious"}} {suspicious}
lyta_shield_events_total{{verdict="safe"}} {safe}

# HELP lyta_shield_events_scraped_at Unix timestamp of last scrape.
# TYPE lyta_shield_events_scraped_at gauge
lyta_shield_events_scraped_at {int(datetime.now(timezone.utc).timestamp())}
"""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


def main():
    server = HTTPServer(("", PORT), MetricsHandler)
    print(f"[OK] LYTA Shield metrics on http://localhost:{PORT}/metrics")
    server.serve_forever()


if __name__ == "__main__":
    main()
