#!/usr/bin/env python3
"""Export LYTA Shield telemetry as loopback-only Prometheus metrics."""

from __future__ import annotations

import argparse
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    events = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    events.append(event)
            except json.JSONDecodeError:
                continue
    return events


def render_metrics(path: Path) -> str:
    events = read_events(path)
    dangerous = sum(event.get("verdict") == "DANGEROUS" for event in events)
    suspicious = sum(event.get("verdict") == "SUSPICIOUS" for event in events)
    safe = len(events) - dangerous - suspicious
    circuit = int((ROOT / "var" / "circuit-breaker-open").exists())
    return f"""# HELP lyta_shield_events_total Total guard events.
# TYPE lyta_shield_events_total counter
lyta_shield_events_total {len(events)}
# HELP lyta_shield_events_by_verdict Guard events by verdict.
# TYPE lyta_shield_events_by_verdict gauge
lyta_shield_events_by_verdict{{verdict="SAFE"}} {safe}
lyta_shield_events_by_verdict{{verdict="SUSPICIOUS"}} {suspicious}
lyta_shield_events_by_verdict{{verdict="DANGEROUS"}} {dangerous}
# HELP lyta_shield_circuit_open Whether the circuit breaker is open.
# TYPE lyta_shield_circuit_open gauge
lyta_shield_circuit_open {circuit}
"""


def make_handler(event_log: Path, token: str):
    class MetricsHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/metrics":
                self.send_response(404)
                self.end_headers()
                return
            if token and not hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {token}"):
                self.send_response(401)
                self.send_header("WWW-Authenticate", "Bearer")
                self.end_headers()
                return
            body = render_metrics(event_log).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    return MetricsHandler


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event_log", nargs="?", type=Path, default=ROOT / "var" / "hermes-guard-events.jsonl")
    parser.add_argument("port", nargs="?", type=int, default=9101)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.once:
        print(render_metrics(args.event_log), end="")
        return 0

    token = os.environ.get("LYTA_METRICS_TOKEN", "")
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        if os.environ.get("LYTA_METRICS_ALLOW_REMOTE") != "1" or not token:
            raise SystemExit("remote binding requires LYTA_METRICS_ALLOW_REMOTE=1 and LYTA_METRICS_TOKEN")
    server = ThreadingHTTPServer((args.host, args.port), make_handler(args.event_log, token))
    print(f"[OK] LYTA Shield metrics on http://{args.host}:{args.port}/metrics")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
