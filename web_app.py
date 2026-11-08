"""A small local web page for IOC Checker: paste an alert into the search box and see the sorted results.

Run:
    python web_app.py            demo mode: fake results, no API calls, no keys needed
    python web_app.py --live     real AbuseIPDB and Gemini calls (uses your free-tier quota)

The server only listens on 127.0.0.1, so other computers on your network cannot reach it.
"""
import argparse
import json
import secrets
import threading
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import checker
import extractor
import insight
import lookup
import verdict

MAX_IPS = 50
MAX_BODY_BYTES = 100_000
MAX_STORED_ALERTS = 20  # newest checked alerts kept in memory for the details panel's alert excerpts
WEB_DIR = Path(__file__).with_name("web")
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}
PAGE_CSP = "default-src 'self'; frame-ancestors 'none'"

# Demo verdicts by made-up score: (minimum score, verdict, severity), checked from the top.
DEMO_LEVELS = [
    (90, "malicious", "critical"),
    (75, "malicious", "high"),
    (50, "suspicious", "medium"),
    (25, "suspicious", "low"),
    (0, "benign", "none"),
]


def demo_score(ip):
    """Return a made-up but repeatable abuse score from 0 to 100 for ip."""
    return sum(int(part) * (n + 1) for n, part in enumerate(ip.split("."))) % 101


def demo_lookup(ip):
    """Fake AbuseIPDB lookup with the same fields as lookup_ip. IPs whose last part is 13 fail, to show a failed lookup."""
    if ip.split(".")[-1] == "13":
        return {"ip": ip, "error": "rate limit reached (demo)"}
    score = demo_score(ip)
    return {
        "ip": ip, "score": score, "country": "ZZ", "isp": "Example Hosting (demo)", "reports": score * 7,
        "last_reported": "2026-11-07T10:00:00+00:00" if score else None, "whitelisted": False, "error": None,
    }


def demo_verdict(lookup_result):
    """Fake Gemini verdict from the fake score. Any IP whose last part is 66 fails, so a failed verdict can be seen."""
    ip = lookup_result["ip"]
    if ip.split(".")[-1] == "66":
        return {"error": "invalid severity: super-critical (demo)"}

    score = lookup_result["score"]
    for minimum, label, severity in DEMO_LEVELS:
        if score >= minimum:
            reason = f"DEMO: made-up score {score}, not real reputation data"
            return {"verdict": label, "severity": severity, "reason": reason, "error": None}


def demo_details(ip):
    """Fake detailed AbuseIPDB record with the same shape as lookup.lookup_ip_details. IPs ending in 13 fail."""
    if ip.split(".")[-1] == "13":
        return {"ip": ip, "error": "rate limit reached (demo)"}

    score = demo_score(ip)
    reports = score * 7
    recent = [
        {"reported_at": "2026-11-07T10:00:00+00:00", "categories": ["Brute-Force", "SSH"],
         "reporter_country": "Demo Land", "comment": "DEMO: made-up report comment"},
    ] if reports else []
    return {
        "ip": ip, "score": score, "country": "ZZ", "country_name": "Demo Land",
        "usage_type": "Data Center/Web Hosting/Transit", "isp": "Example Hosting (demo)",
        "domain": "example.net", "hostnames": [f"host-{ip.replace('.', '-')}.example.net"],
        "is_tor": score >= 90, "whitelisted": False, "reports": reports, "distinct_reporters": score,
        "last_reported": "2026-11-07T10:00:00+00:00" if reports else None,
        "top_categories": [["Brute-Force", score * 4], ["SSH", score * 3]] if reports else [],
        "top_reporter_countries": [["Demo Land", reports]] if reports else [],
        "recent_reports": recent, "checks_left_today": "demo", "error": None,
    }


def demo_assessment(details, excerpts):
    """Fake analyst assessment with the same shape as insight.get_assessment, clearly labelled. IPs ending in 66 fail."""
    ip = details.get("ip") or ""
    if ip.split(".")[-1] == "66":
        return {"error": "assessment failed: demo error"}

    score = details.get("score")
    if score is None:
        label = "inconclusive"
    elif score >= 75:
        label = "likely_malicious"
    elif score >= 25:
        label = "suspicious"
    else:
        label = "likely_benign"
    score_fact = f"DEMO: made-up abuse score {score}" if score is not None else "DEMO: no AbuseIPDB record (demo lookup failed)"
    return {
        "assessment": label,
        "confidence": "low",
        "summary": "DEMO: made-up assessment from a made-up score. Start the server with --live for a real one.",
        "evidence": [score_fact, f"{len(excerpts)} part(s) of the alert mention this IP"],
        "benign_explanations": ["DEMO: this is demo data, so nothing here is real"],
        "attack_techniques": [],
        "recommended_actions": ["Start the server with --live to get a real assessment"],
        "hunting_queries": [{"language": "KQL", "query": f'// DEMO query\nCommonSecurityLog\n| where DestinationIP == "{ip}"'}],
        "pivots": [],
        "error": None,
    }


def run_check(text, live):
    """Check text with the real APIs when live is True, otherwise with the demo fakes."""
    if live:
        return checker.check_payload(text, max_ips=MAX_IPS)
    return checker.check_payload(text, max_ips=MAX_IPS, lookup_fn=demo_lookup, verdict_fn=demo_verdict)


def remember_alert(server, text):
    """Keep the alert text in memory (newest 20 only) and return a random ID for it. Nothing is written to disk."""
    check_id = secrets.token_urlsafe(9)
    with server.alerts_lock:
        server.alerts[check_id] = text
        while len(server.alerts) > MAX_STORED_ALERTS:
            server.alerts.popitem(last=False)
    return check_id


def recall_alert(server, check_id):
    """Return the stored alert text for check_id, or None if it is unknown or has been dropped."""
    if not isinstance(check_id, str):
        return None
    with server.alerts_lock:
        return server.alerts.get(check_id)


def run_insight(ip, live, alert_text=None):
    """Get one IP's detailed AbuseIPDB record and the analyst assessment, real or demo.

    The assessment still runs if the AbuseIPDB lookup fails; it then only has the IP to go on.
    It also gets the parts of the original alert that mention this IP, when the alert is still in memory.
    """
    if live:
        details_fn, assess_fn = lookup.lookup_ip_details, insight.get_assessment
    else:
        details_fn, assess_fn = demo_details, demo_assessment

    details = details_fn(ip)
    known = details if details["error"] is None else {"ip": ip}
    excerpts = insight.alert_excerpts(alert_text, ip) if alert_text else []
    assessment = assess_fn(known, excerpts)

    return {
        "ip": ip, "details": details, "assessment": assessment,
        "alert_excerpts": excerpts, "alert_found": alert_text is not None,
    }


def is_single_public_ipv4(value):
    """True if value is exactly one IPv4 address that the filter would keep (valid, public, not multicast)."""
    if not isinstance(value, str) or extractor.extract_ips(value) != [value]:
        return False
    kept, _ = extractor.filter_ips([value])
    return kept == [value]


class Handler(BaseHTTPRequestHandler):
    """Serves the page files, the mode at GET /status, checks at POST /check and insights at POST /insight."""

    server_version = "IOCChecker"

    def own_addresses(self):
        """Return the host:port names this server answers to (127.0.0.1 and localhost on its port)."""
        port = self.server.server_port
        return {f"127.0.0.1:{port}", f"localhost:{port}"}

    def allowed_host(self):
        """True if the Host header names this server, which blocks DNS-rebinding tricks from other sites."""
        return self.headers.get("Host") in self.own_addresses()

    def same_origin(self):
        """True if the request has no Origin header or comes from this page, so other websites can't trigger checks."""
        origin = self.headers.get("Origin")
        return origin is None or origin in {f"http://{name}" for name in self.own_addresses()}

    def send_body(self, status, body, content_type):
        """Send body (bytes) with the given status and content type, plus basic security headers."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", PAGE_CSP)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, data):
        """Send data as a JSON response with the given status."""
        self.send_body(status, json.dumps(data).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self):
        """Serve the page files and /status; anything else is 404."""
        if not self.allowed_host():
            return self.send_json(403, {"error": "forbidden host"})

        path = urlsplit(self.path).path
        if path == "/status":
            return self.send_json(200, {
                "mode": "live" if self.server.live else "demo",
                "max_ips": MAX_IPS,
                "insight_token": self.server.insight_token,
                "insight_model": insight.INSIGHT_MODEL,
            })
        if path not in STATIC_FILES:
            return self.send_json(404, {"error": "not found"})

        filename, content_type = STATIC_FILES[path]
        self.send_body(200, (WEB_DIR / filename).read_bytes(), content_type)

    def read_json_body(self):
        """Run the shared safety checks on a POST and return its JSON object, or None after sending an error reply."""
        if self.headers.get_content_type() != "application/json":
            self.send_json(415, {"error": "send JSON"})
            return None

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            self.send_json(400, {"error": "empty request"})
            return None
        if length > MAX_BODY_BYTES:
            self.send_json(413, {"error": f"text is too long (limit {MAX_BODY_BYTES} bytes)"})
            return None

        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except ValueError:
            body = None
        if not isinstance(body, dict):
            self.send_json(400, {"error": "expected a JSON object"})
            return None
        return body

    def do_POST(self):
        """Run a check (POST /check) or an insight (POST /insight) and return the results as JSON."""
        if not (self.allowed_host() and self.same_origin()):
            return self.send_json(403, {"error": "forbidden"})
        path = urlsplit(self.path).path
        if path not in ("/check", "/insight"):
            return self.send_json(404, {"error": "not found"})

        body = self.read_json_body()
        if body is None:
            return

        if path == "/check":
            text = body.get("text")
            if not isinstance(text, str):
                return self.send_json(400, {"error": 'expected JSON like {"text": "..."}'})
        else:
            token = body.get("token")
            if not isinstance(token, str) or not secrets.compare_digest(
                token.encode("utf-8"), self.server.insight_token.encode("utf-8")
            ):
                return self.send_json(403, {"error": "this page is out of date because the server restarted; reload it and analyze again"})
            ip = body.get("ip")
            if not is_single_public_ipv4(ip):
                return self.send_json(400, {"error": "expected one public IPv4 address"})

        try:
            if path == "/check":
                report = run_check(text, self.server.live)
                report["check_id"] = remember_alert(self.server, text)
            else:
                report = run_insight(ip, self.server.live, recall_alert(self.server, body.get("check")))
        except SystemExit as err:
            # lookup.get_api_key() stops the program with a fixed message when its key is missing.
            return self.send_json(500, {"error": str(err)})
        except Exception as err:
            return self.send_json(500, {"error": f"{path.strip('/')} failed: {type(err).__name__}"})

        report["mode"] = "live" if self.server.live else "demo"
        report["max_ips"] = MAX_IPS
        self.send_json(200, report)


def main():
    """Read the command line, check the keys exist in live mode, and serve the page until Ctrl+C."""
    parser = argparse.ArgumentParser(description="Local web page for IOC Checker.")
    parser.add_argument("--live", action="store_true", help="use the real AbuseIPDB and Gemini APIs (uses your quota)")
    parser.add_argument("--port", type=int, default=8000, help="port to listen on (default 8000)")
    parser.add_argument("--insight-model", default=insight.INSIGHT_MODEL,
                        help=f"Gemini model for Get insight (default {insight.INSIGHT_MODEL})")
    args = parser.parse_args()
    insight.INSIGHT_MODEL = args.insight_model

    if args.live:
        lookup.get_api_key()  # stops here with a message if ABUSEIPDB_API_KEY is missing
        verdict.get_client()  # stops here if the Gemini key is missing

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.live = args.live
    # A fresh random token each run. The results page reads it from /status (other websites can't) and puts
    # it in every Get insight link, so another site that opens /insight in a new tab can't spend your quota.
    server.insight_token = secrets.token_urlsafe(16)
    server.alerts = OrderedDict()  # check ID -> alert text, newest last; memory only, gone when the server stops
    server.alerts_lock = threading.Lock()
    mode ="LIVE: real API calls, uses your quota" if args.live else "DEMO: fake results, no API calls"
    print(f"IOC Checker web page, {mode}", flush=True)
    print(f"Get insight uses {insight.INSIGHT_MODEL}", flush=True)
    print(f"Open http://127.0.0.1:{args.port} in your browser. Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
