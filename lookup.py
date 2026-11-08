import os
import sys
from collections import Counter

import requests

REPORT_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}
MAX_RECENT_REPORTS = 15
MAX_COMMENT_CHARS = 300

def clean_result(raw):
    """Return a small, flat dictionary from the raw API response."""
    d = raw.get("data", {})

    return{
        "ip":d.get("ipAddress"),
        "score":d.get("abuseConfidenceScore"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "reports": d.get("totalReports"),
        "last_reported": d.get("lastReportedAt"),
        "whitelisted": d.get("isWhitelisted"),
    }

def get_api_key():
    """Read the AbuseIPDB key from the environment, or stop the program."""
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if key is None:
        sys.exit("ABUSEIPDB_API_KEY is not set, stopping")
    return key

def lookup_ip(ip):
    """Look up one IP on AbuseIPDB and return a dict. The 'error' key is None on success."""
    api_key = get_api_key()

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,  
        )
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        status = err.response.status_code
        if status == 401:
            message = "invalid API key"
        elif status == 429:
            message = "rate limit reached"
        else:
            message = f"HTTP {status}"
        return {"ip": ip, "error": message}
    except requests.exceptions.Timeout:
        return {"ip": ip, "error": "timed out"}
    except requests.exceptions.ConnectionError:
        return {"ip": ip, "error": "connection failed"}

    try:
        raw = response.json()
    except ValueError:
        return {"ip": ip, "error": "invalid reply"}

    if not isinstance(raw, dict):
        return {"ip": ip, "error": "invalid reply"}

    result = clean_result(raw)
    result["error"] = None
    return result


def category_names(ids):
    """Turn AbuseIPDB category numbers into names; unknown numbers become 'category N'."""
    if not isinstance(ids, list):
        return []
    return [REPORT_CATEGORIES.get(n, f"category {n}") for n in ids]


def clean_details(raw):
    """Return the full AbuseIPDB record for one IP, with its reports summarised instead of listed in full."""
    d = raw.get("data")
    if not isinstance(d, dict):
        d = {}
    reports = [r for r in (d.get("reports") or []) if isinstance(r, dict)]

    category_counts = Counter()
    country_counts = Counter()
    for report in reports:
        category_counts.update(category_names(report.get("categories")))
        country_counts[report.get("reporterCountryName") or "Unknown"] += 1

    newest_first = sorted(reports, key=lambda r: str(r.get("reportedAt") or ""), reverse=True)
    recent = [
        {
            "reported_at": r.get("reportedAt"),
            "categories": category_names(r.get("categories")),
            "reporter_country": r.get("reporterCountryName"),
            "comment": str(r.get("comment") or "")[:MAX_COMMENT_CHARS],
        }
        for r in newest_first[:MAX_RECENT_REPORTS]
    ]

    return {
        "ip": d.get("ipAddress"),
        "score": d.get("abuseConfidenceScore"),
        "country": d.get("countryCode"),
        "country_name": d.get("countryName"),
        "usage_type": d.get("usageType"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
        "hostnames": d.get("hostnames") or [],
        "is_tor": d.get("isTor"),
        "whitelisted": d.get("isWhitelisted"),
        "reports": d.get("totalReports"),
        "distinct_reporters": d.get("numDistinctUsers"),
        "last_reported": d.get("lastReportedAt"),
        "top_categories": category_counts.most_common(10),
        "top_reporter_countries": country_counts.most_common(5),
        "recent_reports": recent,
    }


def lookup_ip_details(ip):
    """Look up one IP on AbuseIPDB with its individual reports. Return a dict whose 'error' key is None on success."""
    api_key = get_api_key()

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=30,
        )
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        status = err.response.status_code
        if status == 401:
            message = "invalid API key"
        elif status == 429:
            message = "rate limit reached"
        else:
            message = f"HTTP {status}"
        return {"ip": ip, "error": message}
    except requests.exceptions.Timeout:
        return {"ip": ip, "error": "timed out"}
    except requests.exceptions.ConnectionError:
        return {"ip": ip, "error": "connection failed"}

    try:
        raw = response.json()
    except ValueError:
        return {"ip": ip, "error": "invalid reply"}
    if not isinstance(raw, dict):
        return {"ip": ip, "error": "invalid reply"}
    if not isinstance(raw.get("data"), dict):
        return {"ip": ip, "error": "invalid reply"}

    details = clean_details(raw)
    details["checks_left_today"] = response.headers.get("X-RateLimit-Remaining")
    details["error"] = None
    return details

if __name__ == "__main__":
    result = lookup_ip("8.8.8.8")
    print(type(result))
    print(len(result))
    print(result)