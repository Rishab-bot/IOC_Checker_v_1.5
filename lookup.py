import os
import sys
import requests

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

if __name__ == "__main__":
    result = lookup_ip("8.8.8.8")
    print(type(result))
    print(len(result))
    print(result)