import ipaddress
import re

IP_PATTERN = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"


def extract_ips(text):
    """Return the unique IPv4-looking addresses in text, in order of first appearance."""
    found = re.findall(IP_PATTERN, text)
    unique = []
    for ip in found:
        if ip not in unique:
            unique.append(ip)
    return unique


def filter_ips(ips):
    """Split ips into (kept, skipped): keep valid, globally routable addresses; skipped holds (ip, reason) pairs."""
    kept = []
    skipped = []
    for ip in ips:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            skipped.append((ip, "invalid"))
            continue

        if address.is_global and not address.is_multicast:
            kept.append(ip)
        else:
            skipped.append((ip, "not public"))
    return kept, skipped


if __name__ == "__main__":
    with open("sample_alert.txt") as f:
        text = f.read()
    print(extract_ips(text))