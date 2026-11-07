"""Check the IPs in a block of alert text: extract, filter, cap, look up, get verdicts, sort."""
import extractor
import lookup
import verdict


def result_sort_key(result):
    """Sort key for results: errors go last, otherwise higher severity comes first."""
    if result["error"] is not None:
        return (1, 0)
    return (0, -verdict.SEVERITY_RANK[result["severity"]])


def check_ip(ip, lookup_fn, verdict_fn):
    """Look up one IP and, if that worked, get a verdict. Return a dict with ip, verdict, severity, reason, error."""
    result = {"ip": ip, "verdict": None, "severity": None, "reason": None, "error": None}

    lookup_result = lookup_fn(ip)
    if lookup_result["error"] is not None:
        result["error"] = f"lookup failed: {lookup_result['error']}"
        return result

    answer = verdict_fn(lookup_result)
    if answer["error"] is not None:
        result["error"] = f"verdict failed: {answer['error']}"
        return result

    result["verdict"] = answer["verdict"]
    result["severity"] = answer["severity"]
    result["reason"] = answer["reason"]
    return result


def check_payload(text, max_ips=50, lookup_fn=None, verdict_fn=None):
    """Check the public IPs in text, up to max_ips, and return sorted results plus what was skipped or cut.

    lookup_fn and verdict_fn default to the real AbuseIPDB and Gemini calls.
    Tests pass fake functions instead, so nothing goes online.
    """
    if max_ips < 0:
        raise ValueError("max_ips must be 0 or more")

    if lookup_fn is None:
        lookup_fn = lookup.lookup_ip
    if verdict_fn is None:
        verdict_fn = verdict.get_verdict
        verdict.get_client()  # if the Gemini key is missing, stop here, before any lookup uses quota

    ips = extractor.extract_ips(text)
    kept, skipped = extractor.filter_ips(ips)
    to_check = kept[:max_ips]
    cut = len(kept) - len(to_check)

    results = [check_ip(ip, lookup_fn, verdict_fn) for ip in to_check]
    results.sort(key=result_sort_key)

    failed = sum(1 for r in results if r["error"] is not None)

    return {
        "results": results,
        "skipped": skipped,
        "cut": cut,
        "counts": {"checked": len(results), "failed": failed},
    }
