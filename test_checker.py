"""Offline tests for checker.check_payload.

Run with:  python test_checker.py

Plain asserts and fake lookup/verdict functions: no network calls, no API keys, no extra packages.
"""
import sys

import checker
import lookup
import verdict


def refuse_real_call(*args, **kwargs):
    """Stand-in for the real API functions: fail loudly if a test ever reaches one."""
    raise AssertionError("a test tried to call a real API function")


def block_real_calls():
    """Swap the real AbuseIPDB and Gemini functions for refuse_real_call, so no test can go online by mistake."""
    lookup.lookup_ip = refuse_real_call
    verdict.get_verdict = refuse_real_call
    verdict.get_client = refuse_real_call


def run_check(text, max_ips=50, severities=None, failed_lookups=(), failed_verdicts=()):
    """Run check_payload on text with fake functions. Return the report and the IPs each fake was called with."""
    severities = severities or {}
    looked_up = []
    judged = []

    def fake_lookup(ip):
        """Record the IP; fail it if it is in failed_lookups."""
        looked_up.append(ip)
        if ip in failed_lookups:
            return {"ip": ip, "error": "rate limit reached"}
        return {"ip": ip, "score": 0, "error": None}

    def fake_verdict(lookup_result):
        """Record the IP; return its configured severity, or an error if it is in failed_verdicts."""
        ip = lookup_result["ip"]
        judged.append(ip)
        if ip in failed_verdicts:
            return {"error": "invalid severity: super-critical"}
        return {"verdict": "suspicious", "severity": severities.get(ip, "low"), "reason": "fake", "error": None}

    report = checker.check_payload(text, max_ips=max_ips, lookup_fn=fake_lookup, verdict_fn=fake_verdict)
    return report, looked_up, judged


def result_ips(report):
    """Return the IPs in the report's results, in order."""
    return [r["ip"] for r in report["results"]]


def test_duplicates_removed():
    """An IP that appears several times in the alert is checked once."""
    report, looked_up, _ = run_check("8.8.8.8 then 1.1.1.1, again 8.8.8.8 and 8.8.8.8")
    assert looked_up == ["8.8.8.8", "1.1.1.1"], looked_up
    assert report["counts"]["checked"] == 2, report["counts"]


def test_invalid_ip_skipped():
    """An address with an octet over 255 is skipped as invalid and never looked up."""
    report, looked_up, _ = run_check("999.1.1.1 and 8.8.8.8")
    assert report["skipped"] == [("999.1.1.1", "invalid")], report["skipped"]
    assert looked_up == ["8.8.8.8"], looked_up


def test_private_ip_skipped():
    """Private, documentation and multicast addresses are skipped as not public and never looked up."""
    report, looked_up, _ = run_check("10.0.0.5, 192.168.1.10, 203.0.113.7, 224.0.0.251 and 8.8.8.8")
    assert report["skipped"] == [
        ("10.0.0.5", "not public"),
        ("192.168.1.10", "not public"),
        ("203.0.113.7", "not public"),
        ("224.0.0.251", "not public"),
    ], report["skipped"]
    assert looked_up == ["8.8.8.8"], looked_up


def test_cap_of_50():
    """With 55 public IPs only the first 50 are checked and 5 are cut; skipped IPs don't count toward the cap."""
    public = [f"1.1.1.{n}" for n in range(1, 56)]
    text = "10.0.0.1 " + " ".join(public) + " 192.168.0.1"
    report, looked_up, _ = run_check(text)
    assert looked_up == public[:50], f"looked up {len(looked_up)} IPs"
    assert report["counts"]["checked"] == 50, report["counts"]
    assert report["cut"] == 5, report["cut"]
    assert len(report["skipped"]) == 2, report["skipped"]


def test_sorting_order():
    """Results go highest severity first; ties keep alert order; errors go last, in alert order."""
    severities = {
        "1.1.1.1": "low",
        "2.2.2.2": "critical",
        "3.3.3.3": "medium",
        "4.4.4.4": "none",
        "5.5.5.5": "medium",
        "6.6.6.6": "high",
    }
    text = "1.1.1.1 7.7.7.7 2.2.2.2 3.3.3.3 4.4.4.4 9.9.9.9 5.5.5.5 6.6.6.6"
    report, _, _ = run_check(text, severities=severities, failed_lookups={"9.9.9.9"}, failed_verdicts={"7.7.7.7"})
    assert result_ips(report) == [
        "2.2.2.2",  # critical
        "6.6.6.6",  # high
        "3.3.3.3",  # medium, first in the alert
        "5.5.5.5",  # medium
        "1.1.1.1",  # low
        "4.4.4.4",  # none
        "7.7.7.7",  # verdict failed, first error in the alert
        "9.9.9.9",  # lookup failed
    ], result_ips(report)


def test_failed_lookup():
    """A failed lookup is reported with its reason, gets no verdict call, and the run carries on."""
    report, _, judged = run_check("1.1.1.1 8.8.8.8", failed_lookups={"1.1.1.1"})
    failed = report["results"][-1]
    assert failed == {
        "ip": "1.1.1.1",
        "verdict": None,
        "severity": None,
        "reason": None,
        "error": "lookup failed: rate limit reached",
        "score": None,
        "country": None,
        "isp": None,
        "reports": None,
        "last_reported": None,
        "whitelisted": None,
    }, failed
    assert judged == ["8.8.8.8"], judged
    ok = report["results"][0]
    assert ok["ip"] == "8.8.8.8" and ok["score"] == 0, "a successful lookup's score is passed through"
    assert report["counts"] == {"checked": 2, "failed": 1}, report["counts"]


def test_failed_verdict():
    """A failed verdict is reported with its reason, and the other IPs still get verdicts."""
    report, _, judged = run_check("1.1.1.1 8.8.8.8", failed_verdicts={"1.1.1.1"})
    failed = report["results"][-1]
    assert failed["ip"] == "1.1.1.1", failed
    assert failed["error"] == "verdict failed: invalid severity: super-critical", failed
    assert failed["verdict"] is None and failed["severity"] is None, failed
    assert judged == ["1.1.1.1", "8.8.8.8"], judged
    ok = report["results"][0]
    assert ok["ip"] == "8.8.8.8" and ok["error"] is None and ok["severity"] == "low", ok
    assert report["counts"] == {"checked": 2, "failed": 1}, report["counts"]


TESTS = [
    test_duplicates_removed,
    test_invalid_ip_skipped,
    test_private_ip_skipped,
    test_cap_of_50,
    test_sorting_order,
    test_failed_lookup,
    test_failed_verdict,
]


def run_all():
    """Run every test, print PASS, FAIL or ERROR for each, and return how many did not pass."""
    block_real_calls()
    failures = 0
    for test in TESTS:
        try:
            test()
        except AssertionError as err:
            failures += 1
            print(f"FAIL   {test.__name__}: {err}")
        except Exception as err:
            failures += 1
            print(f"ERROR  {test.__name__}: {type(err).__name__}: {err}")
        else:
            print(f"PASS   {test.__name__}")
    print(f"{len(TESTS) - failures} of {len(TESTS)} tests passed")
    return failures


if __name__ == "__main__":
    sys.exit(1 if run_all() else 0)
