from datetime import datetime

import checker

MAX_IPS = 50


def add_line(lines, text):
    """Print text and append it to lines, so the console and the report show the same thing."""
    print(text)
    lines.append(text)


def write_report(lines):
    """Write lines to report_YYYYMMDD_HHMMSS.txt in the current folder and return the filename."""
    filename = "report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return filename


def format_result(result):
    """Turn one result dict from checker.check_payload into a single report line."""
    if result["error"] is not None:
        return f"{result['ip']} -> {result['error']}"
    return f"{result['ip']} -> {result['verdict']} / {result['severity']} / {result['reason']}"


def main():
    """Check the IPs in sample_alert.txt, print one line per result plus a summary, and save them to a report file."""
    with open("sample_alert.txt", encoding="utf-8", errors="replace") as f:
        text = f.read()

    print("Checking sample_alert.txt ...")
    report = checker.check_payload(text, max_ips=MAX_IPS)

    lines = []
    for result in report["results"]:
        add_line(lines, format_result(result))

    counts = report["counts"]
    add_line(lines, "--- Summary ---")
    add_line(lines, f"Checked: {counts['checked']} ({counts['failed']} failed)")
    add_line(lines, f"Skipped: {len(report['skipped'])}")
    for ip, reason in report["skipped"]:
        add_line(lines, f"  {ip}: {reason}")
    add_line(lines, f"Cut: {report['cut']} (limit is {MAX_IPS} IPs per run)")

    filename = write_report(lines)
    print("Report written to", filename)


if __name__ == "__main__":
    main()
