# IOC Checker

A small Python tool that turns a security alert into a quick first-pass triage of its IP addresses. It pulls the IPs out of the alert text, skips any that aren't valid public addresses, checks up to 50 of the rest on AbuseIPDB, asks Google Gemini for a verdict on each, checks that every verdict is well-formed, and lists the results with the most severe first. It runs from the command line or as a local web page, where any result opens a full-page investigation of that address, with an optional AI-assisted deep analysis.

## The problem

When an alert fires in a Security Operations Centre (SOC), an analyst often has to check each indicator by hand: copy an IP address, paste it into a reputation site, read the result, note it down, then repeat for the next one. It is slow, repetitive and easy to get wrong (a skipped IP, a typo), and it happens on every alert.

IOC Checker automates that look-up-and-summarise step for IP addresses, so the analyst starts from a short summary instead of a blank page. It does not make the decision for them.

## What's new in version 1.6

- **A local web page.** A start screen where you paste an alert, upload a text file (up to 95 KB) or pick one of four made-up sample alerts. The results are sorted by severity, with a summary of what was checked, skipped and cut. Clicking a row shows a quick-triage panel, and the results can be exported as CSV or JSON. The page starts in demo mode (made-up results, no API calls) and uses the real APIs only when started with `--live`. History and Settings appear in the top bar marked **Soon**; they aren't built yet.
- **Full-page investigation.** Double-click a result, press Enter on it, or choose **Investigate** in the panel to open a page for that IP. **Previous** and **Next** (or the arrow keys) move through the results in severity order. **Run deep analysis** adds two parts, and nothing is spent until you click it:
  - **Analyst assessment:** Gemini judges the activity in the alert, not just the IP's reputation, using the AbuseIPDB record and the parts of the alert that mention this IP. It returns an assessment and confidence, the evidence, possible harmless explanations, MITRE ATT&CK techniques, recommended actions, hunting queries (for example KQL for Microsoft Sentinel) and pivots. The reply must match a fixed structure and is validated before it is shown.
  - **The full AbuseIPDB record:** usage type, domain, hostnames, whether it is a Tor exit, distinct reporters, the most reported attack categories and reporter countries, and the 15 most recent reports.
- **Locked down by design.** The page only listens on your own machine, refuses requests from other websites, and shows everything from AbuseIPDB, alerts and Gemini as plain text.
- **More offline tests.** `test_insight.py` adds 10 tests for the insight feature, alongside the 7 in `test_checker.py`.

### Version 1.5

- **Filtering before lookup.** Invalid addresses (such as `999.1.1.1`) and addresses that aren't public (private, loopback, documentation, multicast and other special ranges) are skipped with a reason and never use API quota.
- **A cap of 50 addresses per run.** Public addresses beyond the first 50 are counted as cut instead of being checked.
- **Sorted output.** Results are ordered by severity, most severe first, with failed checks at the bottom. The sorting is done in code, not by the LLM.
- **A summary.** Every report ends with how many addresses were checked and how many failed, which were skipped and why, and how many were cut.
- **Sturdier error handling.** A reply from AbuseIPDB that isn't a JSON object is reported as `lookup failed: invalid reply` instead of stopping the run. A Gemini reply that isn't text is reported as `verdict failed: reply is not text`.
- **Offline tests.** `test_checker.py` checks the whole pipeline with fake lookup and verdict functions, with no network calls and no API keys.

## What it does

Given an alert's text (from `sample_alert.txt` on the command line, or pasted into the web page), the tool:

1. **Extracts** every IPv4-looking address, keeping each one once, in the order it first appears.
2. **Filters** them with Python's standard `ipaddress` module. Anything that isn't a valid address is skipped as `invalid`. Private, loopback, documentation, multicast and other non-public addresses are skipped as `not public`.
3. **Caps** the run at the first 50 public addresses. Any beyond that are counted as cut.
4. **Looks up** each remaining address on [AbuseIPDB](https://www.abuseipdb.com/) using reports from the last 90 days: abuse confidence score, country, ISP, number of reports, when it was last reported, and whether it is whitelisted.
5. **Asks an LLM** (Gemini) for a verdict based on that reputation data: `benign`, `suspicious` or `malicious`, a severity from `none` to `critical`, and a short reason.
6. **Validates** the LLM's reply before trusting it (see below).
7. **Sorts** the results by severity, from `critical` down to `none`. Addresses with the same severity keep their order from the alert, and addresses whose lookup or verdict failed go at the bottom.
8. **Reports** one line per address, then a summary: on screen and in `report_YYYYMMDD_HHMMSS.txt` from the command line, or as a sorted list on the web page.

If the lookup or the verdict fails for one address, the tool records why on that address's line and carries on with the rest. Skipped and cut addresses never reach AbuseIPDB or Gemini.

Command-line output format (placeholders, not real results):

```
Checking sample_alert.txt ...
<ip> -> <verdict> / high / <reason>
<ip> -> <verdict> / low / <reason>
<ip> -> lookup failed: rate limit reached
<ip> -> verdict failed: invalid severity: super-critical
--- Summary ---
Checked: 4 (2 failed)
Skipped: 2
  203.0.113.7: not public
  999.1.1.1: invalid
Cut: 0 (limit is 50 IPs per run)
Report written to report_20261107_160512.txt
```

The first and last lines appear only on screen. Everything in between is also saved in the report file.

### Deep analysis (web page only)

Clicking **Run deep analysis** on an IP's investigation page adds two parts: the **full AbuseIPDB record**, from one detailed lookup, and an **analyst assessment** from Gemini, using `gemini-3.5-flash-lite`, the same model as the verdicts (choose another with `--insight-model`). The result is kept while the page is open, so going back to that IP doesn't spend quota again.

For the assessment, Gemini receives the AbuseIPDB record, the 10 newest report comments, and the parts of the original alert that mention this IP: for a JSON alert, the matching objects or fields; for a text alert, the matching lines. The page lists exactly which alert parts were sent, under **What Gemini was given**. The reply has to match a fixed JSON structure, and `validate_assessment()` then rejects anything with an unknown assessment or confidence value, an ATT&CK ID that isn't in `T####` or `T####.###` form, wrong types or missing fields.

If the AbuseIPDB lookup fails, the assessment still runs with just the IP.

## How it works

```
alert text
  -> extract IPs          (extractor.py)
  -> filter               (extractor.py)
  -> cap at 50            (checker.py)
  -> AbuseIPDB lookup     (lookup.py)
  -> Gemini verdict       (verdict.py)
  -> validate the reply   (verdict.py)
  -> sort by severity     (checker.py)
  -> print and save       (main.py)  or  show on the web page (web_app.py)

Deep analysis for one IP
  -> detailed AbuseIPDB record                    (lookup.py)
  -> analyst assessment                           (insight.py)
  -> investigation page                           (web_app.py, web/)
```

| File | Role |
|---|---|
| `extractor.py` | `extract_ips` finds IPv4-looking addresses with a regular expression and removes duplicates. `filter_ips` uses `ipaddress` to split them into addresses to check and skipped addresses, each with a reason. |
| `lookup.py` | `lookup_ip` calls AbuseIPDB's `check` endpoint (10-second timeout) and returns a small, flat summary. `lookup_ip_details` asks for the verbose record (30-second timeout) and summarises thousands of reports into counts plus the 15 newest. Errors become short messages (`invalid API key`, `rate limit reached`, `HTTP <code>`, `timed out`, `connection failed`, `invalid reply`) instead of crashing the run. |
| `verdict.py` | Sends the reputation summary to `gemini-3.5-flash-lite` (30-second timeout) with instructions to answer in JSON, then validates the answer. The Gemini client is created on first use, so importing the module needs no API key. |
| `checker.py` | `check_payload` runs the whole pipeline on a block of text and returns the sorted results, the skipped addresses, the number cut and the counts. The lookup and verdict functions can be passed in, which is how the tests run offline. |
| `insight.py` | `get_assessment` (Gemini with a JSON schema) and `validate_assessment`, plus `alert_excerpts`, which picks the parts of an alert that mention one IP. Uses `gemini-3.5-flash-lite` by default, with a 120-second timeout and no automatic retries, so quota errors show straight away. |
| `main.py` | Reads `sample_alert.txt`, calls `check_payload`, prints the results and the summary, and writes the report file. |
| `web_app.py` | A local web server built only on Python's standard library. It serves the page in `web/`, runs checks and deep analyses, and has demo versions of every API call. |
| `web/` | A single page (`index.html`, `app.js`, `style.css`, `favicon.svg`) with three views: the start screen, the results and the investigation page. It loads no external fonts, scripts or images. |
| `test_checker.py`, `test_insight.py` | Offline tests using plain `assert` statements and fake API functions. |

**Why the LLM's replies are validated.** The tool treats every LLM answer as untrusted input. The model might reply in prose, wrap its JSON in a Markdown code fence, leave out a field, or invent a value like `"super-critical"`. `validate_verdict()` first rejects a reply that isn't text at all. It then strips a code fence if there is one, and requires valid JSON forming an object, with all three keys (`verdict`, `severity`, `reason`) and values from the allowed lists. A reply that fails any check is reported as `verdict failed: <reason>` rather than shown as a verdict. The deep-analysis assessment gets the same treatment from `validate_assessment()`.

Other deliberate choices:

- **API keys stay out of the code.** Both keys are read from environment variables, and `.gitignore` excludes `.env` files.
- **The LLM gets only what it needs.** The verdict prompt contains just the AbuseIPDB summary for one IP, never the alert. The deep-analysis assessment also gets the parts of the alert that mention that IP, never the whole alert, and the investigation page lists exactly which parts were sent. The web page keeps the alert text in memory only, for the newest 20 checks, and forgets it when the server stops.
- **Untrusted text is fenced off.** AbuseIPDB report comments and alert excerpts are written by people and systems outside your control, so they go to Gemini between markers with an instruction to treat them only as data. Any copy of a marker word inside them is removed first, so they can't fake the end of the block.
- **Quota goes only where it can tell you something.** Skipped addresses and anything past the 50-address cap are never sent to either service. A deep analysis runs only when you click **Run deep analysis** for one IP. If a key is missing, the tool stops before the first lookup.
- **Sorting is done in code.** The LLM only labels each address. The order comes from a fixed severity ranking, so the same verdicts always come out in the same order.
- **The web page is locked down.**
  - It listens only on `127.0.0.1` and rejects requests from other websites.
  - Deep-analysis requests need a random token that is new each time the server starts, so another site can't start one and spend your quota.
  - Everything from AbuseIPDB, alerts and Gemini is shown as plain text, never as HTML.
  - In a CSV export, any cell that starts with `=`, `+`, `-` or `@` gets a leading `'`, so a spreadsheet shows it as text instead of running it as a formula.
- **One failure doesn't stop the run.** Lookup and verdict errors are reported per address, and each part of a deep analysis reports its own error.

## How to run

Built with Python 3.14 on Windows. In Command Prompt or PowerShell, from the project folder:

1. Create a virtual environment and install the pinned dependencies:

   ```
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. Get an API key from [AbuseIPDB](https://www.abuseipdb.com/) and one for the [Gemini API](https://ai.google.dev/). Set them as environment variables named `ABUSEIPDB_API_KEY` and `GEMINI_API_KEY`, either through **Start → "Edit environment variables for your account"** or with:

   ```
   setx ABUSEIPDB_API_KEY "<your AbuseIPDB key>"
   setx GEMINI_API_KEY "<your Gemini key>"
   ```

   `setx` only affects windows opened afterwards, so open a new terminal and activate the venv again. Don't put keys in the code or in any file you commit.

3. Optionally, run the offline tests first. They need no keys and make no network calls:

   ```
   python test_checker.py
   python test_insight.py
   ```

4. Run the command-line checker on `sample_alert.txt`:

   ```
   python main.py
   ```

5. Or start the web page and open `http://127.0.0.1:8000` in your browser (Ctrl+C stops it):

   ```
   python web_app.py              demo mode: made-up results, no API calls, no keys needed
   python web_app.py --live       real AbuseIPDB and Gemini calls
   python web_app.py --port 8001  use another port
   python web_app.py --live --insight-model gemini-3.8-flash   try another model for deep analysis
   ```

To check a different alert on the command line, replace the contents of `sample_alert.txt` (it is read as UTF-8). What each action costs:

| Action | AbuseIPDB | Gemini |
|---|---|---|
| Check an alert | 1 lookup per unique public address (up to 50) | 1 verdict call per address, with `gemini-3.5-flash-lite` |
| Deep analysis for one IP | 1 detailed lookup | 1 assessment call with `gemini-3.5-flash-lite` (or your `--insight-model`) |

Report files are git-ignored.

## Limitations

- **IPv4 only.** The tool does not handle IPv6 addresses, domains, URLs, file hashes or email addresses. It also can't tell an IP address from text that merely looks like one: a version number such as `1.2.3.4` is a valid public address, so it would be looked up and use a request.
- **Reputation is not legitimacy.** AbuseIPDB shows how often an address has been reported for abuse. That says nothing about whether a specific login or event was legitimate. A clean score for the address behind a successful login does not prove the login came from the real user.
- **The LLM can be wrong.** The verdict and the deep-analysis assessment are suggestions based only on the data they were given. Validation guarantees that answers have the right shape and allowed values, not that the judgement is correct. An ATT&CK ID is checked for its format, not for whether it fits, and hunting queries may use fields your workspace doesn't have. That is why every reply is validated, every AI section is labelled, and a person still makes the call.
- **Prompt injection is reduced, not ruled out.** Report comments and alerts are fenced off as data and every reply is validated, but a cleverly written comment could still sway what Gemini writes. The tool never acts on Gemini's output by itself.
- **Free-tier rate limits.** AbuseIPDB and Gemini both limit free usage. When AbuseIPDB's limit is hit, the address is reported as `lookup failed: rate limit reached`. A Gemini error shows as `verdict failed: LLM call failed: <error type>`, or as an assessment error on the investigation page. The tool itself does not retry. The 50-address cap limits how much one run can use, but it does not guarantee a run stays within your quota.
- **Alert excerpts go to Google.** The deep analysis sends the alert parts that mention the IP, which can include usernames or hostnames on the same line. On Google's unpaid tier, its terms allow submitted content to be used to improve its products.
- **Reserved and private addresses are skipped, not judged.** Documentation-range addresses such as `203.0.113.7` (RFC 5737) and private addresses such as `10.0.0.5` have no meaningful reputation, so the tool skips them as `not public` instead of spending a lookup. The flip side: an alert about internal hosts gets no verdict for those hosts, only a line in the summary.

Also worth knowing: the command line reads a fixed file name. Addresses are checked one at a time, and results appear only once every address has been checked, because they are sorted first. A deep analysis can take up to a minute. The web page keeps alert context only for the newest 20 checks while the server runs. The tests cover everything with fake functions, but the real AbuseIPDB and Gemini calls are not tested automatically.

## What I'd change for production

- **Input and output:** take alerts from the SIEM or ticketing system instead of a fixed file or a pasted box. Write structured output (JSON or ticket updates) alongside the human-readable report.
- **More indicator types:** add IPv6, domains, URLs and file hashes, and tell real IP addresses apart from look-alikes such as version numbers.
- **More context for the assessment:** add internal data, such as the asset inventory, a user's usual login locations and other sightings of the same IP, so the assessment can reason about the event, not just one alert. This needs a review first of what data may be sent to an LLM.
- **Web-grounded research:** use Gemini with Google Search for news and threat reporting about an IP, once a billed Gemini project is available.
- **Quota and reliability:** cache recent lookups, retry with back-off when rate-limited, run lookups in parallel within the limits, and make the 50-address cap and the Gemini models settings.
- **LLM controls:** record the model and prompt version with each verdict and assessment, and keep a set of known alerts to measure how often the AI agrees with analysts before trusting changes.
- **Operations and access:** run the offline tests in CI, add logging that never includes keys, and hold keys in a secrets manager rather than environment variables. If the web page were ever shared beyond one machine, it would need real sign-in and a proper session store.
