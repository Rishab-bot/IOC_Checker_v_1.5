# IOC Checker

A small Python tool that turns a security alert into a quick first-pass triage of its IP addresses. It pulls the IPs out of the alert text, skips any that aren't valid public addresses, checks up to 50 of the rest on AbuseIPDB, asks Google Gemini for a verdict on each, checks that every verdict is well-formed, and lists the results with the most severe first, on screen and in a report file.

## The problem

When an alert fires in a Security Operations Centre (SOC), an analyst often has to check each indicator by hand: copy an IP address, paste it into a reputation site, read the result, note it down, then repeat for the next one. It is slow, repetitive and easy to get wrong (a skipped IP, a typo), and it happens on every alert.

IOC Checker automates that look-up-and-summarise step for IP addresses, so the analyst starts from a short summary instead of a blank page. It does not make the decision for them.

## What's new in version 1.5

- **Filtering before lookup.** Invalid addresses (such as `999.1.1.1`) and addresses that aren't public (private, loopback, documentation, multicast and other special ranges) are skipped with a reason and never use API quota.
- **A cap of 50 addresses per run.** Public addresses beyond the first 50 are counted as cut instead of being checked.
- **Sorted output.** Results are ordered by severity, most severe first, with failed checks at the bottom. The sorting is done in code, not by the LLM.
- **A summary.** Every report ends with how many addresses were checked and how many failed, which were skipped and why, and how many were cut.
- **Sturdier error handling.** A reply from AbuseIPDB that isn't a JSON object is reported as `lookup failed: invalid reply` instead of stopping the run. A Gemini reply that isn't text is reported as `verdict failed: reply is not text`.
- **Offline tests.** `test_checker.py` checks the whole pipeline with fake lookup and verdict functions, with no network calls and no API keys.

## What it does

Given the alert text in `sample_alert.txt`, the tool:

1. **Extracts** every IPv4-looking address, keeping each one once, in the order it first appears.
2. **Filters** them with Python's standard `ipaddress` module. Anything that isn't a valid address is skipped as `invalid`. Private, loopback, documentation, multicast and other non-public addresses are skipped as `not public`.
3. **Caps** the run at the first 50 public addresses. Any beyond that are counted as cut.
4. **Looks up** each remaining address on [AbuseIPDB](https://www.abuseipdb.com/) using reports from the last 90 days: abuse confidence score, country, ISP, number of reports, when it was last reported, and whether it is whitelisted.
5. **Asks an LLM** (Gemini) for a verdict based on that reputation data: `benign`, `suspicious` or `malicious`, a severity from `none` to `critical`, and a short reason.
6. **Validates** the LLM's reply before trusting it (see below).
7. **Sorts** the results by severity, from `critical` down to `none`. Addresses with the same severity keep their order from the alert, and addresses whose lookup or verdict failed go at the bottom.
8. **Reports** one line per address, then a summary, on screen and in `report_YYYYMMDD_HHMMSS.txt`.

If the lookup or the verdict fails for one address, the tool records why on that address's line and carries on with the rest. Skipped and cut addresses never reach AbuseIPDB or Gemini.

Output format (placeholders, not real results):

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
  -> print and save       (main.py)
```

| File | Role |
|---|---|
| `extractor.py` | `extract_ips` finds IPv4-looking addresses with a regular expression and removes duplicates. `filter_ips` uses `ipaddress` to split them into addresses to check and skipped addresses, each with a reason. |
| `lookup.py` | Calls AbuseIPDB's `check` endpoint (10-second timeout) and returns a small, flat summary. Errors become short messages (`invalid API key`, `rate limit reached`, `HTTP <code>`, `timed out`, `connection failed`, `invalid reply`) instead of crashing the run. |
| `verdict.py` | Sends the reputation summary to `gemini-3.5-flash-lite` (30-second timeout) with instructions to answer in JSON, then validates the answer. The Gemini client is created on first use, so importing the module needs no API key. |
| `checker.py` | `check_payload` runs the whole pipeline on a block of text and returns the sorted results, the skipped addresses, the number cut and the counts. The lookup and verdict functions can be passed in, which is how the tests run offline. |
| `main.py` | Reads `sample_alert.txt`, calls `check_payload`, prints the results and the summary, and writes the report file. |
| `test_checker.py` | Offline tests using plain `assert` statements and fake lookup and verdict functions. |

**Why the LLM's reply is validated.** The tool treats the LLM's answer as untrusted input. The model might reply in prose, wrap its JSON in a Markdown code fence, leave out a field, or invent a value like `"super-critical"`. `validate_verdict()` first rejects a reply that isn't text at all. It then strips a code fence if there is one, and requires valid JSON forming an object, with all three keys (`verdict`, `severity`, `reason`) and values from the allowed lists. A reply that fails any check is reported as `verdict failed: <reason>` rather than shown as a verdict.

Other deliberate choices:

- **API keys stay out of the code.** Both keys are read from environment variables, and `.gitignore` excludes `.env` files.
- **Only reputation data goes to the LLM.** The prompt contains the AbuseIPDB summary for one IP, not the alert itself, so details such as usernames in the alert are not sent to Gemini.
- **Quota goes only where it can tell you something.** Skipped addresses and anything past the 50-address cap are never sent to either service. If the Gemini key is missing, the run stops before the first lookup.
- **Sorting is done in code.** The LLM only labels each address. The order comes from a fixed severity ranking, so the same verdicts always come out in the same order.
- **One failure doesn't stop the run.** Lookup and verdict errors are reported per address.

## How to run

Built with Python 3.14 on Windows. In Command Prompt, from the project folder:

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

   `setx` only affects windows opened afterwards, so open a new Command Prompt and activate the venv again. Don't put keys in the code or in any file you commit.

3. Optionally, run the offline tests first. They need no keys and make no network calls:

   ```
   python test_checker.py
   ```

4. Run the checker:

   ```
   python main.py
   ```

To check a different alert, replace the contents of `sample_alert.txt` (it is read as UTF-8). Each run makes one AbuseIPDB lookup and at most one Gemini call per unique public address, up to 50, and both count against the services' free-tier quotas. Report files are git-ignored.

## Limitations

- **IPv4 only.** The tool does not handle IPv6 addresses, domains, URLs, file hashes or email addresses. It also can't tell an IP address from text that merely looks like one: a version number such as `1.2.3.4` is a valid public address, so it would be looked up and use a request.
- **Reputation is not legitimacy.** AbuseIPDB shows how often an address has been reported for abuse. That says nothing about whether a specific login or event was legitimate. A clean score for the address behind a successful login does not prove the login came from the real user.
- **The LLM can be wrong.** The verdict is a suggestion based only on reputation data. Validation guarantees that the answer has the right shape and allowed values, not that the judgement is correct. That is why the reply is validated and a person still makes the call.
- **Free-tier rate limits.** AbuseIPDB and Gemini both limit free usage. When AbuseIPDB's limit is hit, the address is reported as `lookup failed: rate limit reached`. A Gemini error shows as `verdict failed: LLM call failed: <error type>`. The tool itself does not retry. The 50-address cap limits how much one run can use, but it does not guarantee a run stays within your quota.
- **Reserved and private addresses are skipped, not judged.** Documentation-range addresses such as `203.0.113.7` (RFC 5737) and private addresses such as `10.0.0.5` have no meaningful reputation, so the tool skips them as `not public` instead of spending a lookup. The flip side: an alert about internal hosts gets no verdict for those hosts, only a line in the summary.

Also worth knowing: the input file name is fixed, addresses are checked one at a time, the report is plain text, and results appear only once every address has been checked, because they are sorted first. The tests cover the pipeline with fake functions. The real AbuseIPDB and Gemini calls are not tested automatically.

## What I'd change for production

- **Input and output:** take alerts from the SIEM or ticketing system instead of a fixed file. Write structured output (JSON or ticket updates) alongside the human-readable report.
- **More indicator types:** add IPv6, domains, URLs and file hashes, and tell real IP addresses apart from look-alikes such as version numbers.
- **More context for the verdict:** combine several intelligence sources with internal data, such as the asset inventory or a user's usual login locations. The verdict could then say something about the event, not just the IP, including for internal hosts. This needs a review first of what data may be sent to an LLM.
- **Quota and reliability:** cache recent lookups, retry with back-off when rate-limited, run lookups in parallel within the limits, and make the 50-address cap a setting.
- **LLM controls:** use the model's structured-output mode where available, alongside validation. Record the model and prompt version with each verdict, and track how often analysts agree with it.
- **Operations:** run the offline tests in CI and add tests for the validator and the lookup error handling. Add logging that never includes keys, and hold keys in a secrets manager rather than environment variables.
