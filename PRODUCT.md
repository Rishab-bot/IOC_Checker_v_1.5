# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary: a SOC analyst triaging an alert. They paste alert text (SIEM JSON, log lines, free text) and decide which IPs need action.

Secondary: hiring managers and the user's manager evaluating the project through the README, screenshots, a local demo and, later, a shared link opened on a work laptop where nothing can be installed.

## Product Purpose

Turn an alert into a fast first-pass triage of its IP addresses: extract, filter, check AbuseIPDB, get a validated Gemini verdict, sort worst first, and dig into one IP with an analyst assessment. Success: the most dangerous IPs are on top and the next step is clear. It never makes the decision for the analyst.

## Positioning

Every AI answer is validated before it is shown and labelled as AI. Sorting is done in code. The assessment reasons over the alert lines that mention the IP, not just its reputation.

## Operating Context

Runs locally (127.0.0.1) on Windows, from the command line (main.py) or as a local web page (web_app.py). Demo mode (made-up data, no API calls) is the default; --live uses the analyst's limited free-tier AbuseIPDB and Gemini quota. Alerts often come from Microsoft Sentinel JSON.

A hosted copy is built and tested offline but not deployed yet: `--public-host`, a sign-in page with personal logins (IOC_USERS, made with make_user.py), no per-person limits, and one site-wide daily ceiling (default 700 AbuseIPDB lookups per UTC day) that protects the user's quota. Without a login nothing but the sign-in page is reachable. The user shares their own credit with people they choose.

## Capabilities and Constraints

- IPv4 only; up to 50 public IPs per check; invalid, private, documentation and multicast IPs are skipped with a reason.
- Input by pasting, by uploading a text file (up to 95 KB) or from four made-up sample alerts. Results export as CSV or JSON.
- AbuseIPDB lookups (basic and detailed), Gemini verdicts and the analyst assessment (gemini-3.5-flash-lite), which runs only from the investigation page's Run deep analysis button.
- Not built, so never shown: web research, VirusTotal, domains, hashes, reports, integrations. The one exception, at the user's request: History and Settings appear in the top bar as disabled items marked Soon.
- Sign-in (hosted copy only): username and password, 12-hour sessions, a 15-minute lockout after 5 wrong passwords, a Sign out button. No sign-up, password reset or roles.
- Planned: free public data from Shodan InternetDB and the Tor Project exit list.
- Stack: Python standard-library server, plain HTML/CSS/JS, strict CSP (default-src 'self'), no new dependencies, no external fonts or scripts.
- Actions that spend API quota must be explicit, never triggered just by browsing.

## Brand Commitments

Name: IOC Checker. The user's second mockup is the binding visual reference: a centred start screen (crosshair-shield mark, the title IOC Checker, a paste/upload box, a three-item strip of true statements) on dark navy with a dotted horizon, a blue accent and red/amber/green verdict chips. Results are a sorted table with a quick-triage side panel, and one IP opens a full-page investigation with Previous/Next. The first mockup's sidebar dashboard is superseded.

## Evidence on Hand

Real outputs from live tests, for example 185.220.101.5: Tor exit, abuse score 100. No users, testimonials or benchmarks exist, and none may be invented.

## Product Principles

1. Show only what works (History and Settings marked Soon are the agreed exception).
2. Demo and live must be unmistakable.
3. Untrusted text is shown as text; AI output is labelled and validated.
4. Spending quota is always a deliberate click, and a hosted copy has a site-wide ceiling so it can never spend the whole day's allowance.
5. Nothing on a hosted copy is reachable without a login.
5. Worst first, details one click away.
