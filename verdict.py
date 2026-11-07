import json

from google import genai
from google.genai import types

ALLOWED_SEVERITIES = ["none", "low", "medium", "high", "critical"]
SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
REQUIRED_KEYS = ["verdict", "severity", "reason"]
ALLOWED_VERDICTS = ["benign", "suspicious", "malicious"]

_client = None

def get_client():
    """Create the Gemini client on first use and reuse it, so importing this module needs no API key."""
    global _client
    if _client is None:
        _client = genai.Client(http_options=types.HttpOptions(timeout=30000))
    return _client

def strip_code_fence(text):
    """Remove a surrounding ```json ... ``` wrapper from text, if present."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines)
    return cleaned.strip()

def validate_verdict(text):
    """Parse and check an LLM reply. Return a dict whose 'error' key is None on success."""
    if not isinstance(text, str):
        return {"error": "reply is not text"}

    try:
        data = json.loads(strip_code_fence(text))
    except json.JSONDecodeError:
         return {"error": f"reply is not valid JSON: {text[:80]!r}"}

    if not isinstance(data, dict):
        return {"error": "reply is not a JSON object"}

    for key in REQUIRED_KEYS:
        if key not in data:
            return {"error": f"missing key: {key}"}

    if data["severity"] not in ALLOWED_SEVERITIES:
        return {"error": f"invalid severity: {data['severity']}"}

    if data["verdict"] not in ALLOWED_VERDICTS:
        return {"error": f"invalid verdict: {data['verdict']}"}
    
    data["error"] = None
    return data


def get_verdict(lookup_result):
    """Ask Gemini for a verdict on a lookup result. Return a dict with an 'error' key."""
    prompt = (
        "You are a SOC assistant. Here is data about an IP address:\n"
        + json.dumps(lookup_result)
        + "\nReply with JSON only, using exactly these keys: verdict, severity, reason."
        + " Severity must be one of: none, low, medium, high, critical."
        + " Verdict must be one of: benign, suspicious, malicious."
    )

    client = get_client()

    try:
        interaction = client.interactions.create(
            model="gemini-3.5-flash-lite",
            input=prompt,
        )
        reply = interaction.output_text
    except Exception as err:
        return {"error": f"LLM call failed: {type(err).__name__}"}

    return validate_verdict(reply)