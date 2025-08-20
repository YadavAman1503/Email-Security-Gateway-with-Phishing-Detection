
import re
from typing import Dict, List, Tuple

SUSPICIOUS_KEYWORDS = [
    "verify your account", "urgent", "immediately", "password", "reset",
    "limited time", "action required", "suspended", "unusual activity",
    "gift", "lottery", "click below", "confirm your identity",
    "invoice", "payment", "bank", "security alert", "otp", "one time password"
]

def score_headers(raw_headers: str, from_addr: str) -> Tuple[int, List[str]]:
    score = 0
    reasons = []
    rh = raw_headers.lower() if raw_headers else ""

    # Simple presence checks
    if "authentication-results" not in rh:
        score += 5
        reasons.append("Missing Authentication-Results header")

    # SPF & DKIM quick signals (based on Authentication-Results or Received-SPF)
    if "spf=fail" in rh or "received-spf: fail" in rh:
        score += 20
        reasons.append("Header anomaly: SPF fail")
    elif "spf=softfail" in rh:
        score += 10
        reasons.append("Header anomaly: SPF softfail")

    if "dkim=fail" in rh:
        score += 15
        reasons.append("Header anomaly: DKIM fail")
    elif "dkim=none" in rh:
        score += 8
        reasons.append("Header anomaly: DKIM none")

    # Reply-To vs From mismatch (very naive)
    m_reply = re.search(r"^reply-to:\s*(.+)$", raw_headers, re.IGNORECASE | re.MULTILINE) if raw_headers else None
    m_from = re.search(r"^from:\s*(.+)$", raw_headers, re.IGNORECASE | re.MULTILINE) if raw_headers else None
    if m_reply and m_from and m_reply.group(1) and m_from.group(1):
        rt = m_reply.group(1).strip()
        fr = m_from.group(1).strip()
        if rt and fr and rt.split('@')[-1] != fr.split('@')[-1]:
            score += 10
            reasons.append("Reply-To domain differs from From domain")

    return min(score, 60), reasons

def score_urls(urls: List[str]) -> Tuple[int, List[str]]:
    score = 0
    reasons = []
    for u in urls[:20]:  # evaluate up to 20 URLs
        if re.search(r'http[s]?://\d{1,3}(\.\d{1,3}){3}', u):
            score += 15
            reasons.append("Suspicious URL: IP address used")
        if u.count('.') >= 4:
            score += 8
            reasons.append("Suspicious URL: many subdomains")
        if "xn--" in u:
            score += 8
            reasons.append("Suspicious URL: punycode detected")
        if '@' in u.split('/')[2]:
            score += 10
            reasons.append("Suspicious URL: @ in hostname (obfuscation)")
    score += min(len(urls)*2, 10)  # many links -> more suspicious
    if urls:
        reasons.append(f"Email contains {len(urls)} URL(s)")
    return min(score, 50), reasons

def score_body(body: str) -> Tuple[int, List[str]]:
    score = 0
    reasons = []
    b = body.lower() if body else ""

    # Keyword hits
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in b]
    if hits:
        score += min(5*len(hits), 25)
        reasons.append(f"Suspicious keywords: {', '.join(hits[:5])}{'...' if len(hits)>5 else ''}")

    # Excess punctuation / urgency signals
    exclam = b.count('!')
    if exclam >= 3:
        score += 5
        reasons.append("Excessive exclamation marks")

    # Hidden unicode (rough heuristic)
    if any(ord(c) > 127 for c in b):
        score += 2
        reasons.append("Non-ASCII characters present (could be homoglyphs)")

    return min(score, 35), reasons
