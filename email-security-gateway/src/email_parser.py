
import re
from email import policy
from email.parser import BytesParser
from typing import Dict, Any, List, Tuple, Optional
import tldextract

URL_REGEX = re.compile(r'(https?://[^\s<>"\'\)\]]+)', re.IGNORECASE)

def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    urls = URL_REGEX.findall(text)
    # De-duplicate and strip trailing punctuation
    cleaned = []
    for u in urls:
        u = u.rstrip(').,;!?"\'')
        if u not in cleaned:
            cleaned.append(u)
    return cleaned

def parse_eml_bytes(raw: bytes) -> Dict[str, Any]:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    subject = msg['subject'] or ''
    from_addr = msg['from'] or ''
    # Collect raw headers
    raw_headers = ''
    for k, v in msg.items():
        raw_headers += f"{k}: {v}\n"

    # Extract body (prefer text/plain)
    body = ''
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == 'text/plain':
                body += part.get_content() or ''
    else:
        body = msg.get_content() or ''

    urls = extract_urls(body)
    return {
        "subject": subject,
        "from_addr": from_addr,
        "raw_headers": raw_headers,
        "body": body,
        "urls": urls
    }

def domain_of(email_or_url: str) -> Optional[str]:
    if not email_or_url:
        return None
    if '@' in email_or_url and ' ' not in email_or_url:
        # email address form
        try:
            dom = email_or_url.split('@')[-1].strip('<> ')
        except Exception:
            return None
    else:
        dom = email_or_url
    ext = tldextract.extract(dom)
    if not ext.registered_domain:
        return None
    return ext.registered_domain
