
import os
import base64
import time
from typing import List, Dict

import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()

def _vt_headers():
    return {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

def _vt_url_id(url: str) -> str:
    # per VT API: url id is url encoded in base64 (urlsafe, no padding)
    b = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return b

def scan_urls(urls: List[str]) -> List[Dict]:
    """
    Returns list of dicts: {"url": ..., "malicious": int, "suspicious": int, "harmless": int}
    If no VT_API_KEY, returns empty list (skip reputation).
    """
    if not VT_API_KEY or not urls:
        return []

    results = []
    for u in urls[:10]:  # avoid rate limits
        try:
            url_id = _vt_url_id(u)
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=_vt_headers(), timeout=15)
            if r.status_code == 404:
                # submit URL if unknown
                sub = requests.post("https://www.virustotal.com/api/v3/urls", headers=_vt_headers(), data={"url": u}, timeout=15)
                time.sleep(2)
                if sub.ok:
                    rid = sub.json()["data"]["id"]
                    # fetch analysis
                    for _ in range(5):
                        a = requests.get(f"https://www.virustotal.com/api/v3/analyses/{rid}", headers=_vt_headers(), timeout=15)
                        if a.ok and a.json()["data"]["attributes"]["status"] == "completed":
                            stats = a.json()["data"]["attributes"]["stats"]
                            results.append({"url": u, **stats})
                            break
                        time.sleep(2)
                continue
            if r.ok:
                data = r.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                results.append({"url": u, **stats})
        except Exception:
            # ignore network errors
            pass
        time.sleep(1.5)  # gentle pacing
    return results
