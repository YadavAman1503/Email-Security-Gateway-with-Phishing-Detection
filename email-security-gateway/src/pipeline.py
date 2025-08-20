
import math
from typing import Dict, Any, List

from src.rules import score_headers, score_urls, score_body

from .vt_scan import scan_urls
from .ml_model import load_model

def combine_scores(heur: int, ml_prob: float, vt_stats: List[dict]) -> Dict[str, Any]:
    vt_mal = 0
    reasons = []
    if vt_stats:
        vt_mal = sum(x.get("malicious", 0) for x in vt_stats)
        if vt_mal > 0:
            reasons.append(f"VirusTotal flagged {vt_mal} detection(s)")

    # Normalize heuristic to 0-1
    heur01 = min(max(heur / 100.0, 0.0), 1.0)
    # Weighted blend: heuristics 0.45, ML 0.45, VT 0.10
    vt01 = 1.0 if vt_mal > 0 else 0.0
    combined = 0.45*heur01 + 0.45*ml_prob + 0.10*vt01

    if combined >= 0.80:
        verdict = "BLOCK"
    elif combined >= 0.55:
        verdict = "QUARANTINE"
    else:
        verdict = "ALLOW"

    return {"verdict": verdict, "confidence": combined, "reasons": reasons, "vt_malicious": vt_mal}

def analyze(parsed: Dict[str, Any]) -> Dict[str, Any]:
    # Heuristic scores
    h_score, h_reasons = score_headers(parsed.get("raw_headers",""), parsed.get("from_addr",""))
    u_score, u_reasons = score_urls(parsed.get("urls", []))
    b_score, b_reasons = score_body(parsed.get("body",""))

    heur_total = min(h_score + u_score + b_score, 100)

    # ML
    model = load_model()
    text_for_ml = (parsed.get("subject","") + " " + parsed.get("body","")).strip()
    ml_prob = float(model.predict_proba([text_for_ml])[0][1])
    ml_reason = f"ML suggests phishing (p={ml_prob:.2f})" if ml_prob >= 0.5 else f"ML suggests ham (p={1-ml_prob:.2f})"

    # VirusTotal (optional)
    vt_stats = scan_urls(parsed.get("urls", []))

    combo = combine_scores(heur_total, ml_prob, vt_stats)

    return {
        "verdict": combo["verdict"],
        "confidence": round(combo["confidence"], 3),
        "scores": {
            "heuristics": heur_total,
            "ml": round(ml_prob, 3),
            "vt_malicious": combo["vt_malicious"]
        },
        "reasons": h_reasons + u_reasons + b_reasons + ([ml_reason] if ml_reason else []) + combo["reasons"],
        "artifacts": {
            "subject": parsed.get("subject",""),
            "from_addr": parsed.get("from_addr",""),
            "urls": parsed.get("urls", [])
        }
    }
