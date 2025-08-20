from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

from src.email_parser import extract_urls
from src.pipeline import analyze

# Initialize FastAPI app
app = FastAPI(
    title="Email Security Gateway API",
    version="0.1.0",
    description="API to scan and analyze emails for potential phishing or malicious content"
)

# Request schema
class ScanRequest(BaseModel):
    subject: Optional[str] = ""
    from_addr: Optional[str] = ""
    raw_headers: Optional[str] = ""
    body: Optional[str] = ""

# Health check endpoint
@app.get("/health")
def health():
    return {"status": "ok"}

# Email scanning endpoint
@app.post("/scan")
def scan(req: ScanRequest):
    parsed = {
        "subject": req.subject or "",
        "from_addr": req.from_addr or "",
        "raw_headers": req.raw_headers or "",
        "body": req.body or "",
        "urls": extract_urls(req.body or ""),
    }
    result = analyze(parsed)
    return result
