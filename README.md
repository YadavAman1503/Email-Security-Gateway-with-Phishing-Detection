# Email Security Gateway with Phishing Detection

A beginner-friendly Email Security Gateway that analyzes messages for phishing using **header checks**, **URL heuristics**, optional **VirusTotal URL reputation**, and a **simple ML classifier**.

## What you get
- CLI scanner to analyze raw text or `.eml` files
- REST API (FastAPI) to accept scans programmatically
- Heuristic rules: header anomalies, suspicious keywords, risky URLs
- Optional VirusTotal URL reputation (if you provide `VT_API_KEY`)
- Tiny demo dataset + ML model (TF-IDF + Logistic Regression)
- Clear JSON report with reasons & scores

---

## 1) Prerequisites
- Python 3.10+
- Windows PowerShell or macOS/Linux terminal
- (Optional) VirusTotal API key — create an account and copy your key

## 2) Setup (one-time)
```powershell
# 2.1. Unzip and enter the project
cd email-security-gateway

# 2.2. Create & activate virtual environment
python -m venv venv
venv\Scripts\activate     # Windows
# source venv/bin/activate  # macOS/Linux

# 2.3. Install dependencies
pip install -r requirements.txt

# 2.4. (Optional) Copy .env.example → .env and add your VT_API_KEY
copy .env.example .env      # Windows
# cp .env.example .env      # macOS/Linux
# then edit .env and paste your API key
```

## 3) Train the ML model (using the tiny demo dataset)
```powershell
python src/ml_model.py --train
```
This will create `models/phish_clf.joblib`.

## 4) Run CLI scanner
```powershell
# Scan raw text
python src/cli.py --text "Urgent: verify your account now at http://malicious.example.com"

# Scan an .eml file (see data/sample_emails/)
python src/cli.py --file data/sample_emails/phish_sample.eml
```

## 5) Run REST API
```powershell
uvicorn src.app:app --reload --port 8000
```
Then send a request (PowerShell example):
```powershell
$body = @{
  subject = "Payment notice"
  from_addr = "billing@pay-secure.example"
  raw_headers = "Authentication-Results: spf=fail; dkim=none"
  body = "Please verify payment within 24 hours at http://pay-secure.example/verify"
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/scan -ContentType "application/json" -Body $body
```

## 6) Interpreting results
You’ll get a JSON like:
```json
{
  "verdict": "QUARANTINE",
  "confidence": 0.86,
  "scores": {"heuristics": 58, "ml": 0.74, "vt_malicious": 0},
  "reasons": [
    "Header anomaly: SPF fail",
    "Suspicious URL: IP or many subdomains",
    "ML suggests phishing (p=0.74)"
  ]
}
```
- **ALLOW** → likely safe
- **QUARANTINE** → suspicious (review manually)
- **BLOCK** → very likely phishing

## 7) Project structure
```
email-security-gateway/
  ├─ src/
  │  ├─ app.py                # FastAPI app
  │  ├─ cli.py                # Command-line scanner
  │  ├─ pipeline.py           # Orchestrates checks
  │  ├─ email_parser.py       # Parse .eml & extract URLs
  │  ├─ rules.py              # Heuristic rules
  │  ├─ vt_scan.py            # Optional VirusTotal URL checks
  │  └─ ml_model.py           # Train/load ML model
  ├─ data/
  │  ├─ sample_dataset.csv    # Tiny demo dataset
  │  └─ sample_emails/
  │     ├─ ham_sample.eml
  │     └─ phish_sample.eml
  ├─ models/                  # Saved ML model here
  ├─ requirements.txt
  ├─ .env.example
  └─ README.md
```

## 8) Publish to GitHub
```powershell
# Create a new repo on GitHub first (empty)

git init
git add .
git commit -m "Email Security Gateway MVP"
git branch -M main
git remote add origin https://github.com/<your-username>/email-security-gateway.git
git push -u origin main
```

## 9) Share on LinkedIn
- Create a post with:
  - Project summary and what you learned (headers, URLs, ML, VirusTotal).
  - A few screenshots of CLI and API results.
  - Link to your GitHub repo.

### Notes
- This is for **education** and **defensive security** only.
- VirusTotal usage is optional; without a key, the scanner still works with heuristics + ML.
- Improve over time: add HTML parsing, attachment scanning, DMARC policy evaluation, URL sandbox detonation, etc.
