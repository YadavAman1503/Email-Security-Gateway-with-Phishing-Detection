
import argparse
import json
import sys

from .email_parser import parse_eml_bytes, extract_urls
from .pipeline import analyze

def main():
    ap = argparse.ArgumentParser(description="Email Security Gateway CLI")
    ap.add_argument("--file", type=str, help="Path to .eml file")
    ap.add_argument("--text", type=str, help="Raw email body text to scan")
    ap.add_argument("--subject", type=str, default="", help="Optional subject when using --text")
    ap.add_argument("--from_addr", type=str, default="", help="Optional from address when using --text")
    args = ap.parse_args()

    if not args.file and not args.text:
        print("Provide --file or --text", file=sys.stderr)
        sys.exit(2)

    parsed = None
    if args.file:
        with open(args.file, "rb") as f:
            raw = f.read()
        parsed = parse_eml_bytes(raw)
    else:
        parsed = {
            "subject": args.subject or "",
            "from_addr": args.from_addr or "",
            "raw_headers": "",
            "body": args.text or "",
            "urls": extract_urls(args.text or "")
        }

    result = analyze(parsed)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
