"""
VirusTotal Bulk Enricher
========================
Looks up a list of file hashes, IPs, or domains against the VirusTotal API
and exports a triage report to CSV.

Usage:
    python vt_enricher.py --input iocs.txt --type hash --apikey YOUR_KEY
    python vt_enricher.py --input iocs.txt --type ip --apikey YOUR_KEY
    python vt_enricher.py --input iocs.txt --type domain --apikey YOUR_KEY

Free API tier: 4 requests/minute, 500/day
"""

import argparse
import csv
import json
import time
import sys
from datetime import datetime
from pathlib import Path

import requests

# ── Configuration ─────────────────────────────────────────────────────────────

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Free tier = 4 requests per minute → wait 15s between requests to stay safe
REQUEST_DELAY_SECONDS = 15

# ── API Helpers ────────────────────────────────────────────────────────────────

def vt_get(endpoint: str, api_key: str) -> dict:
    """Send a GET request to the VirusTotal v3 API and return parsed JSON."""
    headers = {"x-apikey": api_key}
    url = f"{VT_BASE_URL}/{endpoint}"
    response = requests.get(url, headers=headers, timeout=15)

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return {"error": "not_found"}
    elif response.status_code == 401:
        print("[!] Invalid API key. Check your key and try again.")
        sys.exit(1)
    elif response.status_code == 429:
        print("[!] Rate limit hit. Waiting 60 seconds...")
        time.sleep(60)
        return vt_get(endpoint, api_key)  # retry once
    else:
        return {"error": f"http_{response.status_code}"}


# ── Parsers — extract the fields we care about ─────────────────────────────────

def parse_hash(data: dict, ioc: str) -> dict:
    """Pull relevant fields from a file hash response."""
    if "error" in data:
        return {"ioc": ioc, "type": "hash", "verdict": data["error"],
                "detections": "", "total_engines": "", "malware_family": "",
                "first_seen": "", "last_seen": "", "tags": ""}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0

    # Try to get the most common malware name from engine results
    results = attrs.get("last_analysis_results", {})
    families = [v.get("result") for v in results.values()
                if v.get("category") == "malicious" and v.get("result")]
    family = max(set(families), key=families.count) if families else ""

    # Verdict label
    if malicious == 0:
        verdict = "CLEAN"
    elif malicious <= 5:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"

    return {
        "ioc": ioc,
        "type": "hash",
        "verdict": verdict,
        "detections": malicious,
        "total_engines": total,
        "malware_family": family,
        "first_seen": attrs.get("first_submission_date", ""),
        "last_seen": attrs.get("last_submission_date", ""),
        "tags": ", ".join(attrs.get("tags", [])),
    }


def parse_ip(data: dict, ioc: str) -> dict:
    """Pull relevant fields from an IP address response."""
    if "error" in data:
        return {"ioc": ioc, "type": "ip", "verdict": data["error"],
                "detections": "", "total_engines": "", "malware_family": "",
                "first_seen": "", "last_seen": "", "tags": ""}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0

    if malicious == 0:
        verdict = "CLEAN"
    elif malicious <= 3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"

    return {
        "ioc": ioc,
        "type": "ip",
        "verdict": verdict,
        "detections": malicious,
        "total_engines": total,
        "malware_family": attrs.get("network", ""),
        "first_seen": attrs.get("whois_date", ""),
        "last_seen": "",
        "tags": ", ".join(attrs.get("tags", [])),
    }


def parse_domain(data: dict, ioc: str) -> dict:
    """Pull relevant fields from a domain response."""
    if "error" in data:
        return {"ioc": ioc, "type": "domain", "verdict": data["error"],
                "detections": "", "total_engines": "", "malware_family": "",
                "first_seen": "", "last_seen": "", "tags": ""}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0

    cats = attrs.get("categories", {})
    category = ", ".join(set(cats.values())) if cats else ""

    if malicious == 0:
        verdict = "CLEAN"
    elif malicious <= 3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"

    return {
        "ioc": ioc,
        "type": "domain",
        "verdict": verdict,
        "detections": malicious,
        "total_engines": total,
        "malware_family": category,
        "first_seen": attrs.get("creation_date", ""),
        "last_seen": attrs.get("last_update_date", ""),
        "tags": ", ".join(attrs.get("tags", [])),
    }


# ── Main lookup logic ──────────────────────────────────────────────────────────

def lookup(ioc: str, ioc_type: str, api_key: str) -> dict:
    """Route the IOC to the correct API endpoint and parser."""
    if ioc_type == "hash":
        data = vt_get(f"files/{ioc}", api_key)
        return parse_hash(data, ioc)
    elif ioc_type == "ip":
        data = vt_get(f"ip_addresses/{ioc}", api_key)
        return parse_ip(data, ioc)
    elif ioc_type == "domain":
        data = vt_get(f"domains/{ioc}", api_key)
        return parse_domain(data, ioc)
    else:
        return {"ioc": ioc, "type": ioc_type, "verdict": "unsupported_type",
                "detections": "", "total_engines": "", "malware_family": "",
                "first_seen": "", "last_seen": "", "tags": ""}


# ── Report writer ──────────────────────────────────────────────────────────────

def write_csv(results: list, output_path: str):
    """Write the list of result dicts to a CSV file."""
    if not results:
        print("[!] No results to write.")
        return

    fieldnames = ["ioc", "type", "verdict", "detections", "total_engines",
                  "malware_family", "first_seen", "last_seen", "tags"]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[+] Report saved to: {output_path}")


def print_summary(results: list):
    """Print a quick summary to the terminal."""
    verdicts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "CLEAN": 0, "other": 0}
    for r in results:
        v = r.get("verdict", "other")
        if v in verdicts:
            verdicts[v] += 1
        else:
            verdicts["other"] += 1

    print("\n" + "=" * 40)
    print("  TRIAGE SUMMARY")
    print("=" * 40)
    print(f"  MALICIOUS  : {verdicts['MALICIOUS']}")
    print(f"  SUSPICIOUS : {verdicts['SUSPICIOUS']}")
    print(f"  CLEAN      : {verdicts['CLEAN']}")
    print(f"  ERRORS     : {verdicts['other']}")
    print(f"  TOTAL      : {len(results)}")
    print("=" * 40)

    malicious = [r for r in results if r["verdict"] == "MALICIOUS"]
    if malicious:
        print("\n[!] MALICIOUS IOCs:")
        for r in malicious:
            print(f"    {r['ioc']}  ({r['detections']}/{r['total_engines']} engines)"
                  + (f"  [{r['malware_family']}]" if r['malware_family'] else ""))


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="VirusTotal Bulk Enricher — threat hunting triage tool"
    )
    parser.add_argument("--input",   required=True, help="Path to text file with one IOC per line")
    parser.add_argument("--type",    required=True, choices=["hash", "ip", "domain"],
                        help="Type of IOCs in the input file")
    parser.add_argument("--apikey",  required=True, help="Your VirusTotal API key")
    parser.add_argument("--output",  default="", help="Output CSV filename (optional)")
    args = parser.parse_args()

    # Read IOCs from file, skip blank lines and comments
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    iocs = [line.strip() for line in input_path.read_text().splitlines()
            if line.strip() and not line.startswith("#")]

    if not iocs:
        print("[!] No IOCs found in input file.")
        sys.exit(1)

    print(f"[*] Loaded {len(iocs)} IOCs of type '{args.type}'")
    print(f"[*] Estimated time: ~{len(iocs) * REQUEST_DELAY_SECONDS // 60} min "
          f"{len(iocs) * REQUEST_DELAY_SECONDS % 60} sec (free tier rate limit)\n")

    # Determine output filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = args.output or f"vt_report_{args.type}_{timestamp}.csv"

    results = []
    for i, ioc in enumerate(iocs, 1):
        print(f"[{i}/{len(iocs)}] Looking up: {ioc}", end=" ... ", flush=True)
        result = lookup(ioc, args.type, args.apikey)
        verdict = result.get("verdict", "?")
        det = result.get("detections", "")
        tot = result.get("total_engines", "")
        label = f"{verdict} ({det}/{tot})" if det != "" else verdict
        print(label)
        results.append(result)

        # Rate limit pause (skip after last item)
        if i < len(iocs):
            time.sleep(REQUEST_DELAY_SECONDS)

    print_summary(results)
    write_csv(results, output_file)


if __name__ == "__main__":
    main()
