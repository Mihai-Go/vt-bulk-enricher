# VirusTotal Bulk Enricher 🔍

A command-line threat hunting tool that automates bulk IOC lookups against the VirusTotal API and exports a triage report to CSV.

Instead of manually checking hundreds of IPs, hashes, or domains one by one on the VirusTotal website — you feed this script a list and get back a clean, sortable report in minutes.

---

## What it does

- Accepts a list of **file hashes** (MD5/SHA1/SHA256), **IP addresses**, or **domains**
- Queries the VirusTotal v3 API for each one
- Labels each IOC as `MALICIOUS`, `SUSPICIOUS`, or `CLEAN`
- Exports a full CSV report with detection counts, malware family, first/last seen dates, and tags
- Prints a live summary to the terminal during the run
- Handles rate limiting automatically (free tier: 4 requests/minute)

---

## Example output

```
[*] Loaded 5 IOCs of type 'ip'
[*] Estimated time: ~1 min 15 sec

[1/5] Looking up: 185.220.101.45 ... MALICIOUS (72/94)
[2/5] Looking up: 8.8.8.8 ... CLEAN (0/94)
[3/5] Looking up: 1.1.1.1 ... CLEAN (0/94)
[4/5] Looking up: 45.33.32.156 ... SUSPICIOUS (3/94)
[5/5] Looking up: 192.168.1.1 ... not_found

========================================
  TRIAGE SUMMARY
========================================
  MALICIOUS  : 1
  SUSPICIOUS : 1
  CLEAN      : 2
  ERRORS     : 1
  TOTAL      : 5
========================================

[!] MALICIOUS IOCs:
    185.220.101.45  (72/94 engines)
```

---

## Requirements

- Python 3.6+
- `requests` library
- A free VirusTotal API key

---

## Installation

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/vt-bulk-enricher.git
cd vt-bulk-enricher

# 2. Install dependency
pip3 install requests

# 3. Get a free API key at https://www.virustotal.com
```

---

## Usage

```bash
python3 VirusTotal_Bulk_Enricher.py --input iocs.txt --type [hash|ip|domain] --apikey YOUR_KEY
```

### Arguments

| Argument | Required | Description |
|---|---|---|
| `--input` | ✅ | Path to your IOC list (one per line) |
| `--type` | ✅ | Type of IOCs: `hash`, `ip`, or `domain` |
| `--apikey` | ✅ | Your VirusTotal API key |
| `--output` | ❌ | Custom output CSV filename (auto-generated if not set) |

### Examples

```bash
# Check a list of file hashes
python3 VirusTotal_Bulk_Enricher.py --input hashes.txt --type hash --apikey YOUR_KEY

# Check a list of IPs
python3 VirusTotal_Bulk_Enricher.py --input ips.txt --type ip --apikey YOUR_KEY

# Check a list of domains with custom output filename
python3 VirusTotal_Bulk_Enricher.py --input domains.txt --type domain --apikey YOUR_KEY --output report.csv
```

---

## Input file format

Plain `.txt` file, one IOC per line. Lines starting with `#` are treated as comments and skipped.

```
# suspicious IPs from firewall logs - 2026-03-01
185.220.101.45
45.33.32.156
198.51.100.0
```

---

## Output CSV columns

| Column | Description |
|---|---|
| `ioc` | The original IOC value |
| `type` | hash / ip / domain |
| `verdict` | MALICIOUS / SUSPICIOUS / CLEAN / not_found |
| `detections` | Number of engines that flagged it |
| `total_engines` | Total engines that scanned it |
| `malware_family` | Most common malware name (hashes) or category (domains) |
| `first_seen` | First time VT saw this IOC |
| `last_seen` | Most recent submission/update |
| `tags` | Any tags VT has associated with it |

---

## Verdict thresholds

| Verdict | Hashes | IPs & Domains |
|---|---|---|
| CLEAN | 0 detections | 0 detections |
| SUSPICIOUS | 1–5 detections | 1–3 detections |
| MALICIOUS | 6+ detections | 4+ detections |

You can tune these thresholds directly in the script.

---

## Rate limiting

The free VirusTotal API allows **4 requests/minute** and **500 requests/day**. The script automatically waits 15 seconds between each request. If a rate limit error is hit anyway, it backs off for 60 seconds and retries automatically.

If you have a premium API key, set `REQUEST_DELAY_SECONDS = 0` at the top of the script.

---

## ⚠️ Important: Protect your API key

Never hardcode your API key into the script or commit it to GitHub. Always pass it via the `--apikey` argument, or better yet use an environment variable:

```bash
export VT_API_KEY="your_key_here"
python3 VirusTotal_Bulk_Enricher.py --input iocs.txt --type ip --apikey $VT_API_KEY
```

---

## Project structure

```
vt-bulk-enricher/
├── VirusTotal_Bulk_Enricher.py   # main script
├── iocs.txt                      # your IOC list (add to .gitignore)
└── README.md
```

---

## Roadmap / ideas to extend

- [ ] Auto-detect IOC type (hash length, IP regex, domain pattern)
- [ ] Support URL lookups
- [ ] Add HTML report output
- [ ] Slack/email alert when MALICIOUS IOCs are found
- [ ] MISP integration for automatic threat intel sharing

---

## License

MIT License — free to use, modify, and distribute.

---

*Built for threat hunting and SOC triage workflows.*
