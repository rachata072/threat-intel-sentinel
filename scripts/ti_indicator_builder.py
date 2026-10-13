#!/usr/bin/env python3
"""
ti_indicator_builder.py

Turn a Sentinel/Defender failed-logon export into clean, reviewable threat
intelligence indicators.

What it does
  1. Reads a CSV exported from KQL (columns: RemoteIP, Count). Extra columns are fine.
  2. Validates every IP with the ipaddress module.
  3. Drops private, loopback, link-local, multicast, reserved and allow-listed IPs.
  4. Scores confidence from the failure count (transparent, tunable thresholds).
  5. Optionally enriches with AbuseIPDB (free tier) if ABUSEIPDB_KEY is set.
  6. Writes indicators.import.json (a plain JSON array, the format Sentinel's
     "Import using a file" JSON template expects), a full STIX 2.1 bundle for
     other platforms, and a review CSV.

Python standard library only. No cost.

Usage
  python ti_indicator_builder.py --input failed_logons.csv --outdir out
  python ti_indicator_builder.py --input failed_logons.csv --allowlist my_ips.txt --valid-days 30
"""

import argparse
import csv
import ipaddress
import json
import os
import sys
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

NAME_PREFIX = "MaliciousFlows"
TLP_AMBER_ID = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"


def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def load_allowlist(path):
    nets = []
    if not path:
        return nets
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                nets.append(ipaddress.ip_network(line, strict=False))
    return nets


def is_routable_public(ip):
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def score_confidence(count):
    """Simple, explainable scoring. Tune these thresholds for your environment."""
    if count >= 500:
        return 85
    if count >= 100:
        return 70
    if count >= 25:
        return 50
    return 30


def abuseipdb_score(ip, key):
    """Optional enrichment. Returns abuse confidence 0-100 or None on any failure."""
    url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode(
        {"ipAddress": ip, "maxAgeInDays": 90}
    )
    req = urllib.request.Request(url, headers={"Key": key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.load(resp)
        return int(data["data"]["abuseConfidenceScore"])
    except Exception as exc:  # network, quota, bad key: never crash the run
        print(f"  enrichment skipped for {ip}: {exc}", file=sys.stderr)
        return None


def read_rows(path):
    rows = []
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        needed = {"RemoteIP", "Count"}
        if not needed.issubset(set(reader.fieldnames or [])):
            sys.exit(f"Input needs columns {sorted(needed)}. Found: {reader.fieldnames}")
        for r in reader:
            rows.append(r)
    return rows


def build_indicator(ip, confidence, count, valid_days, reason, created):
    valid_until = created + timedelta(days=valid_days)
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": iso(created),
        "modified": iso(created),
        "name": f"{NAME_PREFIX} - Brute Force Source - {ip}",
        "description": f"{count} failed logons observed against our endpoints. {reason}",
        "indicator_types": ["malicious-activity"],
        "pattern": f"[ipv4-addr:value = '{ip}']",
        "pattern_type": "stix",
        "valid_from": iso(created),
        "valid_until": iso(valid_until),
        "confidence": confidence,
        "labels": ["brute-force", "first-party-observation", "tlp:amber"],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, help="CSV with RemoteIP,Count")
    ap.add_argument("--outdir", default="out")
    ap.add_argument("--allowlist", help="text file, one IP or CIDR per line, # comments allowed")
    ap.add_argument("--valid-days", type=int, default=30, help="indicator lifetime (default 30)")
    ap.add_argument("--min-count", type=int, default=10, help="ignore IPs below this many failures")
    args = ap.parse_args()

    allow = load_allowlist(args.allowlist)
    key = os.environ.get("ABUSEIPDB_KEY")
    created = now_utc()
    os.makedirs(args.outdir, exist_ok=True)

    indicators, review = [], []
    seen = set()

    for row in read_rows(args.input):
        raw = (row["RemoteIP"] or "").strip()
        try:
            count = int(row["Count"])
        except (TypeError, ValueError):
            review.append([raw, "", "", "skipped", "bad Count value"])
            continue
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            review.append([raw, count, "", "skipped", "not a valid IP"])
            continue
        if ip.version != 4:
            review.append([raw, count, "", "skipped", "IPv6 not handled in this version"])
            continue
        if not is_routable_public(ip):
            review.append([raw, count, "", "skipped", "non-public address"])
            continue
        if any(ip in n for n in allow):
            review.append([raw, count, "", "skipped", "allow-listed (known good)"])
            continue
        if count < args.min_count:
            review.append([raw, count, "", "skipped", f"below min-count {args.min_count}"])
            continue
        if str(ip) in seen:
            review.append([raw, count, "", "skipped", "duplicate"])
            continue
        seen.add(str(ip))

        conf = score_confidence(count)
        reason = "Confidence derived from failure volume."
        if key:
            ext = abuseipdb_score(str(ip), key)
            if ext is not None:
                conf = round((conf + ext) / 2)
                reason = f"Confidence blends our volume score with AbuseIPDB score {ext}."
        indicators.append(build_indicator(str(ip), conf, count, args.valid_days, reason, created))
        review.append([raw, count, conf, "indicator", reason])

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "marking-definition",
                "spec_version": "2.1",
                "id": TLP_AMBER_ID,
                "created": "2017-01-20T00:00:00.000Z",
                "definition_type": "tlp",
                "name": "TLP:AMBER",
                "definition": {"tlp": "amber"},
            }
        ]
        + [dict(i, object_marking_refs=[TLP_AMBER_ID]) for i in indicators],
    }

    import_path = os.path.join(args.outdir, "indicators.import.json")
    with open(import_path, "w", encoding="utf-8") as fh:
        json.dump(indicators, fh, indent=2)

    bundle_path = os.path.join(args.outdir, "indicators.stix.json")
    review_path = os.path.join(args.outdir, "review.csv")
    with open(bundle_path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)
    with open(review_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["RemoteIP", "FailedLogons", "Confidence", "Decision", "Reason"])
        w.writerows(review)

    print(f"Indicators written: {len(indicators)}")
    print(f"Sentinel import:    {import_path}  (use this one)")
    print(f"STIX bundle:        {bundle_path}")
    print(f"Decision log:       {review_path}")
    if not indicators:
        print("No indicators produced. Check the review file for why rows were skipped.")


if __name__ == "__main__":
    main()
