#!/usr/bin/env python3

"""
Stage 2: Data Enrichment for SSH Attempt Logs
Enriches JSONL SSH logs with:
- ASN lookup
- Country lookup
- Reverse DNS
- Host reputation flags
- Suspicious behaviour heuristics
Outputs enriched JSONL + Parquet
"""

import json
import os
import socket
import pandas as pd
from ipwhois import IPWhois
from tqdm import tqdm

BASE_DIR = "/var/log/ssh_monitor"  # Same as Stage 1
MONTH = "2025-01"  # Example; set dynamically or via CLI

INPUT_DIR = f"{BASE_DIR}/{MONTH}"
OUTPUT_FILE_JSONL = f"{INPUT_DIR}/enriched-{MONTH}.jsonl"
OUTPUT_FILE_PARQUET = f"{INPUT_DIR}/enriched-{MONTH}.parquet"

def asn_lookup(ip):
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        return {
            "asn": result.get("asn"),
            "asn_description": result.get("asn_description")
        }
    except:
        return {"asn": None, "asn_description": None}

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def load_jsonl(directory):
    entries = []
    for file in os.listdir(directory):
        if file.startswith("attempts-") and file.endswith(".jsonl"):
            with open(os.path.join(directory, file), "r") as f:
                for line in f:
                    entries.append(json.loads(line))
    return entries

print("Loading raw attempts...")
records = load_jsonl(INPUT_DIR)

enriched = []

print("Enriching records...")
for item in tqdm(records):
    ip = item["source_ip"]
    
    asn_data = asn_lookup(ip)
    hostname = reverse_dns(ip)

    enriched.append({
        **item,
        "asn": asn_data["asn"],
        "asn_description": asn_data["asn_description"],
        "hostname": hostname,
        "is_cloud_provider": "amazon" in (asn_data["asn_description"] or "").lower() or 
                             "google" in (asn_data["asn_description"] or "").lower(),
        "is_bot_suspected": item["result"] in ["failed", "invalid_user"]
                             and hostname is None
    })

print("Saving enriched dataset...")

with open(OUTPUT_FILE_JSONL, "w") as f:
    for row in enriched:
        f.write(json.dumps(row) + "\n")

df = pd.DataFrame(enriched)
df.to_parquet(OUTPUT_FILE_PARQUET)

print(f"Enrichment complete.\nJSONL: {OUTPUT_FILE_JSONL}\nPARQUET: {OUTPUT_FILE_PARQUET}")
