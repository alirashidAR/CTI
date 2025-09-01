#!/usr/bin/env python3
# Check if IP, Domain, URL, or File Hash is malicious using AlienVault OTX
import argparse
import hashlib
import requests

# Your OTX API key (free after signup at https://otx.alienvault.com/)
API_KEY = ""
OTX_SERVER = "https://otx.alienvault.com/api/v1/indicators"

HEADERS = {"X-OTX-API-KEY": "080a3a1bc30860ca9a0e346e1e24f1bd0e4868efb1a1edb7406d68df24f715d1"}


def check_indicator(indicator_type, indicator):
    url = f"{OTX_SERVER}/{indicator_type}/{indicator}/general"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        data = response.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        if pulses > 0:
            return True, data["pulse_info"]["pulses"]
        else:
            return False, None
    else:
        return None, f"Error {response.status_code}: {response.text}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check IoCs against AlienVault OTX")
    parser.add_argument("-ip", help="IP address, e.g. 8.8.8.8")
    parser.add_argument("-host", help="Domain/Hostname, e.g. example.com")
    parser.add_argument("-url", help="URL, e.g. http://example.com")
    parser.add_argument("-hash", help="File hash (MD5/SHA1/SHA256)")
    parser.add_argument("-file", help="Path to file (will be hashed)")
    args = parser.parse_args()

    if args.ip:
        result, details = check_indicator("IPv4", args.ip)
        print(f"[IP] {args.ip} -> {'MALICIOUS' if result else 'Clean/Unknown'}")

    if args.host:
        result, details = check_indicator("hostname", args.host)
        print(f"[Host] {args.host} -> {'MALICIOUS' if result else 'Clean/Unknown'}")

    if args.url:
        result, details = check_indicator("url", args.url)
        print(f"[URL] {args.url} -> {'MALICIOUS' if result else 'Clean/Unknown'}")

    if args.hash:
        result, details = check_indicator("file", args.hash)
        print(f"[Hash] {args.hash} -> {'MALICIOUS' if result else 'Clean/Unknown'}")

    if args.file:
        file_hash = hashlib.md5(open(args.file, "rb").read()).hexdigest()
        result, details = check_indicator("file", file_hash)
        print(f"[File] {args.file} (MD5={file_hash}) -> {'MALICIOUS' if result else 'Clean/Unknown'}")
