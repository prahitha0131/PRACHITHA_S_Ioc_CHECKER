#!/usr/bin/env python3
"""Simple local IoC checker for cybersecurity learning.

Uses a tiny, clearly labeled example dataset. It does not query live services
or claim that unknown indicators are safe or malicious.
"""
import argparse
import ipaddress
import re

# Example records for demonstration only; not live threat intelligence.
SAMPLE_INDICATORS = {
    "198.51.100.23": {"type": "IPv4", "status": "example-listed", "risk": "HIGH", "note": "Documentation-only example address"},
    "203.0.113.42": {"type": "IPv4", "status": "example-listed", "risk": "MEDIUM", "note": "Documentation-only example address"},
    "example.test": {"type": "domain", "status": "example-listed", "risk": "LOW", "note": "Reserved example domain"},
}


def identify_type(value):
    """Return a basic type label for an IPv4/IPv6 address, hash, or domain."""
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return "IP address"
    except ValueError:
        pass
    if re.fullmatch(r"(?i)(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", value):
        return "file hash"
    if re.fullmatch(r"(?i)(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*", value):
        return "domain"
    return "unknown"


def check_indicator(value):
    """Look up an indicator in the local examples; unknown means no local match."""
    normalized = value.strip().lower()
    kind = identify_type(normalized)
    if kind == "unknown":
        return {"indicator": value, "type": kind, "status": "invalid-format", "risk": "UNKNOWN", "note": "Enter an IP address, domain, or MD5/SHA-1/SHA-256 hash."}
    record = SAMPLE_INDICATORS.get(normalized)
    if record:
        return {"indicator": value, **record}
    return {"indicator": value, "type": kind, "status": "not-in-example-dataset", "risk": "UNKNOWN", "note": "No local sample match. This does not mean the indicator is safe."}


def main():
    parser = argparse.ArgumentParser(description="Check an indicator against a tiny local teaching dataset.")
    parser.add_argument("indicator", help="IP address, domain, or file hash")
    args = parser.parse_args()
    result = check_indicator(args.indicator)
    print("Local IoC Check (teaching demo)")
    for key, value in result.items():
        print(f"{key.title()}: {value}")
    print("\nData note: sample records only; no live reputation lookup was performed.")


if __name__ == "__main__":
    main()
