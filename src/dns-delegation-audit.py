#!/usr/bin/env python3
"""
DNS Delegation Hygiene Audit
============================

Identify externally delegated subdomains that may no longer have
any backend infrastructure attached.

Designed for DNS hygiene and infrastructure cleanup.
"""

import argparse
import csv
import dns.resolver
import requests
import urllib3
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------------
# Configuration
# -------------------------

DNS_RESOLVERS = ["1.1.1.1", "8.8.8.8"]
DEFAULT_TIMEOUT = 5
DEFAULT_WORKERS = 40
TCP_TIMEOUT = 3
PROGRESS_INTERVAL = 25

PROVIDER_MAP = {
    "cloudfront.net": "AWS CloudFront",
    "elb.amazonaws.com": "AWS ELB / ALB",
    "amazonaws.com": "AWS",
    "azurewebsites.net": "Azure App Service",
    "trafficmanager.net": "Azure Traffic Manager",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "fastly.net": "Fastly",
    "zendesk.com": "Zendesk",
}

# -------------------------
# Banner
# -------------------------

BANNER = r"""
====================================================
  DNS Delegation Hygiene Audit
  External CNAME Infrastructure Review Tool
====================================================
"""

# -------------------------
# Logging
# -------------------------

def log(msg, verbose, silent):
    if verbose and not silent:
        print(msg, flush=True)

# -------------------------
# Provider detection
# -------------------------

def detect_provider(cname):
    cname = cname.lower()
    for suffix, provider in PROVIDER_MAP.items():
        if suffix in cname:
            return provider
    return "Other"

# -------------------------
# DNS
# -------------------------

def resolve_cname(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = DNS_RESOLVERS
    resolver.timeout = 2
    resolver.lifetime = 2
    try:
        ans = resolver.resolve(domain, "CNAME")
        return True, str(ans[0]).rstrip(".")
    except Exception:
        return False, ""

# -------------------------
# TCP probe
# -------------------------

def tcp_probe(host, port=443):
    try:
        s = socket.create_connection((host, port), timeout=TCP_TIMEOUT)
        s.close()
        return True
    except Exception:
        return False

# -------------------------
# HTTPS
# -------------------------

def check_https(domain, timeout):
    try:
        resp = requests.get(
            f"https://{domain}",
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "dns-delegation-audit"},
        )
        return True, resp.status_code
    except Exception:
        return False, "N/A"

# -------------------------
# Worker
# -------------------------

def process_domain(domain, timeout, verbose, silent):
    tid = threading.get_ident()

    if domain.startswith("_"):
        return [
            domain, "N", "-", "N/A", "N", "N", "N/A",
            "not_applicable", "N/A", "N", "N"
        ]

    log(f"[{domain}][T{tid}] DNS resolving CNAME", verbose, silent)
    cname_exists, cname = resolve_cname(domain)

    if not cname_exists:
        return [
            domain, "N", "-", "N/A", "N", "N", "N/A",
            "no_delegation", "N/A", "N", "N"
        ]

    provider = detect_provider(cname)

    log(f"[{domain}][T{tid}] TCP probe 443", verbose, silent)
    tcp_open = tcp_probe(domain)

    log(f"[{domain}][T{tid}] HTTPS probe", verbose, silent)
    https_ok, status = check_https(domain, timeout)

    # NOTE:
    # "potential_dangling" indicates absence of observable backend
    # infrastructure from an external network perspective.
    # It does NOT imply exploitability or takeover feasibility.
    if not tcp_open and not https_ok:
        state = "potential_dangling"
        potential_dangling = "Y"
        access_restricted = "N"
    elif tcp_open and not https_ok:
        state = "access_restricted"
        potential_dangling = "N"
        access_restricted = "Y"
    else:
        state = "active"
        potential_dangling = "N"
        access_restricted = "N"

    if state == "potential_dangling" and provider != "Other":
        confidence = "high"
    elif state == "potential_dangling":
        confidence = "medium"
    else:
        confidence = "N/A"

    return [
        domain,
        "Y",
        cname,
        provider,
        "Y" if tcp_open else "N",
        "Y" if https_ok else "N",
        status,
        state,
        confidence,
        potential_dangling,
        access_restricted,
    ]

# -------------------------
# Main
# -------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DNS-first external delegation hygiene audit"
    )
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--silent", action="store_true")

    args = parser.parse_args()

    print(BANNER)

    with open(args.input) as f:
        domains = [d.strip() for d in f if d.strip()]

    total = len(domains)
    processed = 0
    counters = Counter()
    lock = threading.Lock()

    with open(args.output, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "subdomain",
            "cname_exists",
            "cname",
            "provider",
            "tcp_443_open",
            "https_reachable",
            "status_code",
            "state",
            "confidence",
            "potential_dangling",
            "access_restricted",
        ])

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    process_domain,
                    d,
                    args.timeout,
                    args.verbose,
                    args.silent,
                ): d
                for d in domains
            }

            for future in as_completed(futures):
                row = future.result()
                writer.writerow(row)
                csvfile.flush()

                with lock:
                    processed += 1
                    state = row[7]
                    confidence = row[8]
                    counters[state] += 1
                    if confidence in ("high", "medium"):
                        counters[f"{confidence}_confidence"] += 1

                    if processed % PROGRESS_INTERVAL == 0 or processed == total:
                        print(
                            f"[PROGRESS] {processed}/{total} domains processed",
                            flush=True,
                        )

    # -------------------------
    # Summary
    # -------------------------

    print("\nSummary")
    print("-------")
    print(f"Total domains        : {total}")
    print(f"No delegation        : {counters['no_delegation']}")
    print(f"Active               : {counters['active']}")
    print(f"Access restricted    : {counters['access_restricted']}")
    print(f"Potential dangling   : {counters['potential_dangling']}")
    print(f"  ├─ High confidence : {counters['high_confidence']}")
    print(f"  └─ Medium confidence: {counters['medium_confidence']}")

if __name__ == "__main__":
    main()
