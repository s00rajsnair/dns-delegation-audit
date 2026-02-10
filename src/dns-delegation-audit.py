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

def resolve_cname(domain, max_depth=5, verbose=False, silent=False):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = DNS_RESOLVERS
    resolver.timeout = 2
    resolver.lifetime = 2
    try:
        current = domain
        seen = set()
        for _ in range(max_depth):
            if current in seen:
                break
            seen.add(current)
            ans = resolver.resolve(current, "CNAME")
            target = str(ans[0]).rstrip(".")
            current = target
        return True, current.rstrip(".")
    except Exception as exc:
        log(f"[DNS] CNAME resolve failed for {domain}: {exc}", verbose, silent)
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
# AWS verification (optional)
# -------------------------

def is_aws_candidate(cname):
    c = cname.lower()
    return (
        c.endswith(".cloudfront.net")
        or ".elb.amazonaws.com" in c
        or c.endswith(".amazonaws.com")
    )

def parse_elb_hostname(cname):
    c = cname.lower().rstrip(".")
    parts = c.split(".")
    if len(parts) < 5:
        return None, None, None
    if parts[-3:] != ["elb", "amazonaws", "com"]:
        return None, None, None
    lb_label = parts[-5]
    region = parts[-4]
    if lb_label.startswith("internal-"):
        lb_label = lb_label[len("internal-"):]
    return lb_label, region, c

def strip_elbv2_hash(label):
    # For ALB/NLB, the DNS label often ends with a hash segment.
    # Example: my-lb-1234567890 -> my-lb
    if "-" not in label:
        return label
    base, last = label.rsplit("-", 1)
    if len(last) >= 6 and last.isalnum():
        return base
    return label

def build_aws_context(args):
    if not args.aws_verify:
        return None
    if args.aws_org and args.aws_accounts:
        raise ValueError("Use either --aws-org or --aws-accounts, not both")
    if not args.aws_org and not args.aws_accounts:
        raise ValueError("AWS verification requires --aws-org or --aws-accounts")
    if not args.aws_role_name:
        raise ValueError("AWS verification requires --aws-role-name")
    ctx = {
        "profile": args.aws_profile,
        "role_name": args.aws_role_name,
        "accounts": [],
        "session_cache": {},
        "verify_cache": {},
        "base_session": None,
        "lock": threading.Lock(),
    }
    return ctx

def get_base_boto3_session(profile):
    import boto3
    if profile:
        return boto3.session.Session(profile_name=profile)
    return boto3.session.Session()

def list_org_accounts(profile):
    import boto3
    sess = get_base_boto3_session(profile)
    org = sess.client("organizations")
    accounts = []
    paginator = org.get_paginator("list_accounts")
    for page in paginator.paginate():
        for acct in page.get("Accounts", []):
            if acct.get("Status") == "ACTIVE":
                accounts.append(acct["Id"])
    return accounts

def assume_role_session(base_session, account_id, role_name, region):
    import boto3
    sts = base_session.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    resp = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="dns-delegation-audit",
    )
    creds = resp["Credentials"]
    return boto3.session.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )

def log_aws_error(prefix, err, verbose, silent):
    try:
        code = err.response.get("Error", {}).get("Code", "Unknown")
        msg = err.response.get("Error", {}).get("Message", "")
        log(f"{prefix}: {code} {msg}", verbose, silent)
    except Exception:
        log(f"{prefix}: error", verbose, silent)

def get_account_session(ctx, account_id, region):
    key = (account_id, region)
    with ctx["lock"]:
        if key in ctx["session_cache"]:
            return ctx["session_cache"][key]
        if ctx["base_session"] is None:
            ctx["base_session"] = get_base_boto3_session(ctx["profile"])
        base = ctx["base_session"]
    sess = assume_role_session(base, account_id, ctx["role_name"], region)
    with ctx["lock"]:
        ctx["session_cache"][key] = sess
    return sess

def cache_get(ctx, key):
    with ctx["lock"]:
        return ctx["verify_cache"].get(key)

def cache_set(ctx, key, value):
    with ctx["lock"]:
        ctx["verify_cache"][key] = value

def verify_elbv2(session, lb_names, verbose, silent):
    import botocore
    elbv2 = session.client("elbv2")
    for name in lb_names:
        try:
            resp = elbv2.describe_load_balancers(Names=[name])
        except botocore.exceptions.ClientError as err:
            log_aws_error("[AWS] elbv2 describe_load_balancers", err, verbose, silent)
            continue
        lbs = resp.get("LoadBalancers", [])
        if not lbs:
            continue
        lb = lbs[0]
        lb_arn = lb["LoadBalancerArn"]
        lb_type = lb.get("Type", "elbv2")
        try:
            tgs = elbv2.describe_target_groups(LoadBalancerArn=lb_arn).get(
                "TargetGroups", []
            )
            for tg in tgs:
                th = elbv2.describe_target_health(
                    TargetGroupArn=tg["TargetGroupArn"]
                )
                _ = th.get("TargetHealthDescriptions", [])
        except botocore.exceptions.ClientError as err:
            log_aws_error("[AWS] elbv2 target health check", err, verbose, silent)
            log("[AWS] elbv2 target health check failed", verbose, silent)
        return True, f"elbv2:{lb_type}", lb_arn
    return False, None, None

def verify_elb_classic(session, lb_name, verbose, silent):
    import botocore
    elb = session.client("elb")
    try:
        resp = elb.describe_load_balancers(LoadBalancerNames=[lb_name])
    except botocore.exceptions.ClientError as err:
        log_aws_error("[AWS] classic elb describe_load_balancers", err, verbose, silent)
        return False, None, None
    lbs = resp.get("LoadBalancerDescriptions", [])
    if not lbs:
        return False, None, None
    lb = lbs[0]
    name = lb.get("LoadBalancerName")
    try:
        instances = lb.get("Instances", [])
        if instances:
            elb.describe_instance_health(LoadBalancerName=name)
    except botocore.exceptions.ClientError as err:
        log_aws_error("[AWS] classic elb describe_instance_health", err, verbose, silent)
        log("[AWS] classic ELB health check failed", verbose, silent)
    return True, "elb_classic", name

def verify_cloudfront(session, cname, verbose, silent):
    import botocore
    cf = session.client("cloudfront")
    paginator = cf.get_paginator("list_distributions")
    cname_lower = cname.lower()
    for page in paginator.paginate():
        dist_list = page.get("DistributionList", {})
        for dist in dist_list.get("Items", []):
            domain = (dist.get("DomainName") or "").lower()
            aliases = dist.get("Aliases", {}).get("Items", []) or []
            aliases_lower = [a.lower() for a in aliases]
            if cname_lower == domain or cname_lower in aliases_lower:
                dist_id = dist.get("Id")
                try:
                    cf.get_distribution(Id=dist_id)
                except botocore.exceptions.ClientError as err:
                    log_aws_error("[AWS] cloudfront get_distribution", err, verbose, silent)
                    log("[AWS] cloudfront get_distribution failed", verbose, silent)
                return True, "cloudfront", dist_id
    return False, None, None

def verify_aws_resource(ctx, cname, verbose, silent):
    cname = cname.rstrip(".")
    cache_key = f"aws:{cname.lower()}"
    cached = cache_get(ctx, cache_key)
    if cached is not None:
        return cached
    accounts = ctx["accounts"]
    # CloudFront is global
    if cname.lower().endswith(".cloudfront.net"):
        region = "us-east-1"
        for account_id in accounts:
            session = get_account_session(ctx, account_id, region)
            ok, rtype, rid = verify_cloudfront(session, cname, verbose, silent)
            if ok:
                result = (True, rtype, rid)
                cache_set(ctx, cache_key, result)
                return result
        result = (False, None, None)
        cache_set(ctx, cache_key, result)
        return result

    lb_label, region, _ = parse_elb_hostname(cname)
    if not lb_label or not region:
        result = (False, None, None)
        cache_set(ctx, cache_key, result)
        return result

    elbv2_names = [lb_label, strip_elbv2_hash(lb_label)]
    for account_id in accounts:
        session = get_account_session(ctx, account_id, region)
        ok, rtype, rid = verify_elbv2(session, elbv2_names, verbose, silent)
        if ok:
            result = (True, rtype, rid)
            cache_set(ctx, cache_key, result)
            return result
        ok, rtype, rid = verify_elb_classic(session, lb_label, verbose, silent)
        if ok:
            result = (True, rtype, rid)
            cache_set(ctx, cache_key, result)
            return result
    result = (False, None, None)
    cache_set(ctx, cache_key, result)
    return result

# -------------------------
# Worker
# -------------------------

def process_domain(domain, timeout, verbose, silent, tcp_check, aws_ctx):
    tid = threading.get_ident()
    aws_verify = aws_ctx is not None
    tcp_open = None
    access_restricted = None

    def build_row(
        cname_exists,
        cname,
        provider,
        https_reachable,
        status_code,
        state,
        confidence,
        potential_dangling,
        tcp_open=None,
        access_restricted=None,
        aws_resource_type="N/A",
        aws_resource_id="N/A",
    ):
        if tcp_check:
            row = [
                domain,
                cname_exists,
                cname,
                provider,
                tcp_open,
                https_reachable,
                status_code,
                state,
                confidence,
                potential_dangling,
                access_restricted,
            ]
        else:
            row = [
                domain,
                cname_exists,
                cname,
                provider,
                https_reachable,
                status_code,
                state,
                confidence,
                potential_dangling,
            ]
        if aws_verify:
            row += [aws_resource_type, aws_resource_id]
        return row

    if domain.startswith("_"):
        return build_row(
            "N",
            "-",
            "N/A",
            "N",
            "N/A",
            "not_applicable",
            "N/A",
            "N",
            tcp_open="N" if tcp_check else None,
            access_restricted="N" if tcp_check else None,
        )

    log(f"[{domain}][T{tid}] DNS resolving CNAME", verbose, silent)
    cname_exists, cname = resolve_cname(domain, verbose=verbose, silent=silent)

    if not cname_exists:
        return build_row(
            "N",
            "-",
            "N/A",
            "N",
            "N/A",
            "no_delegation",
            "N/A",
            "N",
            tcp_open="N" if tcp_check else None,
            access_restricted="N" if tcp_check else None,
        )

    provider = detect_provider(cname)

    log(f"[{domain}][T{tid}] HTTPS probe", verbose, silent)
    https_ok, status = check_https(domain, timeout)

    if tcp_check:
        log(f"[{domain}][T{tid}] TCP probe 443", verbose, silent)
        tcp_open = tcp_probe(domain)

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
    else:
        # NOTE:
        # "potential_dangling" indicates absence of observable backend
        # infrastructure from an external network perspective.
        # It does NOT imply exploitability or takeover feasibility.
        if https_ok:
            state = "active"
            potential_dangling = "N"
        else:
            state = "potential_dangling"
            potential_dangling = "Y"

    if state == "potential_dangling" and provider != "Other":
        confidence = "high"
    elif state == "potential_dangling":
        confidence = "medium"
    else:
        confidence = "N/A"

    aws_resource_type = "N/A"
    aws_resource_id = "N/A"
    if aws_verify and state == "potential_dangling" and is_aws_candidate(cname):
        try:
            ok, rtype, rid = verify_aws_resource(aws_ctx, cname, verbose, silent)
        except Exception:
            log("[AWS] verification error", verbose, silent)
            ok, rtype, rid = False, None, None
        if ok:
            state = "verified_internal"
            confidence = "N/A"
            potential_dangling = "N"
            aws_resource_type = rtype
            aws_resource_id = rid

    return build_row(
        "Y",
        cname,
        provider,
        "Y" if https_ok else "N",
        status,
        state,
        confidence,
        potential_dangling,
        tcp_open="Y" if tcp_open else "N" if tcp_check else None,
        access_restricted=access_restricted if tcp_check else None,
        aws_resource_type=aws_resource_type,
        aws_resource_id=aws_resource_id,
    )

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
    parser.add_argument("--tcp-check", action="store_true")
    parser.add_argument("--aws-verify", action="store_true")
    parser.add_argument("--aws-org", action="store_true")
    parser.add_argument("--aws-accounts")
    parser.add_argument("--aws-role-name")
    parser.add_argument("--aws-profile")

    args = parser.parse_args()

    print(BANNER)

    aws_ctx = None
    if args.aws_verify:
        try:
            import boto3  # noqa: F401
        except ModuleNotFoundError:
            print("ERROR: boto3 is required for --aws-verify")
            return
        try:
            aws_ctx = build_aws_context(args)
        except ValueError as exc:
            print(f"ERROR: {exc}")
            return
        if args.aws_org:
            aws_ctx["accounts"] = list_org_accounts(args.aws_profile)
        else:
            aws_ctx["accounts"] = [
                a.strip() for a in args.aws_accounts.split(",") if a.strip()
            ]
        if not aws_ctx["accounts"]:
            print("ERROR: No AWS accounts provided or discovered")
            return

    with open(args.input) as f:
        domains = [d.strip() for d in f if d.strip()]

    total = len(domains)
    processed = 0
    counters = Counter()
    lock = threading.Lock()

    with open(args.output, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        if args.tcp_check:
            header = [
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
            ]
        else:
            header = [
                "subdomain",
                "cname_exists",
                "cname",
                "provider",
                "https_reachable",
                "status_code",
                "state",
                "confidence",
                "potential_dangling",
            ]
        if args.aws_verify:
            header += ["aws_resource_type", "aws_resource_id"]
        writer.writerow(header)

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    process_domain,
                    d,
                    args.timeout,
                    args.verbose,
                    args.silent,
                    args.tcp_check,
                    aws_ctx,
                ): d
                for d in domains
            }

            for future in as_completed(futures):
                row = future.result()
                writer.writerow(row)
                csvfile.flush()

                with lock:
                    processed += 1
                    state = row[7] if args.tcp_check else row[6]
                    confidence = row[8] if args.tcp_check else row[7]
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
    if args.aws_verify:
        print(f"Verified internal    : {counters['verified_internal']}")
    if args.tcp_check:
        print(f"Access restricted    : {counters['access_restricted']}")
    print(f"Potential dangling   : {counters['potential_dangling']}")
    print(f"  ├─ High confidence : {counters['high_confidence']}")
    print(f"  └─ Medium confidence: {counters['medium_confidence']}")
    if args.aws_verify:
        print("AWS verification scope: CloudFront + ELB/ALB/NLB only")

if __name__ == "__main__":
    main()
