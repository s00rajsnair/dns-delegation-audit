# DNS Delegation Hygiene Audit
A DNS-first, deterministic audit tool that flags externally delegated subdomains with no observable backend. It is built for internal hygiene and governance — not exploitation, takeover validation, or bug bounty automation.

**What it does**
- Resolves CNAME delegations and checks HTTPS reachability
- Classifies delegation state conservatively
- Optionally verifies AWS-backed delegations via control-plane APIs

**What it does not do**
- Exploit or claim resources
- Use provider-specific error signatures
- Infer takeover feasibility

## Quick Start
```bash
python3 dns-delegation-audit.py -i input.txt -o output.csv
```

AWS internal verification example:
```bash
python3 dns-delegation-audit.py -i input.txt -o output.csv \
  --aws-verify --aws-org --aws-role-name DNSDelegationAuditRole --aws-profile corp-audit
```

## Method (High Level)
1. Resolve CNAME. If none, state is `no_delegation`.
2. Check HTTPS reachability (no TLS validation, redirects allowed).
3. Classify state. If `--aws-verify` is enabled and AWS resource exists, mark `verified_internal`.

## States
- `active`: CNAME exists and HTTPS responds
- `potential_dangling`: CNAME exists and HTTPS does not respond
- `verified_internal`: AWS resource exists for an externally unreachable delegation (`--aws-verify` only)
- `no_delegation`: No CNAME record
- `not_applicable`: Non-HTTP DNS labels (e.g. `_dmarc`, `_domainkey`)
- `access_restricted`: Only when `--tcp-check` is enabled (TCP reachable, HTTPS not)

## Output (CSV)
Columns always present:
- `subdomain`, `cname_exists`, `cname`, `provider`, `https_reachable`, `status_code`, `state`, `confidence`, `potential_dangling`

Optional columns:
- `--aws-verify`: `aws_resource_type`, `aws_resource_id`
- `--tcp-check`: `tcp_443_open`, `access_restricted`

When enabled, optional columns are appended to the right of the base schema.

## Command-Line Options
` -i, --input `  Path to input file (one FQDN per line)

` -o, --output `  Path to output CSV

` --timeout `  HTTPS timeout seconds (default 5)

` --workers `  Concurrency (default 40)
Note: for `--aws-verify`, consider reducing `--workers` to avoid AWS API throttling.

` --verbose `  Per-domain logs

` --silent `  Suppress per-domain logs

` --tcp-check `  Enable TCP/443 probing and `access_restricted`

` --aws-verify `  Enable AWS internal verification

` --aws-org `  Enumerate accounts via AWS Organizations

` --aws-accounts `  Comma-separated AWS account IDs

` --aws-role-name `  Role name to assume in each account

` --aws-profile `  AWS CLI profile for base credentials

## AWS Verification (Appendix)
AWS verification does **not** require corporate network access. It uses AWS control-plane APIs.

### Supported AWS Services
- CloudFront
- ELB / ALB / NLB

CloudFront verification matches both the distribution domain and any configured aliases. ELB verification supports standard, internal, and dualstack DNS names.
AWS verification only covers CloudFront and ELB/ALB/NLB. Other `amazonaws.com` CNAMEs are not internally verified.

### Prerequisites
- `boto3` installed
- Base credentials with `sts:AssumeRole` into each target account
- Read-only auditor role in each account with:
  - `elasticloadbalancing:DescribeLoadBalancers`
  - `elasticloadbalancing:DescribeInstanceHealth`
  - `elasticloadbalancing:DescribeTargetGroups`
  - `elasticloadbalancing:DescribeTargetHealth`
  - `cloudfront:ListDistributions`
  - `cloudfront:GetDistribution`

If using `--aws-org`, base credentials also need:
- `organizations:ListAccounts`

### Setup Guide (Multi-Account)
1. Create a central audit role in your tooling/security account.
2. Create a read-only auditor role (same name) in every target account.
3. Allow the central role to assume the auditor role in each account.
4. Run the tool with `--aws-org` or `--aws-accounts`.

### Example IAM Policy (Role Permissions)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeInstanceHealth",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "cloudfront:ListDistributions",
        "cloudfront:GetDistribution"
      ],
      "Resource": "*"
    }
  ]
}
```

### Example Trust Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/CorpAuditRole"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### Account List vs Org Mode
Use `--aws-org` when:
- You have `organizations:ListAccounts`
- You want zero manual account maintenance
- You can assume the same auditor role across all accounts

Use `--aws-accounts` when:
- You don’t have Org permissions
- You want to scope to a subset of accounts
- You can maintain a vetted account list

### Setup Diagram
```
Your Machine
  |
  | (base creds / AWS profile)
  v
Central Audit Role (Account A)
  |
  | sts:AssumeRole
  v
Auditor Role (Account 1) ---> Describe ELB/ALB/NLB + CloudFront
Auditor Role (Account 2) ---> Describe ELB/ALB/NLB + CloudFront
Auditor Role (Account N) ---> Describe ELB/ALB/NLB + CloudFront
```

## Limitations
- External-only checks can’t see internal routing or allowlists.
- Results vary by network path, ISP filtering, or outbound policy.
- `potential_dangling` indicates no observable backend, not exploitability.
- Provider detection is best-effort and informational only.

## Intended Audience
Infrastructure, platform, cloud security, and DNS owners responsible for hygiene and governance.

## Primary Use Cases
- DNS hygiene audits
- Infrastructure cleanup
- Attack surface reduction
- Ownership clarification
- Pre/post-migration reviews
