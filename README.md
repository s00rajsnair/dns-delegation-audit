# DNS Delegation Hygiene Audit
A DNS-first audit tool to identify externally delegated subdomains that may no longer have any observable backend infrastructure attached. This tool performs CNAME resolution, TCP/443 reachability, and HTTPS reachability checks, and classifies delegation state to support DNS hygiene, infrastructure cleanup, and attack surface reduction.
It is not an exploit, subdomain takeover, or bug bounty automation tool.

## What This Tool Is (and Is Not)
This tool is:
- A DNS-first visibility and hygiene audit
- Designed for infrastructure, platform, and security engineering teams
- Focused on identifying stale or unclear external DNS delegations
- Conservative by design, favoring signal quality over aggressiveness

This tool is not:
- A subdomain takeover exploitation framework
- A provider-specific error signature matcher
- A bug bounty automation or vulnerability scanner
- A proof-of-impact or exploit validation tool
If you are looking to confirm exploitability or claim resources, this tool is intentionally not designed for that purpose.

## Why This Tool Exists
Modern organizations routinely delegate subdomains to external platforms such as CDNs, cloud load balancers, SaaS services, and third-party vendors using DNS CNAME records. Over time, these delegations frequently outlive the backend infrastructure they were created for.

Common causes include:
- application decommissioning
- proof-of-concept deployments never cleaned up
- vendor migrations
- environment teardown (staging, UAT, regional)
- team or ownership changes

In many organizations, DNS management and infrastructure ownership are handled by different teams. As a result, DNS records often persist even after backend resources are removed.
This creates two practical problems:

### 1. Infrastructure hygiene gaps
Externally delegated subdomains with no active backend represent unmanaged surface area. Even when not exploitable, they:
- increase operational ambiguity
- complicate asset inventories
- obscure ownership and responsibility
- add unnecessary external exposure

### 2. Poor signal from existing tools
Most existing tools in this space are built for offensive security and bug bounty workflows. They:
- rely on brittle provider-specific signatures
- conflate reachability with exploitability
- generate high false-positive rates
- are noisy for internal cleanup and governance use cases

Infrastructure and platform teams typically need a different answer:
- Is this subdomain still backed by any observable infrastructure?
- Is access intentionally restricted?
- Or does this delegation appear to no longer serve a backend at all?

This tool exists to answer those questions conservatively, without attempting exploitation, resource claiming, or provider-specific takeover logic.

## Design Principles
This tool is built around a few explicit design choices:
- DNS-first
  All analysis starts from DNS delegation, not HTTP error patterns.
- Conservative classification
  Absence of reachability is treated as a potential hygiene issue, not a confirmed vulnerability.
- Provider-agnostic
  Provider detection is informational only and does not affect classification logic.
- Low-noise output
  The goal is to support cleanup and review, not overwhelm teams with speculative findings.
- Externally observable perspective
  All checks reflect what is visible from an external network, not internal routing or allowlists.

## High-Level Methodology
The tool evaluates each input subdomain using a **DNS-first, externally observable workflow**.
For every subdomain, the following steps are performed:

### 1. CNAME Resolution
The tool checks whether the subdomain resolves to a **CNAME record**.
- If no CNAME exists, the subdomain is classified as `no_delegation`
- If a CNAME exists, the delegation target is recorded for visibility

Only CNAME-based delegations are evaluated, as these represent external service attachment patterns commonly used for:
- CDNs
- cloud load balancers
- SaaS integrations
- managed platforms

Non-HTTP DNS labels (e.g. `_acme-challenge`, DKIM selectors) are explicitly excluded from analysis.

### 2. TCP Reachability (Port 443)
For CNAME-delegated subdomains, the tool performs a **TCP connection attempt on port 443**.
This check answers a narrow but important question:

> Is there *any* process listening on the expected HTTPS port from an external network?

This step helps distinguish:
- infrastructure that exists but may restrict access
- infrastructure that no longer exists at all

No protocol negotiation or TLS validation is performed at this stage.

### 3. HTTPS Reachability
An HTTPS request is made to the subdomain:
- TLS verification is disabled
- redirects are followed
- no assumptions are made about application behavior

The intent is **not** to validate correctness, authentication, or content — only whether the HTTPS stack responds at all.
The returned HTTP status code is recorded **for operator context only** and does not drive state classification.

### 4. State Classification
Using the combination of DNS, TCP, and HTTPS observations, each subdomain is classified into a single state:

- `active`
- `access_restricted`
- `potential_dangling`
- `no_delegation`
- `not_applicable`

Classification logic is intentionally minimal and deterministic, avoiding provider-specific heuristics or error message parsing.

## State Definitions

### `active`
- CNAME exists
- TCP/443 is reachable
- HTTPS responds

This indicates observable backend infrastructure is present.

### `access_restricted`
- CNAME exists
- TCP/443 is reachable
- HTTPS does **not** respond successfully

This commonly indicates:
- IP allowlisting
- WAF or firewall enforcement
- internal-only access
- authentication-gated endpoints

These delegations typically require **ownership confirmation**, not removal.

### `potential_dangling`
- CNAME exists
- TCP/443 is **not** reachable
- HTTPS does **not** respond

This indicates **no externally observable backend infrastructure**.

Importantly:
- This does **not** imply exploitability
- This does **not** imply takeover feasibility
- This **does** indicate a delegation that merits review or cleanup

### `no_delegation`
- No CNAME record exists for the subdomain

These entries are retained in output for completeness and reporting consistency.

### `not_applicable`
- DNS labels not intended for HTTP/S usage (e.g. `_domainkey`, `_acme-challenge`)

These are explicitly excluded to reduce noise.

## Confidence Scoring
A lightweight confidence indicator is provided **only for prioritization**:

- `high` — potential_dangling with a recognized external provider
- `medium` — potential_dangling with an unrecognized provider
- `N/A` — all other states

Confidence does **not** indicate exploit likelihood.  
It is a signal to help teams triage cleanup effort.

## Input Requirements and Validation
This tool expects a **clean, pre-curated list of DNS names** as input.

Each line in the input file must contain:
- a fully qualified domain name (FQDN)
- one domain per line
- no protocol prefixes (`https://`, `http://`)
- no ports
- no wildcards

Example:
example.domain.com
api.service.company.com
cdn.assets.company.net

The tool is intentionally strict about input expectations. It does **not** attempt to normalize, guess, or repair malformed input.

### Explicitly Excluded Inputs
The following are ignored or classified as not applicable:

- non-HTTP DNS labels (e.g. `_acme-challenge`, `_domainkey`, `_dmarc`)
- DKIM selectors
- SRV-style service records
- internal DNS-only naming conventions

These records are preserved in output with a `not_applicable` state to:
- maintain input/output consistency
- prevent silent data loss
- avoid false assumptions during downstream analysis

### Why Strict Input Matters
This tool is designed for **infrastructure hygiene**, not discovery.

It assumes the input list has already been:
- scoped correctly
- ownership-reviewed
- derived from authoritative DNS sources

Attempting to auto-discover or sanitize arbitrary input would:
- introduce ambiguity
- reduce signal quality
- blur ownership boundaries

By enforcing strict input requirements, the tool ensures that results remain deterministic, auditable, and suitable for platform and DNS owner review.

## Output Format
The tool produces a single CSV file intended for direct consumption by infrastructure, platform, and security teams.
Each row represents one input subdomain and its externally observable delegation state at the time of execution.

The output format is intentionally flat and tool-agnostic to allow:
- spreadsheet review
- filtering and pivoting
- ingestion into internal tooling
- attachment to tickets or cleanup tasks

### CSV Columns Explained

**subdomain**  
The input fully qualified domain name as provided.

**cname_exists**  
Indicates whether the subdomain resolves to a CNAME record.

Values:
- `Y` — CNAME record present  
- `N` — No CNAME record

**cname**  
The resolved CNAME target if one exists.

Values:
- actual CNAME target (without trailing dot)
- `-` if no CNAME exists

**provider**  
Best-effort identification of the external platform based on the CNAME suffix.

This field is **informational only** and does not influence classification.

Values:
- known provider name (e.g. AWS CloudFront, Azure App Service)
- `Other` if no known pattern matches
- `N/A` if no delegation exists

**tcp_443_open**  
Indicates whether a TCP connection could be established to port 443.

Values:
- `Y` — TCP listener reachable
- `N` — No TCP listener reachable

This check does not validate TLS, certificates, or application behavior.

**https_reachable**  
Indicates whether an HTTPS request received any response.

Values:
- `Y` — HTTPS stack responded
- `N` — No HTTPS response observed

Any HTTP status code (2xx–5xx) is considered a response.

**status_code**  
HTTP status code returned by the HTTPS request.

Values:
- numeric status code (e.g. 200, 403, 404)
- `N/A` if no HTTPS response was received

This value is provided for operator context only and does not drive state classification.

**state**  
Authoritative classification of the delegation based on DNS, TCP, and HTTPS observations.

Possible values:
- `active`
- `access_restricted`
- `potential_dangling`
- `no_delegation`
- `not_applicable`

**confidence**  
Prioritization signal for `potential_dangling` entries only.

Values:
- `high` — recognized external provider
- `medium` — unrecognized provider
- `N/A` — all other states

This field does **not** indicate exploitability.

**potential_dangling**  
Explicit flag indicating absence of observable backend infrastructure.

Values:
- `Y`
- `N`

Provided to simplify filtering and reporting.

**access_restricted**  
Explicit flag indicating reachable infrastructure with restricted access.

Values:
- `Y`
- `N`

Commonly associated with IP allowlists, WAF rules, or internal-only services.

### Recommended Usage Patterns

Typical downstream analysis includes:
- filtering `state = potential_dangling` for cleanup candidates
- reviewing `access_restricted` entries with owning teams
- validating `active` entries against expected application inventories
- prioritizing `high` confidence findings first

The CSV is designed to support review workflows, not automated deletion.

## Usage

The tool is executed as a standalone Python script.

### Basic Usage

``` bash
python3 dns-delegation-audit.py -i input.txt -o output.csv
```

Where:
- `input.txt` contains one fully qualified domain name per line
- `output.csv` will be created or overwritten

## Example Execution

The tool prints periodic progress updates during execution and a final summary
showing delegation states and prioritization counts.

![CLI execution showing progress and summary](docs/cli-run.png)

## Example Output

The CSV output is designed for manual review, filtering, and triage by
infrastructure and platform teams.

![Sample CSV output with delegation state classification](docs/csv-output.png)

### Command-Line Options

` -i, --input `  
Path to the input file containing subdomains (one per line). Required.

` -o, --output `  
Path to the output CSV file. Required.

` --timeout `

Timeout (in seconds) for HTTPS requests.
Default: 5
This does not affect DNS resolution or TCP probing.

` --workers`

Number of concurrent worker threads.
Default: 40
Increasing this value improves throughput but may:
- increase outbound connection volume
- trigger rate limits on some networks

` --verbose`

Enable per-domain logging during execution.

` --silent`

Suppress per-domain logs.
Progress indicators and final summary are still printed to ensure visibility during long runs.

### Execution Notes

- DNS resolution, TCP probing, and HTTPS checks are performed concurrently
- Output is written incrementally to disk to avoid data loss
- Progress indicators are printed at regular intervals
- A final summary is printed after completion regardless of verbosity

The tool is safe to interrupt. Partial results written to the output file remain valid.

## Limitations and Assumptions

This tool intentionally operates under a **conservative and minimal-assumption model**.
Understanding its limitations is critical for correct interpretation of results.

### Externally Observable Perspective

All checks are performed from the network where the tool is executed.
As a result:

- private backends
- internal load balancers
- VPC-only endpoints
- allowlisted corporate IPs
- geo-restricted services

may appear as `access_restricted` or `potential_dangling` despite being
intentionally configured.

This tool does **not** attempt to infer intent.



### No Exploitability Determination

The tool does not:
- attempt to claim resources
- validate ownership of external services
- use provider-specific error messages
- simulate takeover workflows

A `potential_dangling` classification indicates **absence of observable
infrastructure**, not a confirmed vulnerability.



### DNS Scope Assumptions

The tool assumes:
- the input list is authoritative
- domains are intended to be externally resolvable
- DNS records are not transient or rapidly changing

It is not designed to continuously monitor DNS state or detect race
conditions.



### Network Conditions

Results may vary based on:
- outbound firewall rules
- ISP filtering
- DNS resolver behavior
- rate limiting by providers

Running the tool from different networks may produce different outcomes.



### Provider Detection

Provider identification is best-effort and informational only.

It:
- does not influence classification logic
- may misidentify custom domains
- should not be relied upon for automation



### Recommended Usage Context

This tool is best used as:
- a periodic hygiene audit
- an input to manual review
- a prioritization aid for cleanup efforts

It is not a replacement for:
- ownership verification
- application inventories
- cloud asset tracking
- formal security assessments

## Intended Audience and Use Cases

This tool is intended for teams responsible for managing, securing, or
governing DNS and externally exposed infrastructure.

### Intended Audience

- Infrastructure engineers
- Platform engineering teams
- Cloud security teams
- DNS owners and administrators
- Security engineers supporting internal hygiene and governance

The tool is specifically **not** optimized for:
- bug bounty hunting
- exploit development
- vulnerability proof-of-concept workflows



### Primary Use Cases

**DNS hygiene audits**  
Identify externally delegated subdomains that may no longer be serving any
backend infrastructure.

**Infrastructure cleanup initiatives**  
Support decommissioning efforts by highlighting stale or unclear delegations
that require owner confirmation or removal.

**Attack surface reduction**  
Reduce unnecessary external exposure by ensuring only active and intentional
delegations remain.

**Ownership clarification**  
Provide structured data to help teams identify which subdomains still have
observable infrastructure versus those that need review.

**Pre-migration and post-migration reviews**  
Validate DNS state before or after platform, vendor, or cloud migrations.



### Complementary Tooling

This tool is designed to complement, not replace:
- asset inventory systems
- cloud provider consoles
- vulnerability scanners
- subdomain takeover detection tools

It occupies a distinct space focused on **delegation clarity and hygiene**,
rather than exploitability or vulnerability confirmation.









