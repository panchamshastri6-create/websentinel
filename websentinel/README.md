# WebSentinel — Comprehensive Web Security Assessment Platform

WebSentinel is an **authorized-use** command-line tool for assessing the
externally observable security posture of a website. It is built for
sites you own or have explicit permission to test.

> ⚠️ **Only assess systems you own or have explicit authorization to
> test.** Unauthorized scanning — even fully passive, non-destructive
> scanning — may violate the U.S. Computer Fraud and Abuse Act, the UK
> Computer Misuse Act, or similar laws elsewhere.

**Security cannot be proven by automated scanning alone.** This
assessment covers only the tests implemented by this tool and is not a
substitute for professional penetration testing, secure code review,
infrastructure assessment, or manual security testing. WebSentinel
never claims a website is "100% secure," and it never claims a finding
is confirmed when it only has an indicator — those are always labeled
`MANUAL VERIFICATION REQUIRED`.

## What it does

WebSentinel examines 18 scored categories (plus a couple of folded-in
informational sub-topics) covering TLS, HTTP headers, cookies, CORS,
redirects, DNS/email-security records, technology fingerprinting, API
configuration, authentication/session indicators, information
disclosure, and more. Every finding includes:

- a plain-English **description** of what was observed,
- the **evidence** behind it (the actual header/record/value seen),
- a **severity** (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`),
- a **recommendation** when something failed, and
- a `manual_verification` flag whenever the finding is only an
  indicator rather than a confirmed vulnerability.

Category sub-scores roll up into one **Web Security Assessment Score**
out of 100.

### Two modes

| Mode | What it does |
|---|---|
| `--passive` (default) | Only ordinary HTTP/HTTPS/DNS/TLS requests — the same kind any browser or resolver sends. |
| `--active` | Adds a small number of additional **safe, non-destructive** checks: an `OPTIONS` request to see advertised HTTP methods, and (only with `--check-ports`) a short, fixed-list TCP reachability check against the target's own resolved address. |

**Even in active mode, WebSentinel never performs:** destructive
attacks, denial of service, credential theft, password brute forcing,
credential stuffing, data destruction, malware deployment, persistence,
privilege escalation, shell execution on the target, database dumping,
mass exploitation, account takeover, bypassing security controls, or
exploitation of any real vulnerability. Every request WebSentinel makes
is a normal GET/HEAD/OPTIONS request or a TCP connect-and-close — the
same interaction a standard browser or client would have.

### Target safety

Before scanning, WebSentinel:

- validates and normalizes the URL,
- resolves the hostname,
- **refuses to scan localhost or private/reserved IP ranges** (RFC 1918,
  loopback, link-local, etc.) unless you explicitly pass `--allow-private`,
- never scans an IP range or network — only the single resolved target,
- never performs open-ended port scanning — only a short, fixed list of
  well-known ports, and only when `--active --check-ports` is both given.

### Authorization confirmation

Unless you pass `-y`/`--yes`, WebSentinel prompts:

```
Type exactly: 'I confirm that I own this system or have explicit authorization to assess it.'
(Or simply type "YES" to confirm and continue.)
>
```

Typing `YES` (or the full statement) is required to proceed.

## Architecture

```
websentinel/
│
├── websentinel.py              # CLI entry point and orchestrator
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
│
├── scanner/
│   ├── __init__.py
│   ├── models.py                 # Finding / CategoryResult / severities
│   ├── scoring.py                  # category weights + overall scoring
│   ├── http.py                       # URL validation, SSRF/private-IP guard, session
│   ├── headers.py                      # HTTP Security Headers + Content Security
│   ├── cookies.py                        # Cookie Security
│   ├── tls.py                              # TLS / HTTPS Security
│   ├── cors.py                               # CORS
│   ├── redirects.py                            # Redirect Security
│   ├── dns.py                                    # DNS Security + Subdomain Security
│   ├── technology.py                               # Technology Detection + CVE indicators
│   ├── api.py                                        # API Security
│   ├── authentication.py                               # Authentication Security Indicators
│   ├── session.py                                         # Session Security
│   ├── information.py                                       # Info Disclosure, Exposed Files, security.txt
│   └── exposure.py                                            # HTTP Methods, Safe Service Exposure, Common Misconfigurations
│
├── reports/
│   ├── __init__.py
│   └── html_report.py            # self-contained report.html generator
│
└── tests/
    ├── __init__.py
    ├── conftest.py                # shared fake Response/Session test doubles
    ├── test_headers.py
    ├── test_cookies.py
    ├── test_cors.py
    ├── test_scoring.py
    └── test_basic.py
```

### A note on the scoring table

The weights below are exactly what was specified for each category.
Added up, they total **110**, not the 100 the original spec table
labels itself. Rather than quietly shrinking individual weights to
force them to add to 100, WebSentinel keeps every stated weight exactly
as given (so each category's *relative* importance matches the spec)
and normalizes the combined result onto a true 0–100 scale in
`overall_score()`. The headline score you see is always genuinely out
of 100.

| Category | Weight |
|---|---|
| TLS / HTTPS Security | 15 |
| HTTP Security Headers | 15 |
| Cookie Security | 10 |
| CORS | 5 |
| HTTP Methods | 5 |
| Redirect Security | 5 |
| Information Disclosure | 8 |
| DNS Security | 7 |
| Subdomain Security | 5 |
| Technology Detection | 5 |
| API Security | 8 |
| Authentication Security Indicators | 5 |
| Session Security | 4 |
| Content Security | 3 |
| Exposed Files | 3 |
| security.txt | 1 |
| Common Misconfigurations | 4 |
| Safe Service Exposure | 2 |

`robots.txt`/`sitemap.xml` presence (spec category 17) and Access
Control indicators (spec category 14) are folded in as informational
findings inside Information Disclosure and API Security respectively,
since the spec's own scoring table doesn't give them independent
weights.

## Installation

### Windows (PowerShell)

```powershell
mkdir websentinel
cd websentinel
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### Linux / Kali

```bash
mkdir websentinel
cd websentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`dnspython` is recommended (in requirements.txt) for full DNS Security
and Subdomain Security coverage. If it isn't installed, WebSentinel
still runs — it falls back to a basic hostname-resolves check and
clearly marks the rest of those categories as skipped, rather than
crashing.

## Usage

```bash
# Passive scan (default), interactive authorization prompt
python websentinel.py https://example.com

# Passive scan, skip the prompt (e.g. for scripting/CI)
python websentinel.py https://example.com --passive -y

# Authorized active scan (adds OPTIONS-based HTTP-methods check)
python websentinel.py https://example.com --active -y

# Authorized active scan, also check a short list of well-known ports
# on the target's own resolved address
python websentinel.py https://example.com --active --check-ports -y

# Also check specific subdomains you explicitly authorize (no enumeration)
python websentinel.py https://example.com --subdomains "www,api,old-app" -y

# JSON output to stdout
python websentinel.py https://example.com --json -y

# JSON report written to a file
python websentinel.py https://example.com -o report.json -y

# Custom HTML report path (default is ./report.html)
python websentinel.py https://example.com --html-output my_report.html -y

# Scan an authorized internal/private target
python websentinel.py http://10.0.0.5/ --allow-private -y
```

### Example terminal output

```
 __        __   _   ____             _   _            _
 \ \      / /__| |_/ ___|  ___ _ __ | |_(_)_ __   ___| |
  \ \ /\ / / _ \ '_\___ \ / _ \ '_ \| __| | '_ \ / _ \ |
   \ V  V /  __/ |_|___) |  __/ | | | |_| | | | |  __/ |
    \_/\_/ \___|\__|____/ \___|_| |_|\__|_|_| |_|\___|_|

     Comprehensive Web Security Assessment Platform

================================================================
Target:
https://example.com

Assessment:
AUTHORIZED ACTIVE

Overall Assessment Score:
82.4/100  (grade: B)

Coverage:
18 categories, 61 checks
================================================================

----------------------------------------------------------
CRITICAL
----------------------------------------------------------

None

----------------------------------------------------------
HIGH
----------------------------------------------------------

[HIGH] Content-Security-Policy (HTTP Security Headers)
  No Content-Security-Policy header found. ...
  Fix: Define a CSP that allow-lists only the origins your site actually needs.

...

----------------------------------------------------------
CATEGORY SCORES
----------------------------------------------------------
TLS / HTTPS Security                   15.0/15
HTTP Security Headers                  11.2/15
Cookie Security                        10.0/10
...

================================================================
IMPORTANT
================================================================

This assessment does NOT prove that the website is secure. Automated
scanning cannot guarantee the absence of vulnerabilities, and it cannot
confirm that an attacker has zero possible attack paths. Manual
penetration testing, authenticated testing, source-code review,
infrastructure review, and business-logic testing may identify
additional issues.
================================================================
```

### Severity levels

`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` — used conservatively.
Anything that can't be automatically proven (an old-looking software
version, a login form's rate limiting, whether an exposed file
actually contains secrets) is worded as "potential," "indicator," or
"manual verification required," and carries `manual_verification: true`
in the JSON output — never presented as a confirmed vulnerability.

### JSON report

`--json` prints it to stdout; `-o FILE` writes it to a file. Fields
include: `target`, `timestamp`, `final_url`, `status_code`,
`assessment_mode`, `overall_score`, `grade`, `coverage`, `categories`
(each with its own findings and sub-score), a flattened `findings`
list, `manual_verification` (findings that need it), `recommendations`,
`disclaimer`, and `limitations`.

### HTML report

Always written (default `report.html`, override with `--html-output`).
A single self-contained file — no external CSS/JS/fonts, no network
calls — with a clean, dark, muted "security dashboard" style (no neon
colors): overall score, per-category bars, findings grouped by
severity, evidence, recommendations, and the same limitations text as
the terminal/JSON output.

## Limitations

**No automated scanner can guarantee that a website is completely
secure.** Specifically, WebSentinel cannot:

- perform authenticated testing (it never logs in or uses credentials),
- confirm whether a discovered "potentially exposed" file actually
  contains secrets (it only checks whether the URL returns HTTP 200),
- confirm a flagged HTTP method (`PUT`/`DELETE`/`TRACE`) is actually
  enabled server-side (it never sends those methods),
- confirm a version-based CVE indicator represents a real, exploitable
  vulnerability (that requires a real vulnerability database lookup
  and manual verification — WebSentinel deliberately does not call any
  paid API, and its local heuristic table is small and conservative by
  design),
- detect business-logic flaws, access-control bugs, or anything that
  requires exploiting a real vulnerability to observe,
- replace a professional penetration test, secure code review, or
  infrastructure security assessment.

## Responsible use

- Only scan systems you own or are explicitly authorized to test.
- WebSentinel intentionally avoids anything that could be considered
  an attack: no brute-forcing, no exploitation, no destructive
  requests, no mass/internet-wide enumeration.
- If you extend this project, please preserve that scope.

## Running the tests

```bash
python -m pytest tests/
```

All 38 tests use small fake `Response`/`Session` objects (see
`tests/conftest.py`) instead of real network calls, so the suite is
fast, deterministic, and never targets a real website.
