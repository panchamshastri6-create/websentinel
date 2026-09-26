#!/usr/bin/env python3
"""
WebSentinel - Comprehensive Web Security Assessment Platform
================================================================

An AUTHORIZED security assessment tool for websites you own or have
explicit permission to test.

WebSentinel performs a broad, externally-observable security
assessment across TLS, HTTP headers, cookies, CORS, DNS, information
disclosure, and several other categories (see README.md for the full
list). It has two modes:

  PASSIVE (default)     - only ordinary HTTP/HTTPS/DNS/TLS requests, the
                           same kind any browser or resolver sends.
  AUTHORIZED ACTIVE      - adds a small number of additional safe,
                           non-destructive checks (an OPTIONS request to
                           see advertised HTTP methods; an opt-in,
                           fixed-list TCP reachability check against the
                           target's own resolved address). Even in this
                           mode, WebSentinel NEVER performs destructive
                           attacks, denial of service, credential theft,
                           brute forcing, data destruction, malware
                           deployment, privilege escalation, shell
                           execution, database dumping, mass
                           exploitation, account takeover, or the
                           exploitation of any real vulnerability.

SECURITY CANNOT BE PROVEN BY AUTOMATED SCANNING ALONE. This assessment
covers only the checks implemented here and is not a substitute for
professional penetration testing, secure code review, infrastructure
assessment, or manual security testing.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from scanner import api, authentication, cookies, cors, dns as dns_checks, exposure, headers, information, redirects, technology, tls
from scanner import session as session_checks
from scanner.http import TargetValidationError, build_session, validate_target
from scanner.models import MODE_ACTIVE, MODE_PASSIVE
from scanner.scoring import CATEGORY_WEIGHTS, grade_for_score, overall_score
from reports.html_report import render_html_report

BANNER = r"""
 __        __   _   ____             _   _            _
 \ \      / /__| |_/ ___|  ___ _ __ | |_(_)_ __   ___| |
  \ \ /\ / / _ \ '_\___ \ / _ \ '_ \| __| | '_ \ / _ \ |
   \ V  V /  __/ |_|___) |  __/ | | | |_| | | | |  __/ |
    \_/\_/ \___|\__|____/ \___|_| |_|\__|_|_| |_|\___|_|

     Comprehensive Web Security Assessment Platform
"""

AUTHORIZATION_STATEMENT = (
    "I confirm that I own this system or have explicit authorization to assess it."
)

DISCLAIMER = (
    "Security cannot be proven by automated scanning alone. This assessment "
    "covers only the tests implemented by this tool and is not a substitute "
    "for professional penetration testing, secure code review, "
    "infrastructure assessment, or manual security testing."
)

LIMITATIONS = (
    "This assessment does NOT prove that the website is secure. Automated "
    "scanning cannot guarantee the absence of vulnerabilities, and it "
    "cannot confirm that an attacker has zero possible attack paths. "
    "Manual penetration testing, authenticated testing, source-code "
    "review, infrastructure review, and business-logic testing may "
    "identify additional issues."
)


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="websentinel",
        description="WebSentinel - Comprehensive Web Security Assessment Platform "
                    "(authorized use only).",
    )
    parser.add_argument("url", help="Target website, e.g. example.com or https://example.com")

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--passive", action="store_true", help="Passive mode only (default).")
    mode_group.add_argument("--active", action="store_true", help="Authorized active mode (adds safe, non-destructive checks).")

    parser.add_argument("--check-ports", action="store_true",
                        help="With --active: also run a short, fixed-list TCP "
                             "reachability check against the target's own resolved address.")
    parser.add_argument("--subdomains", metavar="LIST",
                        help="Comma-separated list of subdomains you explicitly want "
                             "checked for dangling-CNAME indicators. WebSentinel never "
                             "enumerates subdomains on its own.")
    parser.add_argument("--allow-private", action="store_true",
                        help="Allow scanning localhost or private/reserved IP ranges "
                             "(only for intentional, authorized internal targets).")
    parser.add_argument("--json", action="store_true", help="Print the JSON report to stdout as well.")
    parser.add_argument("-o", "--output", metavar="FILE", help="Write the JSON report to FILE.")
    parser.add_argument("--html-output", metavar="FILE", default="report.html",
                        help="Path to write the HTML report (default: report.html).")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout in seconds (default: 8).")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip the interactive authorization prompt.")
    return parser.parse_args(argv)


def confirm_authorization(mode: str, skip_prompt: bool) -> bool:
    if skip_prompt:
        return True
    print(f"\nMode: {mode}")
    print(
        "Only assess systems you own or have explicit permission to test.\n"
        "Unauthorized scanning -- even passive/non-destructive scanning -- "
        "may be illegal in your jurisdiction."
    )
    print(f'\nType exactly: {AUTHORIZATION_STATEMENT!r}')
    print('(Or simply type "YES" to confirm and continue.)')
    answer = input("> ").strip()
    return answer == "YES" or answer == AUTHORIZATION_STATEMENT


def fetch_main_response(session, url: str, timeout: float):
    try:
        return session.get(url, timeout=timeout, allow_redirects=True), None
    except requests.exceptions.SSLError as exc:
        return None, f"TLS/SSL error while connecting to {url}: {exc}"
    except requests.exceptions.ConnectionError as exc:
        return None, f"Could not connect to {url}: {exc}"
    except requests.exceptions.Timeout:
        return None, f"Connection to {url} timed out after {timeout}s."
    except requests.exceptions.RequestException as exc:
        return None, f"Request to {url} failed: {exc}"


def run_all_checks(resolved, mode: str, http_session, timeout: float, check_ports: bool, extra_subdomains):
    """Run every check module. Returns (category_results_by_name, main_response, error)."""
    url = resolved.url
    hostname = resolved.hostname
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{hostname}"

    main_response, error = fetch_main_response(http_session, url, timeout)
    if error:
        return None, None, error

    by_name = {}

    def add(cat_result):
        by_name[cat_result.category] = cat_result

    add(headers.run(main_response))
    add(headers.run_content_security(main_response))
    add(cookies.run(main_response))
    add(session_checks.run(main_response))

    https_ok = str(main_response.url).startswith("https://")
    https_response_for_tls = main_response
    if not https_ok:
        # Always attempt a dedicated HTTPS probe for the TLS category, even
        # if the operator's input/redirects landed on plain HTTP.
        https_probe_url = f"https://{hostname}/"
        probe_resp, probe_err = fetch_main_response(http_session, https_probe_url, timeout)
        https_response_for_tls = probe_resp

    if https_response_for_tls is not None:
        add(tls.run(hostname, https_response_for_tls, timeout=timeout))
    else:
        from scanner.models import CategoryResult, Finding, SEVERITY_HIGH
        cat = CategoryResult(category="TLS / HTTPS Security", weight=CATEGORY_WEIGHTS["TLS / HTTPS Security"])
        cat.add(Finding(
            check_id="https_available",
            name="HTTPS available",
            passed=False,
            severity=SEVERITY_HIGH,
            description="Could not establish an HTTPS connection to this host at all.",
            recommendation="Enable HTTPS for this site.",
        ))
        add(cat)

    add(cors.run(http_session, url, timeout=timeout))
    add(redirects.run(http_session, hostname, timeout=timeout))
    add(dns_checks.run(hostname))
    add(dns_checks.run_subdomains(hostname, extra_subdomains))
    add(technology.run(main_response))
    add(api.run(http_session, base_url, main_response, timeout=timeout))
    add(authentication.run(main_response, https_ok=https_ok))
    add(information.run_information_disclosure(main_response, http_session, base_url, timeout=timeout))
    add(information.run_exposed_files(http_session, base_url, timeout=timeout))
    add(information.run_security_txt(http_session, base_url, timeout=timeout))
    add(exposure.run_http_methods(http_session, url, timeout=timeout))
    add(exposure.run_safe_service_exposure(
        resolved.resolved_ips,
        enabled=(mode == MODE_ACTIVE and check_ports),
    ))

    # Common Misconfigurations is a rollup of everything gathered so far.
    add(exposure.run_common_misconfigurations(by_name))

    return by_name, main_response, None


def print_report(resolved, mode: str, main_response, category_results, score: float, grade: str) -> None:
    print(BANNER)
    print("=" * 64)
    print(f"Target:\n{resolved.url}")
    print(f"\nAssessment:\n{mode}")
    print(f"\nOverall Assessment Score:\n{score}/100  (grade: {grade})")

    total_checks = sum(len(c.findings) for c in category_results)
    print(f"\nCoverage:\n{len(category_results)} categories, {total_checks} checks")
    print("=" * 64)

    from scanner.models import SEVERITY_ORDER
    findings_by_sev = {sev: [] for sev in SEVERITY_ORDER}
    for cat in category_results:
        for f in cat.findings:
            if not f.passed:
                findings_by_sev[f.severity].append((cat.category, f))

    for sev in SEVERITY_ORDER:
        items = findings_by_sev[sev]
        label = "INFORMATIONAL" if sev == "INFO" else sev
        print(f"\n{'-' * 58}\n{label}\n{'-' * 58}")
        if not items:
            print("\nNone")
            continue
        for cat_name, f in items:
            mv = "  [MANUAL VERIFICATION REQUIRED]" if f.manual_verification else ""
            print(f"\n[{sev}] {f.name} ({cat_name}){mv}")
            print(f"  {f.description}")
            if f.recommendation:
                print(f"  Fix: {f.recommendation}")

    print(f"\n{'-' * 58}\nCATEGORY SCORES\n{'-' * 58}")
    for cat in category_results:
        skipped = f"  [skipped: {cat.skipped_reason}]" if cat.skipped_reason else ""
        print(f"{cat.category:<38} {cat.weighted_score():>5}/{cat.weight}{skipped}")

    print("\n" + "=" * 64)
    print("IMPORTANT")
    print("=" * 64)
    print(f"\n{LIMITATIONS}\n")
    print("=" * 64)


def build_json_report(resolved, mode: str, main_response, category_results) -> dict:
    score = overall_score(category_results)
    all_findings = []
    for cat in category_results:
        for f in cat.findings:
            fd = f.to_dict()
            fd["category"] = cat.category
            all_findings.append(fd)

    return {
        "tool": "WebSentinel",
        "version": "1.0",
        "target": resolved.url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "final_url": main_response.url,
        "status_code": main_response.status_code,
        "assessment_mode": mode,
        "overall_score": score,
        "grade": grade_for_score(score),
        "coverage": {
            "categories": len(category_results),
            "checks": sum(len(c.findings) for c in category_results),
        },
        "categories": [c.to_dict() for c in category_results],
        "findings": all_findings,
        "manual_verification": [f for f in all_findings if f["manual_verification"]],
        "recommendations": [f["recommendation"] for f in all_findings if f["recommendation"]],
        "disclaimer": DISCLAIMER,
        "limitations": LIMITATIONS,
    }


def main(argv=None) -> int:
    args = parse_args(argv)
    mode = MODE_ACTIVE if args.active else MODE_PASSIVE

    try:
        resolved = validate_target(args.url, allow_private=args.allow_private)
    except TargetValidationError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if not confirm_authorization(mode, args.yes):
        print("Aborting: authorization not confirmed.", file=sys.stderr)
        return 1

    extra_subdomains = [s.strip() for s in args.subdomains.split(",") if s.strip()] if args.subdomains else []

    http_session = build_session()
    category_results_by_name, main_response, error = run_all_checks(
        resolved, mode, http_session, args.timeout, args.check_ports, extra_subdomains
    )

    if error:
        print(f"[!] {error}", file=sys.stderr)
        return 2

    category_results = list(category_results_by_name.values())
    score = overall_score(category_results)
    grade = grade_for_score(score)

    print_report(resolved, mode, main_response, category_results, score, grade)

    report = build_json_report(resolved, mode, main_response, category_results)
    report_json = json.dumps(report, indent=2, default=str)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report_json)
        print(f"\n[+] JSON report written to {args.output}")
    if args.json:
        print("\n" + report_json)

    html_doc = render_html_report(report)
    with open(args.html_output, "w", encoding="utf-8") as f:
        f.write(html_doc)
    print(f"[+] HTML report written to {args.html_output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
