"""
scanner/dns.py
================
Category: DNS Security

Passive only -- ordinary DNS queries, the same kind any resolver on
the internet performs. Never attempts zone transfers, cache poisoning,
or any DNS takeover / claiming technique.

Uses dnspython if it's installed (recommended, in requirements.txt),
but degrades gracefully -- using Python's built-in socket module for
basic A/AAAA lookups -- if dnspython is unavailable, so the tool still
runs without every optional dependency.
"""

import socket

from scanner.models import CategoryResult, Finding, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_INFO
from scanner.scoring import CATEGORY_WEIGHTS

CATEGORY_NAME = "DNS Security"

try:
    import dns.resolver  # type: ignore
    _HAVE_DNSPYTHON = True
except ImportError:  # pragma: no cover - exercised only when dnspython is absent
    _HAVE_DNSPYTHON = False


def _query(hostname: str, record_type: str):
    """Return a list of string answers for record_type, or [] on failure."""
    if not _HAVE_DNSPYTHON:
        return []
    try:
        answers = dns.resolver.resolve(hostname, record_type, lifetime=5.0)
        return [str(a).strip('"') for a in answers]
    except Exception:
        return []


def run(hostname: str) -> CategoryResult:
    result = CategoryResult(category=CATEGORY_NAME, weight=CATEGORY_WEIGHTS[CATEGORY_NAME])

    if not _HAVE_DNSPYTHON:
        # Fall back to a basic A/AAAA lookup via the standard library so the
        # category isn't entirely empty, and clearly mark the rest as skipped.
        try:
            socket.getaddrinfo(hostname, None)
            resolves = True
        except socket.gaierror:
            resolves = False
        result.add(Finding(
            check_id="dns_resolves",
            name="Hostname resolves",
            passed=resolves,
            severity=SEVERITY_MEDIUM,
            description="Hostname resolves via the system resolver." if resolves
                        else "Hostname does not resolve.",
        ))
        result.skipped_reason = (
            "dnspython is not installed, so MX/TXT/NS/SPF/DMARC/CAA record "
            "checks were skipped. Install dnspython for full DNS coverage."
        )
        return result

    a_records = _query(hostname, "A")
    aaaa_records = _query(hostname, "AAAA")
    mx_records = _query(hostname, "MX")
    ns_records = _query(hostname, "NS")
    txt_records = _query(hostname, "TXT")
    caa_records = _query(hostname, "CAA")

    result.add(Finding(
        check_id="dns_a_records",
        name="A/AAAA records",
        passed=bool(a_records or aaaa_records),
        severity=SEVERITY_MEDIUM,
        description=f"{len(a_records)} A record(s), {len(aaaa_records)} AAAA record(s) found."
                    if (a_records or aaaa_records) else "No A or AAAA records found.",
        evidence=", ".join(a_records + aaaa_records),
    ))

    result.add(Finding(
        check_id="dns_ns_records",
        name="NS records",
        passed=bool(ns_records),
        severity=SEVERITY_LOW,
        description=f"{len(ns_records)} name server(s) found." if ns_records
                    else "No NS records found (unusual for a live domain).",
        evidence=", ".join(ns_records),
    ))

    result.add(Finding(
        check_id="dns_mx_records",
        name="MX records",
        passed=True,
        severity=SEVERITY_INFO,
        description=f"{len(mx_records)} mail exchanger(s) found." if mx_records
                    else "No MX records found (site may not receive email at this domain).",
        evidence=", ".join(mx_records),
    ))

    # --- SPF ---
    spf_records = [t for t in txt_records if t.lower().startswith("v=spf1")]
    if spf_records:
        result.add(Finding(
            check_id="spf",
            name="SPF record",
            passed=True,
            severity=SEVERITY_MEDIUM,
            description="An SPF record was found, helping prevent email spoofing "
                        "of this domain.",
            evidence=spf_records[0],
        ))
    else:
        result.add(Finding(
            check_id="spf",
            name="SPF record",
            passed=False,
            severity=SEVERITY_MEDIUM,
            description="No SPF record found at the domain apex. This is an "
                        "email-security gap, separate from web application security.",
            recommendation="Publish a TXT record starting with 'v=spf1' listing authorized senders.",
        ))

    # --- DMARC (lives at _dmarc.<domain>) ---
    dmarc_records = _query(f"_dmarc.{hostname}", "TXT")
    dmarc_records = [t for t in dmarc_records if t.lower().startswith("v=dmarc1")]
    if dmarc_records:
        result.add(Finding(
            check_id="dmarc",
            name="DMARC record",
            passed=True,
            severity=SEVERITY_MEDIUM,
            description="A DMARC record was found.",
            evidence=dmarc_records[0],
        ))
    else:
        result.add(Finding(
            check_id="dmarc",
            name="DMARC record",
            passed=False,
            severity=SEVERITY_MEDIUM,
            description="No DMARC record found at _dmarc." + hostname + ". "
                        "This is an email-security gap, separate from web application security.",
            recommendation="Publish a DMARC TXT record at _dmarc.<domain>, starting with 'v=DMARC1'.",
        ))

    # --- DKIM: cannot be found without knowing the selector, so this is
    # explicitly marked as needing manual verification rather than guessed. ---
    result.add(Finding(
        check_id="dkim",
        name="DKIM indicator",
        passed=True,
        severity=SEVERITY_INFO,
        description="DKIM uses a per-provider 'selector' name that isn't "
                    "discoverable from public records alone.",
        manual_verification=True,
        recommendation="Manually verify DKIM is configured with your email provider's documentation.",
    ))

    # --- CAA ---
    if caa_records:
        result.add(Finding(
            check_id="caa",
            name="CAA record",
            passed=True,
            severity=SEVERITY_LOW,
            description="A CAA record restricts which certificate authorities may "
                        "issue certificates for this domain.",
            evidence=", ".join(caa_records),
        ))
    else:
        result.add(Finding(
            check_id="caa",
            name="CAA record",
            passed=False,
            severity=SEVERITY_LOW,
            description="No CAA record found; any publicly trusted CA can issue "
                        "certificates for this domain.",
            recommendation="Add a CAA record naming the certificate authorities you actually use.",
        ))

    return result


def run_subdomains(hostname: str, extra_subdomains=None) -> CategoryResult:
    """
    Category: Subdomain Security (weight 5)

    Per the spec, this deliberately does NOT perform any internet-wide or
    wordlist-based subdomain enumeration. It only inspects:
      - the target hostname's own CNAME (if any), and
      - any subdomains the operator explicitly lists via --subdomains.

    For each, it checks whether the CNAME target still resolves (a
    "dangling CNAME" -- pointing at a de-provisioned cloud resource -- is
    a well-known subdomain-takeover indicator). It never attempts to
    actually claim or register anything.
    """
    result = CategoryResult(category="Subdomain Security", weight=CATEGORY_WEIGHTS["Subdomain Security"])
    extra_subdomains = extra_subdomains or []

    if not _HAVE_DNSPYTHON:
        result.skipped_reason = "dnspython is not installed, so CNAME-based checks were skipped."
        return result

    targets = [hostname] + list(extra_subdomains)

    if not extra_subdomains:
        result.add(Finding(
            check_id="subdomains_scope",
            name="Subdomain scope",
            passed=True,
            severity=SEVERITY_INFO,
            description="No additional subdomains were provided via --subdomains. "
                        "WebSentinel does not perform subdomain enumeration; only "
                        "the target hostname itself was checked.",
        ))

    any_dangling = False
    any_cname = False
    for name in targets:
        cname_records = _query(name, "CNAME")
        if not cname_records:
            continue
        any_cname = True
        cname_target = cname_records[0].rstrip(".")
        try:
            socket.getaddrinfo(cname_target, None)
            target_resolves = True
        except socket.gaierror:
            target_resolves = False

        if not target_resolves:
            any_dangling = True
            result.add(Finding(
                check_id=f"subdomain_dangling_{name}",
                name=f"Dangling CNAME: {name}",
                passed=False,
                severity=SEVERITY_HIGH,
                description=f"{name} has a CNAME pointing to {cname_target}, which "
                            f"does not currently resolve. This pattern can indicate "
                            f"a de-provisioned cloud resource that could potentially "
                            f"be claimed by someone else (subdomain takeover).",
                evidence=f"{name} CNAME {cname_target}",
                manual_verification=True,
                recommendation=f"Remove the DNS record for {name} if {cname_target} "
                               f"is no longer in use, or re-provision the resource.",
            ))
        else:
            result.add(Finding(
                check_id=f"subdomain_cname_{name}",
                name=f"CNAME target resolves: {name}",
                passed=True,
                severity=SEVERITY_HIGH,
                description=f"{name} CNAMEs to {cname_target}, which resolves normally.",
                evidence=f"{name} CNAME {cname_target}",
            ))

    if not any_dangling and not any_cname:
        result.add(Finding(
            check_id="subdomains_no_cname",
            name="CNAME check",
            passed=True,
            severity=SEVERITY_LOW,
            description="No CNAME records found on the checked host(s), so there "
                        "is nothing to flag for dangling-CNAME takeover risk.",
        ))

    return result
