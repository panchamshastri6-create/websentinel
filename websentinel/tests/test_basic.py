import pytest

from scanner.http import TargetValidationError, normalize_url, validate_target
from scanner import redirects
from tests.conftest import FakeResponse, FakeSession


# ---------------------------------------------------------------------------
# normalize_url
# ---------------------------------------------------------------------------

def test_normalize_url_adds_https_by_default():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_preserves_existing_scheme():
    assert normalize_url("http://example.com") == "http://example.com"


# ---------------------------------------------------------------------------
# validate_target -- invalid URL / unsafe target handling
# ---------------------------------------------------------------------------

def test_validate_target_rejects_localhost_by_default():
    with pytest.raises(TargetValidationError):
        validate_target("http://localhost/", allow_private=False)


def test_validate_target_rejects_loopback_ip_by_default():
    with pytest.raises(TargetValidationError):
        validate_target("http://127.0.0.1/", allow_private=False)


def test_validate_target_allows_localhost_with_flag():
    resolved = validate_target("http://127.0.0.1/", allow_private=True)
    assert resolved.hostname == "127.0.0.1"


def test_validate_target_rejects_unresolvable_hostname():
    with pytest.raises(TargetValidationError):
        validate_target("http://this-domain-should-not-exist-websentinel-test.invalid/")


def test_validate_target_rejects_bad_scheme():
    with pytest.raises(TargetValidationError):
        validate_target("ftp://example.com/")


# ---------------------------------------------------------------------------
# redirects.run
# ---------------------------------------------------------------------------

def test_redirect_to_https_passes():
    resp = FakeResponse(url="https://example.com/", history=[FakeResponse(url="http://example.com/")])
    session = FakeSession(response=resp)
    result = redirects.run(session, "example.com")
    finding = [f for f in result.findings if f.check_id == "https_redirect"][0]
    assert finding.passed is True


def test_no_https_redirect_fails():
    resp = FakeResponse(url="http://example.com/", history=[])
    session = FakeSession(response=resp)
    result = redirects.run(session, "example.com")
    finding = [f for f in result.findings if f.check_id == "https_redirect"][0]
    assert finding.passed is False


# ---------------------------------------------------------------------------
# JSON report shape (using websentinel's own builder against fakes)
# ---------------------------------------------------------------------------

def test_build_json_report_shape():
    import websentinel
    from scanner.models import CategoryResult, Finding
    from scanner.http import ResolvedTarget

    resolved = ResolvedTarget(
        original_input="example.com",
        url="https://example.com",
        hostname="example.com",
        resolved_ips=["93.184.216.34"],
    )
    cat = CategoryResult(category="HTTP Security Headers", weight=15)
    cat.add(Finding("csp_present", "CSP", passed=True, severity="HIGH", description="ok"))
    resp = FakeResponse(status_code=200, url="https://example.com/")

    report = websentinel.build_json_report(resolved, "PASSIVE", resp, [cat])

    assert report["tool"] == "WebSentinel"
    assert report["target"] == "https://example.com"
    assert report["assessment_mode"] == "PASSIVE"
    assert "overall_score" in report
    assert report["coverage"]["categories"] == 1
    assert report["categories"][0]["category"] == "HTTP Security Headers"
    assert "manual_verification" in report
    assert "recommendations" in report
    assert "limitations" in report
    assert "Security cannot be proven" in report["disclaimer"]


def test_json_report_never_claims_100_percent_secure():
    import websentinel
    assert "100% secure" not in websentinel.DISCLAIMER
    assert "100% secure" not in websentinel.LIMITATIONS
