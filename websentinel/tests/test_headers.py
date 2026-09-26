from scanner import headers
from tests.conftest import FakeResponse


def test_flags_missing_security_headers():
    resp = FakeResponse(headers={})
    result = headers.run(resp)
    failed_ids = {f.check_id for f in result.findings if not f.passed}
    assert "csp_present" in failed_ids
    assert "strict_transport_security" in failed_ids
    assert result.sub_score() < 100


def test_recognizes_present_headers_full_marks():
    resp = FakeResponse(headers={
        "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    })
    result = headers.run(resp)
    assert result.sub_score() == 100


def test_csp_flags_unsafe_inline():
    resp = FakeResponse(headers={
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
    })
    result = headers.run(resp)
    unsafe_findings = [f for f in result.findings if f.check_id == "csp_script-src_unsafe"]
    assert len(unsafe_findings) == 1
    assert unsafe_findings[0].passed is False
    assert unsafe_findings[0].severity == "HIGH"


def test_csp_wildcard_flagged():
    resp = FakeResponse(headers={
        "Content-Security-Policy": "default-src 'self'; script-src *",
    })
    result = headers.run(resp)
    wildcard_findings = [f for f in result.findings if f.check_id == "csp_script-src_wildcard"]
    assert len(wildcard_findings) == 1
    assert wildcard_findings[0].passed is False


def test_frame_ancestors_credited_without_xfo():
    resp = FakeResponse(headers={
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
    })
    result = headers.run(resp)
    fa = [f for f in result.findings if f.check_id == "csp_frame_ancestors"]
    assert len(fa) == 1
    assert fa[0].passed is True


def test_server_header_disclosure_flagged():
    resp = FakeResponse(headers={"Server": "Apache/2.4.41 (Ubuntu)"})
    result = headers.run(resp)
    disclosure = [f for f in result.findings if f.check_id == "disclosure_server"]
    assert len(disclosure) == 1
    assert disclosure[0].passed is False


def test_content_security_mixed_content_detected():
    resp = FakeResponse(
        headers={"Content-Type": "text/html"},
        url="https://example.com/",
        text='<html><img src="http://insecure.example/x.png"></html>',
    )
    result = headers.run_content_security(resp)
    mixed = [f for f in result.findings if f.check_id == "mixed_content"]
    assert len(mixed) == 1
    assert mixed[0].passed is False


def test_content_security_no_mixed_content_on_http_page():
    # Mixed-content check should only apply to HTTPS pages.
    resp = FakeResponse(
        headers={"Content-Type": "text/html"},
        url="http://example.com/",
        text='<html><img src="http://ok.example/x.png"></html>',
    )
    result = headers.run_content_security(resp)
    mixed = [f for f in result.findings if f.check_id == "mixed_content"]
    assert len(mixed) == 0
