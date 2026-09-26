from scanner import cookies
from tests.conftest import FakeResponse


def test_no_cookies_passes():
    resp = FakeResponse(set_cookie_values=[])
    result = cookies.run(resp)
    assert all(f.passed for f in result.findings)


def test_session_cookie_missing_attrs_flagged_medium():
    resp = FakeResponse(set_cookie_values=["sessionid=abc123; Path=/"])
    result = cookies.run(resp)
    session_findings = [f for f in result.findings if "session_attrs" in f.check_id]
    assert len(session_findings) == 1
    assert session_findings[0].passed is False
    assert session_findings[0].severity == "MEDIUM"


def test_session_cookie_with_all_attrs_passes():
    resp = FakeResponse(set_cookie_values=["sessionid=abc123; Secure; HttpOnly; SameSite=Strict"])
    result = cookies.run(resp)
    session_findings = [f for f in result.findings if "session_attrs" in f.check_id]
    assert session_findings[0].passed is True


def test_tracking_cookie_missing_httponly_not_flagged():
    # Missing HttpOnly on a non-session cookie should NOT be flagged --
    # analytics cookies are often read by JS by design.
    resp = FakeResponse(set_cookie_values=["_ga=GA1.2.123; Secure; SameSite=Lax"])
    result = cookies.run(resp)
    attr_findings = [f for f in result.findings if f.check_id == "cookie_1_attrs"]
    assert attr_findings[0].passed is True


def test_secure_prefix_cookie_recognized():
    resp = FakeResponse(set_cookie_values=["__Secure-sessionid=abc; Secure; HttpOnly; SameSite=Strict"])
    result = cookies.run(resp)
    prefix_findings = [f for f in result.findings if "prefix" in f.check_id]
    assert len(prefix_findings) == 1
    assert prefix_findings[0].passed is True
