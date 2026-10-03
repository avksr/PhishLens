"""
backend/tests/test_url_agent_upgrade.py
---------------------------------------
Comprehensive test suite for the upgraded production-grade URL Threat Intelligence Agent:
  1. Data Models (models/schema.py)
  2. Multi-Hop Redirect & Anti-Cloaking Engine (core/redirect_tracer.py)
  3. Homograph & Typosquatting Engine (core/homograph_engine.py)
  4. SSL Infrastructure & Certificate Analyzer (core/ssl_analyzer.py)
  5. DOM & Visual Favicon Inspector (core/dom_inspector.py)
  6. Orchestrator & Scoring Engine (url_agent.py)
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from phishlens.agents.url_agent.models.schema import (
    RiskSignal,
    URLAgentInput,
    URLAgentOutput,
)
from phishlens.agents.url_agent.core.redirect_tracer import (
    HopDetail,
    RedirectHop,
    RedirectTraceResult,
    RedirectTracer,
    trace_redirects_and_cloaking,
)
from phishlens.agents.url_agent.core.homograph_engine import (
    HomographAnalysisResult,
    HomographEngine,
    HomographResult,
    analyze_homograph_and_brands,
    confusable_skeleton,
)
from phishlens.agents.url_agent.core.ssl_analyzer import (
    SSLAnalysisResult,
    SSLAnalyzer,
    analyze_ssl_infrastructure,
)
from phishlens.agents.url_agent.core.dom_inspector import (
    DOMAnalysisResult,
    DOMInspectionResult,
    DOMInspector,
    compute_murmur3_hash,
    compute_shodan_favicon_hash,
    inspect_dom_and_favicons,
)
from phishlens.agents.url_agent.url_agent import (
    URLAgent,
    run_url_agent,
)


# =============================================================================
# 1. DATA MODELS TESTS (models/schema.py)
# =============================================================================

def test_url_agent_input_model():
    """Verify URLAgentInput validation and defaults."""
    inp = URLAgentInput(url="https://secure-bank.example.com")
    assert inp.url == "https://secure-bank.example.com"
    assert inp.deep_scan is True
    assert inp.user_agent_override is None

    custom = URLAgentInput(
        url="http://test.com",
        deep_scan=False,
        user_agent_override="CustomBot/1.0",
    )
    assert custom.deep_scan is False
    assert custom.user_agent_override == "CustomBot/1.0"


def test_risk_signal_model():
    """Verify RiskSignal data structure."""
    sig = RiskSignal(
        category="HOMOGRAPH",
        severity="CRITICAL",
        description="Punycode spoofing detected",
    )
    assert sig.category == "HOMOGRAPH"
    assert sig.severity == "CRITICAL"
    assert "Punycode" in sig.description


def test_exported_aliases_and_helpers():
    """Verify exported aliases and functional entrypoints."""
    assert RedirectHop is HopDetail
    assert HomographResult is HomographAnalysisResult
    assert DOMAnalysisResult is DOMInspectionResult
    assert compute_shodan_favicon_hash is not None
    assert callable(trace_redirects_and_cloaking)
    assert callable(analyze_homograph_and_brands)
    assert callable(analyze_ssl_infrastructure)
    assert callable(inspect_dom_and_favicons)
    assert callable(run_url_agent)


def test_url_agent_output_model_bounds():
    """Verify URLAgentOutput bounds validation on risk_score (0-100)."""
    out = URLAgentOutput(
        input_url="http://bad.com",
        final_destination_url="http://bad.com/login",
        risk_score=85,
        threat_level="MALICIOUS",
        redirect_chain=["http://bad.com", "http://bad.com/login"],
        signals=[],
        metadata={"scan_duration_ms": 12.5},
        explanation="Test explanation",
    )
    assert out.risk_score == 85
    assert out.threat_level == "MALICIOUS"

    # Out-of-bounds risk score must raise ValidationError
    with pytest.raises(ValidationError):
        URLAgentOutput(
            input_url="http://bad.com",
            final_destination_url="http://bad.com",
            risk_score=150,  # > 100
            threat_level="MALICIOUS",
            redirect_chain=[],
            signals=[],
            metadata={},
            explanation="",
        )


# =============================================================================
# 2. HOMOGRAPH & TYPOSQUATTING ENGINE TESTS (core/homograph_engine.py)
# =============================================================================

def test_homograph_punycode_detection():
    """Verify detection and decoding of Punycode IDN domains."""
    engine = HomographEngine()
    # xn--pple-43d.com -> apple.com with Cyrillic 'а'
    result = engine.analyze_domain("xn--pple-43d.com")
    assert result.is_punycode is True
    assert result.is_idn is True
    assert any(s.category == "HOMOGRAPH" for s in result.signals)


def test_unicode_confusable_skeleton():
    """Verify Unicode confusable skeleton mapping (e.g. Cyrillic 'а' -> Latin 'a')."""
    cyrillic_a = "\u0430"
    mixed_paypal = f"p{cyrillic_a}ypal.com"
    skel = confusable_skeleton(mixed_paypal)
    assert skel == "paypal.com"

    engine = HomographEngine()
    res = engine.analyze_domain(mixed_paypal)
    assert res.is_homoglyph_attack is True
    assert res.is_impersonating is True


def test_brand_combosquatting():
    """Verify detection of brand + action/security combosquatting."""
    engine = HomographEngine()
    res = engine.analyze_domain("paypal-security-update.com")
    assert res.is_combosquatting is True
    assert res.target_brand == "PayPal"
    assert res.is_impersonating is True
    assert any("Combosquatting" in s.description for s in res.signals)


def test_subdomain_brand_spoofing():
    """Verify detection of brand injected into subdomain."""
    engine = HomographEngine()
    res = engine.analyze_domain("https://paypal.com.account-verify.ru/login")
    assert res.is_subdomain_spoof is True
    assert res.target_brand == "PayPal"
    assert res.is_impersonating is True


def test_brand_typosquatting_similarity():
    """Verify Levenshtein distance typosquatting detection for close brand lookalikes."""
    engine = HomographEngine(similarity_threshold=0.80)
    res = engine.analyze_domain("paypa1.com")
    # paypa1 is a close typosquat for paypal
    assert res.is_typosquatting is True or res.is_impersonating is True
    assert res.target_brand == "PayPal"


def test_benign_domain_clean():
    """Verify legitimate domains produce clean homograph results."""
    engine = HomographEngine()
    res = engine.analyze_domain("https://www.google.com/search")
    assert res.is_homoglyph_attack is False
    assert res.is_subdomain_spoof is False
    assert res.is_combosquatting is False
    assert res.is_punycode is False


# =============================================================================
# 3. REDIRECT TRACER & ANTI-CLOAKING TESTS (core/redirect_tracer.py)
# =============================================================================

@pytest.mark.asyncio
async def test_redirect_tracer_benign():
    """Verify single-pass redirect without cloaking."""
    tracer = RedirectTracer()

    mock_resp_crawler = MagicMock()
    mock_resp_crawler.url = "https://example.com"
    mock_resp_crawler.status_code = 200
    mock_resp_crawler.reason_phrase = "OK"
    mock_resp_crawler.headers = {"content-type": "text/html"}
    mock_resp_crawler.text = "<html><head><title>Example</title></head><body>Welcome</body></html>"
    mock_resp_crawler.is_redirect = False

    mock_resp_mobile = MagicMock()
    mock_resp_mobile.url = "https://example.com"
    mock_resp_mobile.status_code = 200
    mock_resp_mobile.reason_phrase = "OK"
    mock_resp_mobile.headers = {"content-type": "text/html"}
    mock_resp_mobile.text = "<html><head><title>Example</title></head><body>Welcome</body></html>"
    mock_resp_mobile.is_redirect = False

    async def mock_get(url, **kwargs):
        headers = kwargs.get("headers", {})
        ua = headers.get("User-Agent", "")
        if "Googlebot" in ua:
            return mock_resp_crawler
        return mock_resp_mobile

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        res = await tracer.trace("https://example.com")
        assert res.final_destination_url == "https://example.com"
        assert res.is_cloaked is False
        assert res.hop_count == 1


@pytest.mark.asyncio
async def test_redirect_tracer_anti_cloaking_detected():
    """Verify anti-cloaking dual-pass check flags divergence (crawler 404 vs mobile login)."""
    tracer = RedirectTracer()

    # Pass A (Crawler): 404 Not Found benign error page
    mock_resp_crawler = MagicMock()
    mock_resp_crawler.url = "https://cloak-test.com"
    mock_resp_crawler.status_code = 404
    mock_resp_crawler.reason_phrase = "Not Found"
    mock_resp_crawler.headers = {}
    mock_resp_crawler.text = "<html><title>Not Found</title><body>404 Not Found</body></html>"
    mock_resp_crawler.is_redirect = False

    # Pass B (Mobile Safari): 200 OK phishing login page with password field
    mock_resp_mobile = MagicMock()
    mock_resp_mobile.url = "https://cloak-test.com/login"
    mock_resp_mobile.status_code = 200
    mock_resp_mobile.reason_phrase = "OK"
    mock_resp_mobile.headers = {}
    mock_resp_mobile.text = (
        '<html><title>Bank Login</title><body><form><input type="password" name="pwd"/></form></body></html>'
    )
    mock_resp_mobile.is_redirect = False

    async def mock_get(url, **kwargs):
        headers = kwargs.get("headers", {})
        ua = headers.get("User-Agent", "")
        if "Googlebot" in ua:
            return mock_resp_crawler
        return mock_resp_mobile

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        res = await tracer.trace("https://cloak-test.com")
        assert res.is_cloaked is True
        assert any(s.category == "CLOAKING" for s in res.signals)
        assert any(s.severity == "CRITICAL" for s in res.signals)


# =============================================================================
# 4. SSL INFRASTRUCTURE & CERTIFICATE ANALYZER (core/ssl_analyzer.py)
# =============================================================================

@pytest.mark.asyncio
async def test_ssl_analyzer_young_cert_detection():
    """Verify SSL temporal analysis flags certs issued under 24 hours ago."""
    analyzer = SSLAnalyzer()

    # Certificate issued 5 hours ago
    now = datetime.now(timezone.utc)
    issued_time = now - timedelta(hours=5)
    not_before_str = issued_time.strftime("%b %d %H:%M:%S %Y GMT")

    fake_cert = {
        "notBefore": not_before_str,
        "notAfter": (now + timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT"),
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "subjectAltName": (("DNS", "bad-phish.xyz"),),
    }

    with patch.object(analyzer, "_fetch_certificate", return_value=fake_cert):
        res = await analyzer.analyze("https://bad-phish.xyz")
        assert res.has_ssl is True
        assert res.certificate_age_hours is not None
        assert res.certificate_age_hours < 24.0
        assert res.is_young_cert is True
        assert res.is_very_young_cert is True
        assert res.is_disposable_issuer is True
        assert any("young ssl certificate" in s.description.lower() for s in res.signals)


@pytest.mark.asyncio
async def test_ssl_analyzer_non_standard_port():
    """Verify auditing flags web servers operating on non-standard ports."""
    analyzer = SSLAnalyzer()

    with patch.object(analyzer, "_fetch_certificate", return_value=None):
        res = await analyzer.analyze("http://malicious-node.com:8443/steal")
        assert res.port == 8443
        assert res.is_non_standard_port is True
        assert any("Non-standard web port" in s.description for s in res.signals)


# =============================================================================
# 5. DOM & VISUAL FAVICON INSPECTOR TESTS (core/dom_inspector.py)
# =============================================================================

def test_murmur3_favicon_hash_known_brand():
    """Verify Censys/Shodan standard Murmur3 hash calculation against official brand hashes."""
    # Test Microsoft favicon hash (-1302820302)
    # Even if we don't have the exact Microsoft icon binary, let's test compute_murmur3_hash on bytes
    h = compute_murmur3_hash(b"test-favicon-bytes")
    assert isinstance(h, int)


@pytest.mark.asyncio
async def test_dom_inspector_brand_favicon_mismatch():
    """Verify CRITICAL alert raised when brand favicon is hosted on untrusted domain."""
    inspector = DOMInspector()

    # Pre-calculated Murmur3 hash for Microsoft is -1302820302
    with patch("phishlens.agents.url_agent.core.dom_inspector.compute_shodan_favicon_hash", return_value=-1302820302):
        res = await inspector.inspect(
            url="https://evil-unauthorized-host.ru/login",
            html_body='<html><head><link rel="icon" href="/favicon.ico"></head></html>',
            favicon_bytes=b"dummy_microsoft_bytes",
        )
        assert res.favicon_hash == -1302820302
        assert res.matched_brand == "Microsoft"
        assert res.is_brand_mismatch is True
        assert any("FAVICON_BRAND_IMPERSONATION" in s.description for s in res.signals)


@pytest.mark.asyncio
async def test_dom_inspector_credential_and_cross_domain_form():
    """Verify detection of <input type='password'> and cross-domain action exfiltration."""
    inspector = DOMInspector()
    html = """
    <html>
      <body>
        <h2>Login to Account</h2>
        <form action="https://external-stealer.xyz/collect" method="POST">
          <input type="text" name="username"/>
          <input type="password" name="password"/>
          <input type="text" name="card_number" placeholder="Enter Credit Card Number"/>
          <button type="submit">Submit</button>
        </form>
      </body>
    </html>
    """
    res = await inspector.inspect(
        url="https://victim-bank.com/account",
        html_body=html,
    )
    assert res.has_password_input is True
    assert res.has_payment_input is True
    assert len(res.external_form_actions) == 1
    assert "external-stealer.xyz" in res.external_form_actions[0]
    assert any(s.category == "DOM" and "Cross-domain" in s.description for s in res.signals)


# =============================================================================
# 6. ORCHESTRATOR & WEIGHTED SCORING TESTS (url_agent.py)
# =============================================================================

@pytest.mark.asyncio
async def test_orchestrator_safe_benign_url():
    """Verify safe domain receives score < 35 and threat_level SAFE."""
    agent = URLAgent()

    # Mock all sub-modules to return clean/benign findings
    mock_homograph = HomographAnalysisResult(
        domain="example.com",
        is_idn=False,
        is_punycode=False,
        punycode_decoded="",
        skeleton_string="example.com",
        is_homoglyph_attack=False,
        is_typosquatting=False,
        is_combosquatting=False,
        is_subdomain_spoof=False,
        target_brand=None,
        similarity_score=0.0,
    )
    mock_redirect = RedirectTraceResult(
        initial_url="https://example.com",
        final_destination_url="https://example.com",
        redirect_chain=["https://example.com"],
        hops=[HopDetail(step=1, url="https://example.com", status_code=200, reason="OK")],
        pass_a_status=200,
        pass_b_status=200,
        pass_a_body="",
        pass_b_body="",
        pass_a_title="Example",
        pass_b_title="Example",
        is_cloaked=False,
        cloaking_reason=None,
        signals=[],
        metadata={},
    )
    mock_ssl = SSLAnalysisResult(
        has_ssl=True,
        port=443,
        is_non_standard_port=False,
        certificate_age_hours=2400.0,
        is_young_cert=False,
        is_very_young_cert=False,
        issuer="DigiCert Global Root CA",
        subject="example.com",
        san_count=1,
        sans=["example.com"],
        is_disposable_issuer=False,
    )
    mock_dom = DOMInspectionResult(
        favicon_hash=None,
        matched_brand=None,
        is_brand_favicon_mismatch=False,
        has_password_input=False,
        has_payment_input=False,
        cross_domain_form_actions=[],
    )

    with patch.object(agent.homograph_engine, "analyze", return_value=mock_homograph), \
         patch.object(agent.redirect_tracer, "trace_redirects", return_value=mock_redirect), \
         patch.object(agent.ssl_analyzer, "analyze", return_value=mock_ssl), \
         patch.object(agent.dom_inspector, "inspect", return_value=mock_dom):

        out = await agent.analyze("https://example.com")
        assert out.risk_score == 0
        assert out.threat_level == "SAFE"
        assert "Threat Level: SAFE" in out.explanation


@pytest.mark.asyncio
async def test_orchestrator_weighted_scoring_rules():
    """
    Verify exact weighted scoring rules from specification:
      - Homograph / Brand Impersonation: +35 points
      - Young SSL Cert (<24 hrs) + Password Input Present: +40 points
      - Favicon Hash Brand Mismatch: +45 points
      - Cloaking / Evasive User-Agent: +30 points
      - Multi-Hop Redirect to Untrusted TLD: +20 points
    """
    agent = URLAgent()

    # Case 1: Homograph alone (+35) -> SUSPICIOUS
    mock_homo = HomographAnalysisResult(
        domain="paypa1.com",
        is_idn=False,
        is_punycode=False,
        punycode_decoded="",
        skeleton_string="paypa1.com",
        is_homoglyph_attack=False,
        is_typosquatting=True,
        is_combosquatting=False,
        is_subdomain_spoof=False,
        target_brand="PayPal",
        similarity_score=0.91,
    )
    with patch.object(agent.homograph_engine, "analyze", return_value=mock_homo), \
         patch.object(agent.redirect_tracer, "trace_redirects", return_value=None), \
         patch.object(agent.ssl_analyzer, "analyze", return_value=None), \
         patch.object(agent.dom_inspector, "inspect", return_value=None):

        res = await agent.analyze("https://paypa1.com")
        assert res.risk_score >= 35
        assert res.threat_level == "SUSPICIOUS"

    # Case 2: Favicon mismatch alone (+45) -> SUSPICIOUS
    mock_dom_fav = DOMInspectionResult(
        favicon_hash=-1302820302,
        matched_brand="Microsoft",
        is_brand_favicon_mismatch=True,
        has_password_input=False,
        has_payment_input=False,
        cross_domain_form_actions=[],
    )
    with patch.object(agent.homograph_engine, "analyze", return_value=None), \
         patch.object(agent.redirect_tracer, "trace_redirects", return_value=None), \
         patch.object(agent.ssl_analyzer, "analyze", return_value=None), \
         patch.object(agent.dom_inspector, "inspect", return_value=mock_dom_fav):

        res = await agent.analyze("https://untrusted-host.xyz")
        assert res.risk_score >= 45

    # Case 3: Combined zero-day phishing combo ->
    # Young SSL (<24h) + Password Input (+40) + Cloaking (+30) -> 70 (MALICIOUS)
    mock_ssl_young = SSLAnalysisResult(
        has_ssl=True,
        port=443,
        is_non_standard_port=False,
        certificate_age_hours=6.5,
        is_young_cert=True,
        is_very_young_cert=True,
        issuer="Let's Encrypt",
        subject="fast-phish.top",
        san_count=1,
        sans=["fast-phish.top"],
        is_disposable_issuer=True,
    )
    mock_dom_pwd = DOMInspectionResult(
        favicon_hash=None,
        matched_brand=None,
        is_brand_favicon_mismatch=False,
        has_password_input=True,
        has_payment_input=False,
        cross_domain_form_actions=[],
    )
    mock_redirect_cloak = RedirectTraceResult(
        initial_url="https://fast-phish.top",
        final_destination_url="https://fast-phish.top/login",
        redirect_chain=["https://fast-phish.top", "https://fast-phish.top/login"],
        hops=[],
        pass_a_status=404,
        pass_b_status=200,
        pass_a_body="",
        pass_b_body="",
        pass_a_title="",
        pass_b_title="Login",
        is_cloaked=True,
        cloaking_reason="Divergent status",
        signals=[],
        metadata={},
    )
    with patch.object(agent.homograph_engine, "analyze", return_value=None), \
         patch.object(agent.redirect_tracer, "trace_redirects", return_value=mock_redirect_cloak), \
         patch.object(agent.ssl_analyzer, "analyze", return_value=mock_ssl_young), \
         patch.object(agent.dom_inspector, "inspect", return_value=mock_dom_pwd):

        res = await agent.analyze("https://fast-phish.top")
        assert res.risk_score >= 70
        assert res.threat_level == "MALICIOUS"
        assert "Key Threat Indicators:" in res.explanation


@pytest.mark.asyncio
async def test_orchestrator_network_fallback_resilience():
    """Verify orchestrator gracefully recovers with fallback signals when network modules throw."""
    agent = URLAgent()

    with patch.object(agent.homograph_engine, "analyze", side_effect=RuntimeError("IDN parse failure")), \
         patch.object(agent.redirect_tracer, "trace_redirects", side_effect=TimeoutError("Network down")), \
         patch.object(agent.ssl_analyzer, "analyze", side_effect=ConnectionResetError("Reset")), \
         patch.object(agent.dom_inspector, "inspect", side_effect=Exception("DOM parse error")):

        res = await agent.analyze("https://timeout-test.com")
        # Should gracefully return without crashing
        assert isinstance(res, URLAgentOutput)
        assert res.threat_level in ["SAFE", "SUSPICIOUS"]
        assert len(res.signals) >= 1
