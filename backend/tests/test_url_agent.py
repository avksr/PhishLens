"""
backend.tests.test_url_agent — Unit tests for the URL & Domain Intelligence Agent.

Covers:
  - Core URL analysis (skipped, legitimate, phishing)
  - LRU-cached WHOIS performance benchmarks (cached vs uncached)
  - Homoglyph / Punycode lookalike detection
  - Cache pre-warming
  - Edge cases and error handling

Run from the project root:
    python -m pytest backend/tests/test_url_agent.py -v

Or from the backend/ directory:
    python -m pytest tests/test_url_agent.py -v
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

# ── Ensure backend/ and project root are on sys.path so imports resolve ──
_BACKEND_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _BACKEND_DIR.parent
for _p in (str(_BACKEND_DIR), str(_PROJECT_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from agents.url_agent import (  # noqa: E402
        analyze_url,
        whois_cache_info,
        whois_cache_clear,
        prewarm_whois_cache,
        _normalise_homoglyphs,
        _has_mixed_scripts,
        _is_punycode_domain,
        _check_homoglyph,
        _lookup_domain_age,
        _PREWARM_DOMAINS,
    )
except ImportError:
    from backend.agents.url_agent import (  # noqa: E402
        analyze_url,
        whois_cache_info,
        whois_cache_clear,
        prewarm_whois_cache,
        _normalise_homoglyphs,
        _has_mixed_scripts,
        _is_punycode_domain,
        _check_homoglyph,
        _lookup_domain_age,
        _PREWARM_DOMAINS,
    )

try:
    from shared.models import (  # noqa: E402
        AgentStatusEnum,
        ScanRequest,
        TldReputationEnum,
        UrlAgentResult,
    )
except ImportError:
    from backend.shared.models import (  # noqa: E402
        AgentStatusEnum,
        ScanRequest,
        TldReputationEnum,
        UrlAgentResult,
    )


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _make_request(
    content: str = "Test message with URL payload",
    extracted_url: str | None = None,
) -> ScanRequest:
    """Shorthand factory for test ScanRequests."""
    return ScanRequest(content=content, extracted_url=extracted_url)


# ──────────────────────────────────────────────
# Original test cases (preserved)
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_url_agent_skipped_when_no_url():
    """
    A payload that contains no URL at all must return:
      - status  = SKIPPED
      - risk_score = 0.0
    """
    req = _make_request(content="Hey, can you send me the report by EOD?")
    result = await analyze_url(req)

    assert isinstance(result, UrlAgentResult)
    assert result.status == AgentStatusEnum.SKIPPED
    assert result.risk_score == 0.0
    assert result.details == "No URL detected in payload"
    assert result.latency_ms >= 0


@pytest.mark.asyncio
async def test_url_agent_legitimate_bank_url():
    """
    An official bank URL (e.g. ``https://www.onlinesbi.sbi/portal``) must:
      - NOT be flagged as typosquatting
      - have a risk score < 15
    """
    req = _make_request(extracted_url="https://www.onlinesbi.sbi/portal")

    # Patch WHOIS so tests don't make real network calls
    with patch(
        f"{analyze_url.__module__}._check_whois_age",
        return_value=(365, 0.0, []),
    ):
        result = await analyze_url(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.risk_score < 15
    assert result.is_typosquatting is False
    assert "TYPOSQUATTING_DETECTED" not in result.flags


@pytest.mark.asyncio
async def test_url_agent_typosquatting_phishing_url():
    """
    A phishing lookalike URL (e.g. ``https://sbi-kyc-verify.top``) must:
      - risk_score ≥ 80
      - is_typosquatting = True
      - tld_reputation = HIGH_RISK
      - contain both TYPOSQUATTING_DETECTED and HIGH_RISK_TLD flags
    """
    req = _make_request(extracted_url="https://sbi-kyc-verify.top")

    with patch(
        f"{analyze_url.__module__}._check_whois_age",
        return_value=(5, 40.0, ["NEWLY_REGISTERED_DOMAIN (< 30 days)"]),
    ):
        result = await analyze_url(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.risk_score >= 80
    assert result.is_typosquatting is True
    assert result.tld_reputation == TldReputationEnum.HIGH_RISK
    assert "TYPOSQUATTING_DETECTED" in result.flags
    assert "HIGH_RISK_TLD" in result.flags


@pytest.mark.asyncio
async def test_url_agent_handles_exceptions_gracefully():
    """
    When an unexpected error occurs inside the agent, it must:
      - NOT raise an unhandled exception
      - Return a valid UrlAgentResult with status = ERROR
    """
    # Sabotage _parse_domain to force an exception inside the try block
    with patch(
        f"{analyze_url.__module__}._parse_domain",
        side_effect=RuntimeError("simulated parsing failure"),
    ):
        req = _make_request(extracted_url="https://definitely-broken.example")
        result = await analyze_url(req)

    assert isinstance(result, UrlAgentResult)
    assert result.status == AgentStatusEnum.ERROR
    assert result.risk_score == 0.0
    assert "simulated parsing failure" in (result.details or "")
    assert result.latency_ms >= 0


# ──────────────────────────────────────────────
# Additional edge-case tests
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_url_extracted_from_content_body():
    """
    When ``extracted_url`` is ``None`` but ``content`` contains a URL,
    the agent should extract and analyse it.
    """
    msg = "Dear customer, verify your account at https://hdfc-secure-login.xyz/verify immediately."
    req = _make_request(content=msg)

    with patch(
        f"{analyze_url.__module__}._check_whois_age",
        return_value=(None, 0.0, []),
    ):
        result = await analyze_url(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.url_analyzed is not None
    assert "hdfc-secure-login.xyz" in (result.url_analyzed or "")
    # Should detect typosquatting on HDFC + high-risk .xyz TLD
    assert result.is_typosquatting is True
    assert result.tld_reputation == TldReputationEnum.HIGH_RISK


@pytest.mark.asyncio
async def test_risk_score_clamped_to_100():
    """
    Even when all signals fire, the final risk_score must not exceed 100.
    """
    req = _make_request(extracted_url="https://sbi-kyc-verify.top")

    # Force WHOIS to also add +40 → total = 35 + 50 + 40 = 125 → clamp to 100
    with patch(
        f"{analyze_url.__module__}._check_whois_age",
        return_value=(2, 40.0, ["NEWLY_REGISTERED_DOMAIN (< 30 days)"]),
    ):
        result = await analyze_url(req)

    assert result.risk_score <= 100.0


@pytest.mark.asyncio
async def test_empty_request_returns_skipped():
    """ScanRequest without URL should be SKIPPED, not crash."""
    req = ScanRequest(content="Message without URL")
    result = await analyze_url(req)

    assert result.status == AgentStatusEnum.SKIPPED
    assert result.risk_score == 0.0


# ──────────────────────────────────────────────
# WHOIS LRU Cache tests
# ──────────────────────────────────────────────

class TestWhoisCache:
    """Tests for the in-memory LRU WHOIS cache."""

    def setup_method(self):
        """Clear cache before each test for isolation."""
        whois_cache_clear()

    def test_cache_info_starts_empty(self):
        """After clearing, cache should have zero hits and misses."""
        info = whois_cache_info()
        assert info.hits == 0
        assert info.misses == 0
        assert info.maxsize == 2048

    def test_cached_lookup_returns_same_result(self):
        """Repeated calls with the same domain should return cached results."""
        with patch(
            "backend.agents.url_agent.whois",
            create=True,
        ) as mock_whois_module:
            # Mock the whois module at the import level
            import types
            mock_mod = types.ModuleType("whois")

            class MockWhoisResult:
                creation_date = None

            mock_mod.whois = lambda d: MockWhoisResult()
            sys.modules["whois"] = mock_mod

            try:
                # First call — cache miss
                result1 = _lookup_domain_age("example-test-domain.com")
                # Second call — cache hit
                result2 = _lookup_domain_age("example-test-domain.com")

                assert result1 == result2
                info = whois_cache_info()
                assert info.hits >= 1
                assert info.misses >= 1
            finally:
                # Restore
                if "whois" in sys.modules:
                    del sys.modules["whois"]

    def test_cached_vs_uncached_speed_benchmark(self):
        """
        Benchmark: Cached lookups must be < 0.5ms.
        First call may be slow (mocked), subsequent calls must be sub-millisecond.
        """
        # Mock whois to simulate a 50ms lookup
        import types
        mock_mod = types.ModuleType("whois")

        from datetime import datetime, timezone

        class MockWhoisResult:
            creation_date = datetime(2020, 1, 1, tzinfo=timezone.utc)

        def slow_whois(domain):
            time.sleep(0.05)  # 50ms simulated network call
            return MockWhoisResult()

        mock_mod.whois = slow_whois
        sys.modules["whois"] = mock_mod

        try:
            whois_cache_clear()

            # First call — uncached (should take ~50ms)
            t0 = time.perf_counter()
            result_uncached = _lookup_domain_age("benchmark-test.com")
            uncached_ms = (time.perf_counter() - t0) * 1000

            # Second call — cached (should take < 0.5ms)
            t0 = time.perf_counter()
            result_cached = _lookup_domain_age("benchmark-test.com")
            cached_ms = (time.perf_counter() - t0) * 1000

            assert result_uncached == result_cached
            assert cached_ms < 0.5, f"Cached lookup took {cached_ms:.3f}ms, expected < 0.5ms"
            assert uncached_ms > cached_ms, "Uncached should be slower than cached"

            info = whois_cache_info()
            assert info.hits >= 1
            print(f"\n  ⏱  Uncached: {uncached_ms:.3f}ms | Cached: {cached_ms:.4f}ms "
                  f"| Speedup: {uncached_ms / max(cached_ms, 0.001):.0f}x")
        finally:
            if "whois" in sys.modules:
                del sys.modules["whois"]

    def test_cache_maxsize_is_2048(self):
        """LRU cache maxsize must be exactly 2048."""
        info = whois_cache_info()
        assert info.maxsize == 2048

    def test_prewarm_domains_list_has_50_entries(self):
        """Pre-warm list should contain the top 50 domains."""
        assert len(_PREWARM_DOMAINS) >= 50


class TestPrewarmCache:
    """Tests for the cache pre-warming functionality."""

    def setup_method(self):
        whois_cache_clear()

    def test_prewarm_populates_cache(self):
        """Pre-warming should populate the cache with known domains."""
        import types
        mock_mod = types.ModuleType("whois")

        from datetime import datetime, timezone

        class MockWhoisResult:
            creation_date = datetime(2015, 6, 1, tzinfo=timezone.utc)

        mock_mod.whois = lambda d: MockWhoisResult()
        sys.modules["whois"] = mock_mod

        try:
            cached_count = prewarm_whois_cache()
            info = whois_cache_info()

            # All domains should be in cache
            assert info.misses >= cached_count
            assert cached_count > 0
            print(f"\n  🔥 Pre-warmed {cached_count}/{len(_PREWARM_DOMAINS)} domains")
        finally:
            if "whois" in sys.modules:
                del sys.modules["whois"]

    def test_prewarm_cached_lookup_is_submillisecond(self):
        """After pre-warming, lookups for pre-warmed domains must be < 0.5ms."""
        import types
        mock_mod = types.ModuleType("whois")

        from datetime import datetime, timezone

        class MockWhoisResult:
            creation_date = datetime(2018, 3, 15, tzinfo=timezone.utc)

        mock_mod.whois = lambda d: MockWhoisResult()
        sys.modules["whois"] = mock_mod

        try:
            prewarm_whois_cache()

            # Now time a cached lookup for a pre-warmed domain
            t0 = time.perf_counter()
            _ = _lookup_domain_age("sbi.co.in")
            cached_ms = (time.perf_counter() - t0) * 1000

            assert cached_ms < 0.5, f"Pre-warmed lookup took {cached_ms:.3f}ms, expected < 0.5ms"
            print(f"\n  ⚡ Pre-warmed cache lookup: {cached_ms:.4f}ms")
        finally:
            if "whois" in sys.modules:
                del sys.modules["whois"]


# ──────────────────────────────────────────────
# Homoglyph & Punycode detection tests
# ──────────────────────────────────────────────

class TestHomoglyphDetection:
    """Tests for homoglyph / confusable character detection."""

    def test_normalise_cyrillic_a(self):
        """Cyrillic 'а' (U+0430) should normalise to Latin 'a'."""
        result = _normalise_homoglyphs("sb\u0430nk")
        assert result == "sbank"

    def test_normalise_roman_numeral_i(self):
        """Roman numeral 'ⅰ' (U+2170) should normalise to Latin 'i'."""
        result = _normalise_homoglyphs("sb\u2170-bank")
        assert result == "sbi-bank"

    def test_normalise_cyrillic_o(self):
        """Cyrillic 'о' (U+043E) should normalise to Latin 'o'."""
        result = _normalise_homoglyphs("g\u043E\u043Egle")
        assert result == "google"

    def test_normalise_mixed_cyrillic_latin(self):
        """Mixed Cyrillic/Latin domain should fully normalise."""
        # "аpple" with Cyrillic а + Latin pple
        result = _normalise_homoglyphs("\u0430pple")
        assert result == "apple"

    def test_normalise_fullwidth_chars(self):
        """Fullwidth Latin characters should normalise to ASCII."""
        # ｓｂｉ → sbi
        result = _normalise_homoglyphs("\uff53\uff42\uff49")
        assert result == "sbi"

    def test_normalise_pure_ascii_unchanged(self):
        """Pure ASCII strings should pass through unchanged."""
        result = _normalise_homoglyphs("hdfcbank")
        assert result == "hdfcbank"

    def test_mixed_script_detection_cyrillic_latin(self):
        """A string mixing Latin and Cyrillic should be flagged."""
        # "paуtm" — Latin pa + Cyrillic у + Latin tm
        assert _has_mixed_scripts("pa\u0443tm") is True

    def test_mixed_script_detection_pure_latin(self):
        """Pure Latin strings should NOT be flagged as mixed-script."""
        assert _has_mixed_scripts("hdfcbank") is False

    def test_punycode_detection(self):
        """Punycode domains (xn--...) should be detected."""
        assert _is_punycode_domain("xn--sbi-7la") is True
        assert _is_punycode_domain("sbibank") is False

    def test_homoglyph_sbi_with_roman_numeral(self):
        """
        Domain 'sb\u2170-bank' (using roman numeral ⅰ for i) should be
        detected as a homoglyph attack targeting SBI.
        """
        is_attack, brand, score, flags = _check_homoglyph(
            "sb\u2170-bank", "sb\u2170-bank.com"
        )
        assert is_attack is True
        assert "HOMOGLYPH_CHARACTERS" in flags
        assert brand is not None  # Should identify SBI as target

    def test_homoglyph_icici_with_cyrillic(self):
        """
        Domain 'i\u0441ici' (Cyrillic с for Latin c) should be flagged.
        """
        is_attack, brand, score, flags = _check_homoglyph(
            "i\u0441ici", "i\u0441ici.com"
        )
        assert is_attack is True
        assert "HOMOGLYPH_CHARACTERS" in flags

    def test_legitimate_domain_not_flagged(self):
        """Legitimate ASCII domains should not trigger homoglyph detection."""
        is_attack, brand, score, flags = _check_homoglyph(
            "google", "google.com"
        )
        assert is_attack is False
        assert score == 0.0


@pytest.mark.asyncio
async def test_homoglyph_url_full_pipeline():
    """
    End-to-end: A URL with homoglyph characters should be detected
    and flagged by the full analyze_url pipeline.
    """
    # sb\u2170-bank.top — uses roman numeral ⅰ instead of Latin i
    req = _make_request(extracted_url="https://sb\u2170-bank.top/login")

    with patch(
        "backend.agents.url_agent._check_whois_age",
        return_value=(None, 0.0, []),
    ):
        result = await analyze_url(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.risk_score > 0
    # Should have homoglyph-related flags
    has_homoglyph_flag = any(
        "HOMOGLYPH" in f or "MIXED_SCRIPT" in f
        for f in result.flags
    )
    assert has_homoglyph_flag, f"Expected homoglyph flags, got: {result.flags}"


@pytest.mark.asyncio
async def test_airtel_phishing_url():
    """
    Telecom brand phishing: a fake Airtel domain should be detected.
    """
    req = _make_request(extracted_url="https://airtel-recharge-offer.top/claim")

    with patch(
        "backend.agents.url_agent._check_whois_age",
        return_value=(3, 40.0, ["NEWLY_REGISTERED_DOMAIN (< 30 days)"]),
    ):
        result = await analyze_url(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.is_typosquatting is True
    assert result.target_brand == "Airtel"
    assert result.risk_score >= 80


@pytest.mark.asyncio
async def test_jio_phishing_url():
    """
    Telecom brand phishing: a fake Jio domain should be detected.
    """
    req = _make_request(extracted_url="https://jio-free-data.xyz/activate")

    with patch(
        "backend.agents.url_agent._check_whois_age",
        return_value=(None, 0.0, []),
    ):
        result = await analyze_url(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.is_typosquatting is True
    assert result.target_brand == "Jio"
