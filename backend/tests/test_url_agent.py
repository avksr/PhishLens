"""
backend.tests.test_url_agent — Unit tests for the URL & Domain Intelligence Agent.

Covers:
  - Core URL analysis (skipped, legitimate, phishing)
  - LRU-cached WHOIS performance benchmarks (cached vs uncached)
  - Homoglyph / Punycode lookalike detection
  - Cache pre-warming
  - Edge cases and error handling
  - Google Safe Browsing API v4 (FR-4)
  - Domain age < 30 days flagging with registrar capture (FR-5)
  - Expanded brand watchlist for Indian utilities (FR-7)

Run from the project root:
    python -m pytest backend/tests/test_url_agent.py -v

Or from the backend/ directory:
    python -m pytest tests/test_url_agent.py -v
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock

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
        domain_cache_info,
        domain_cache_clear,
        _domain_cache,
        _DomainCacheEntry,
        _whois_fallback,
        _RISK_WHOIS_TIMEOUT_PENALTY,
        _RISK_SAFE_BROWSING,
        check_google_safe_browsing,
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
        domain_cache_info,
        domain_cache_clear,
        _domain_cache,
        _DomainCacheEntry,
        _whois_fallback,
        _RISK_WHOIS_TIMEOUT_PENALTY,
        _RISK_SAFE_BROWSING,
        check_google_safe_browsing,
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


def _patch_whois_and_safebrowsing(whois_return, sb_return=(None, 0.0, [])):
    """
    Helper to patch both _check_whois_age and check_google_safe_browsing
    for tests that need to isolate from network calls.
    """
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        with patch(
            f"{analyze_url.__module__}._check_whois_age",
            return_value=whois_return,
        ), patch(
            f"{analyze_url.__module__}.check_google_safe_browsing",
            return_value=sb_return,
        ):
            yield

    return _ctx()


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

    with _patch_whois_and_safebrowsing(
        whois_return=(365, None, 0.0, []),
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

    with _patch_whois_and_safebrowsing(
        whois_return=(5, "NameCheap, Inc.", 40.0, ["NEW_DOMAIN (<30 days)"]),
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

    with _patch_whois_and_safebrowsing(
        whois_return=(None, None, 0.0, []),
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
    with _patch_whois_and_safebrowsing(
        whois_return=(2, "GoDaddy", 40.0, ["NEW_DOMAIN (<30 days)"]),
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
        ):
            # Mock the whois module at the import level
            import types
            mock_mod = types.ModuleType("whois")

            class MockWhoisResult:
                creation_date = None
                registrar = None

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
            registrar = "MockRegistrar Inc."

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
            registrar = "Prewarm Registrar"

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
            registrar = "Speed Registrar"

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
        result = _normalise_homoglyphs("g\u043e\u043egle")
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
        Domain 'sb\\u2170-bank' (using roman numeral ⅰ for i) should be
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
        Domain 'i\\u0441ici' (Cyrillic с for Latin c) should be flagged.
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

    with _patch_whois_and_safebrowsing(
        whois_return=(None, None, 0.0, []),
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

    with _patch_whois_and_safebrowsing(
        whois_return=(3, "Shady Registrar LLC", 40.0, ["NEW_DOMAIN (<30 days)"]),
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

    with _patch_whois_and_safebrowsing(
        whois_return=(None, None, 0.0, []),
    ):
        result = await analyze_url(req)

    assert result.status == AgentStatusEnum.SUCCESS
    assert result.is_typosquatting is True
    assert result.target_brand == "Jio"


# ──────────────────────────────────────────────
# Domain-Result LRU Cache tests
# ──────────────────────────────────────────────

class TestDomainResultCache:
    """Tests for the TTL-aware in-memory domain-result cache."""

    def setup_method(self):
        domain_cache_clear()
        whois_cache_clear()

    def test_cache_starts_empty(self):
        """After clearing, the domain-result cache must report zero entries."""
        info = domain_cache_info()
        assert info["hits"] == 0
        assert info["misses"] == 0
        assert info["size"] == 0
        assert info["maxsize"] == 4096

    @pytest.mark.asyncio
    async def test_repeat_domain_returns_cached_result(self):
        """
        Two scans of the same domain must return identical results and
        the second must be served from the domain cache.
        """
        req = _make_request(extracted_url="https://sbi-kyc-verify.top")

        with _patch_whois_and_safebrowsing(
            whois_return=(5, "NameCheap, Inc.", 40.0, ["NEW_DOMAIN (<30 days)"]),
        ):
            result1 = await analyze_url(req)
            result2 = await analyze_url(req)

        # Both should succeed with the same score
        assert result1.status == AgentStatusEnum.SUCCESS
        assert result2.status == AgentStatusEnum.SUCCESS
        assert result1.risk_score == result2.risk_score
        assert result1.flags == result2.flags

        # The second scan should have hit the domain cache
        info = domain_cache_info()
        assert info["hits"] >= 1
        assert info["size"] >= 1

    @pytest.mark.asyncio
    async def test_cached_response_contains_cached_marker(self):
        """
        A domain-cache HIT must include '[cached]' in the details string
        so callers can distinguish cached from fresh results.
        """
        req = _make_request(extracted_url="https://sbi-kyc-verify.top")

        with _patch_whois_and_safebrowsing(
            whois_return=(None, None, 0.0, []),
        ):
            await analyze_url(req)  # populate
            result = await analyze_url(req)  # cached

        assert "[cached]" in (result.details or "")

    @pytest.mark.asyncio
    async def test_cached_lookup_under_1ms(self):
        """
        Benchmark: A domain-cache HIT must complete in <1 ms.
        """
        req = _make_request(extracted_url="https://sbi-kyc-verify.top")

        with _patch_whois_and_safebrowsing(
            whois_return=(None, None, 0.0, []),
        ):
            await analyze_url(req)  # populate

            t0 = time.perf_counter()
            result = await analyze_url(req)  # cached
            elapsed_ms = (time.perf_counter() - t0) * 1000

        assert result.latency_ms < 1.0, (
            f"Cached lookup took {result.latency_ms:.3f} ms, expected < 1 ms"
        )
        print(f"\n  ⚡ Domain-cache HIT latency: {elapsed_ms:.4f} ms")

    @pytest.mark.asyncio
    async def test_different_domains_are_independent(self):
        """
        Two different domains must not share a cache entry.
        """
        req_a = _make_request(extracted_url="https://sbi-kyc-verify.top")
        req_b = _make_request(extracted_url="https://google.com/search")

        with _patch_whois_and_safebrowsing(
            whois_return=(None, None, 0.0, []),
        ):
            result_a = await analyze_url(req_a)
            result_b = await analyze_url(req_b)

        # Different domains → different results
        assert result_a.domain != result_b.domain
        info = domain_cache_info()
        assert info["size"] >= 2  # both domains cached

    def test_cache_clear_resets_stats(self):
        """domain_cache_clear() must reset hits, misses, and size to 0."""
        _domain_cache.put(
            "example.com",
            _DomainCacheEntry(
                risk_score=10.0,
                tld_rep=TldReputationEnum.NEUTRAL,
                is_typo=False,
                target_brand=None,
                is_homoglyph=False,
                homoglyph_brand=None,
                age_days=365,
                registrar=None,
                safe_browsing_threat=None,
                flags=(),
                tld_delta=0.0,
                typo_delta=0.0,
                homoglyph_delta=0.0,
                age_delta=0.0,
            ),
        )
        assert domain_cache_info()["size"] == 1
        domain_cache_clear()
        info = domain_cache_info()
        assert info["size"] == 0
        assert info["hits"] == 0
        assert info["misses"] == 0


# ──────────────────────────────────────────────
# WHOIS Zero-Downtime Fallback tests
# ──────────────────────────────────────────────

class TestWhoisFallback:
    """Tests for the zero-downtime WHOIS/RDAP fallback mechanism."""

    def setup_method(self):
        domain_cache_clear()
        whois_cache_clear()

    def test_fallback_high_risk_tld_applies_penalty(self):
        """
        When WHOIS is unavailable and the TLD is high-risk, the fallback
        must apply a non-zero penalty score.
        """
        age, delta, flags = _whois_fallback("evil-bank.top", "top")
        assert age is None
        assert delta == _RISK_WHOIS_TIMEOUT_PENALTY
        assert any("WHOIS_TIMEOUT_FALLBACK" in f for f in flags)
        assert any("high-risk" in f.lower() for f in flags)

    def test_fallback_benign_tld_no_penalty(self):
        """
        When WHOIS is unavailable and the TLD is benign (e.g. .com),
        the fallback must return zero penalty.
        """
        age, delta, flags = _whois_fallback("example.com", "com")
        assert age is None
        assert delta == 0.0
        assert any("WHOIS_TIMEOUT_FALLBACK" in f for f in flags)
        assert any("benign" in f.lower() for f in flags)

    @pytest.mark.asyncio
    async def test_timeout_triggers_fallback_not_exception(self):
        """
        A WHOIS timeout must trigger the local TLD fallback and NEVER
        raise an unhandled exception.  We simulate this by returning the
        exact tuple that _whois_fallback would produce for a high-risk TLD.
        """
        req = _make_request(extracted_url="https://evil-bank.top/login")

        # Mock _check_whois_age to return the fallback tuple (simulating
        # internal timeout handling that degrades to local TLD scoring)
        with _patch_whois_and_safebrowsing(
            whois_return=(
                None,
                None,
                _RISK_WHOIS_TIMEOUT_PENALTY,
                ["WHOIS_TIMEOUT_FALLBACK (high-risk TLD .top)"],
            ),
        ):
            # Must NOT raise
            result = await analyze_url(req)

        # Even with WHOIS down, the agent should still succeed
        assert result.status == AgentStatusEnum.SUCCESS
        # TLD + typosquatting signals should still be present
        assert result.risk_score > 0
        # The fallback flag must be in the result
        assert any("WHOIS_TIMEOUT_FALLBACK" in f for f in result.flags)

    @pytest.mark.asyncio
    async def test_whois_exception_triggers_fallback(self):
        """
        Any WHOIS exception (not just timeout) must fall back gracefully.
        """
        req = _make_request(extracted_url="https://suspicious.xyz/phish")

        with _patch_whois_and_safebrowsing(
            whois_return=(None, None, 0.0, ["WHOIS_TIMEOUT_FALLBACK (TLD benign — no penalty)"]),
        ):
            result = await analyze_url(req)

        assert result.status == AgentStatusEnum.SUCCESS
        # The fallback flag should be present
        assert any("WHOIS_TIMEOUT_FALLBACK" in f for f in result.flags)

    @pytest.mark.asyncio
    async def test_fallback_with_high_risk_tld_adds_to_score(self):
        """
        End-to-end: when WHOIS times out on a .top domain, the fallback
        penalty should be added to the risk score on top of the TLD +
        typosquatting signals.
        """
        req = _make_request(extracted_url="https://sbi-kyc-verify.top")

        # Simulate the fallback response
        with _patch_whois_and_safebrowsing(
            whois_return=(
                None,
                None,
                _RISK_WHOIS_TIMEOUT_PENALTY,
                ["WHOIS_TIMEOUT_FALLBACK (high-risk TLD .top)"],
            ),
        ):
            result = await analyze_url(req)

        assert result.status == AgentStatusEnum.SUCCESS
        # Should have TLD (35) + typosquat (50) + fallback penalty (15) = 100
        assert result.risk_score >= 95
        assert "WHOIS_TIMEOUT_FALLBACK" in " ".join(result.flags)


# ──────────────────────────────────────────────
# FR-4: Google Safe Browsing API v4 tests
# ──────────────────────────────────────────────

class TestGoogleSafeBrowsing:
    """Tests for the Google Safe Browsing Lookup API v4 integration."""

    def setup_method(self):
        domain_cache_clear()
        whois_cache_clear()

    @pytest.mark.asyncio
    async def test_skips_when_api_key_missing(self):
        """
        When GOOGLE_SAFE_BROWSING_API_KEY is empty, the check must
        silently return no threat and zero score delta.
        """
        with patch(
            f"{check_google_safe_browsing.__module__}._GOOGLE_SAFE_BROWSING_API_KEY",
            "",
        ):
            threat, delta, flags = await check_google_safe_browsing(
                "https://malicious.example.com"
            )

        assert threat is None
        assert delta == 0.0
        assert flags == []

    @pytest.mark.asyncio
    async def test_returns_threat_on_match(self):
        """
        When Safe Browsing API returns a match, check_google_safe_browsing
        must return the threat type with the correct risk delta.
        """
        mock_response_data = {
            "matches": [
                {
                    "threatType": "SOCIAL_ENGINEERING",
                    "platformType": "ANY_PLATFORM",
                    "threat": {"url": "https://evil.example.com"},
                }
            ]
        }

        with patch(
            f"{check_google_safe_browsing.__module__}._GOOGLE_SAFE_BROWSING_API_KEY",
            "fake-api-key",
        ), patch("httpx.AsyncClient") as MockClient:
            mock_resp = MagicMock()
            mock_resp.json.return_value = mock_response_data
            mock_resp.raise_for_status.return_value = None

            mock_ctx = AsyncMock()
            mock_ctx.__aenter__.return_value = AsyncMock()
            mock_ctx.__aenter__.return_value.post.return_value = mock_resp
            MockClient.return_value = mock_ctx

            threat, delta, flags = await check_google_safe_browsing(
                "https://evil.example.com"
            )

        assert threat == "SOCIAL_ENGINEERING"
        assert delta == _RISK_SAFE_BROWSING
        assert any("GOOGLE_SAFE_BROWSING_THREAT" in f for f in flags)
        assert any("SOCIAL_ENGINEERING" in f for f in flags)

    @pytest.mark.asyncio
    async def test_returns_no_threat_on_clean_url(self):
        """
        When Safe Browsing API returns no matches, the function must
        return None threat with zero delta.
        """
        with patch(
            f"{check_google_safe_browsing.__module__}._GOOGLE_SAFE_BROWSING_API_KEY",
            "fake-api-key",
        ), patch("httpx.AsyncClient") as MockClient:
            mock_resp = MagicMock()
            mock_resp.json.return_value = {}  # no matches
            mock_resp.raise_for_status.return_value = None

            mock_ctx = AsyncMock()
            mock_ctx.__aenter__.return_value = AsyncMock()
            mock_ctx.__aenter__.return_value.post.return_value = mock_resp
            MockClient.return_value = mock_ctx

            threat, delta, flags = await check_google_safe_browsing(
                "https://safe.example.com"
            )

        assert threat is None
        assert delta == 0.0
        assert flags == []

    @pytest.mark.asyncio
    async def test_graceful_fallback_on_network_failure(self):
        """
        When the HTTP request fails, check_google_safe_browsing must
        silently return no threat — never raise.
        """
        with patch(
            f"{check_google_safe_browsing.__module__}._GOOGLE_SAFE_BROWSING_API_KEY",
            "fake-api-key",
        ), patch("httpx.AsyncClient") as MockClient:
            mock_ctx = AsyncMock()
            mock_ctx.__aenter__.return_value = AsyncMock()
            mock_ctx.__aenter__.return_value.post.side_effect = ConnectionError(
                "network down"
            )
            MockClient.return_value = mock_ctx

            threat, delta, flags = await check_google_safe_browsing(
                "https://unreachable.example.com"
            )

        assert threat is None
        assert delta == 0.0
        assert flags == []

    @pytest.mark.asyncio
    async def test_timeout_is_1_second(self):
        """
        The Safe Browsing client must use a 1.0s timeout.
        """
        from agents.url_agent import _SAFE_BROWSING_TIMEOUT
        assert _SAFE_BROWSING_TIMEOUT == 1.0

    @pytest.mark.asyncio
    async def test_safe_browsing_threat_in_full_pipeline(self):
        """
        End-to-end: when Safe Browsing flags a URL, the threat type
        must appear in the result's safe_browsing_threat field and flags.
        """
        req = _make_request(extracted_url="https://sbi-kyc-verify.top/phish")

        with patch(
            f"{analyze_url.__module__}._check_whois_age",
            return_value=(5, "NameCheap, Inc.", 40.0, ["NEW_DOMAIN (<30 days)"]),
        ), patch(
            f"{analyze_url.__module__}.check_google_safe_browsing",
            return_value=(
                "SOCIAL_ENGINEERING",
                _RISK_SAFE_BROWSING,
                ["GOOGLE_SAFE_BROWSING_THREAT (SOCIAL_ENGINEERING)"],
            ),
        ):
            result = await analyze_url(req)

        assert result.status == AgentStatusEnum.SUCCESS
        assert result.safe_browsing_threat == "SOCIAL_ENGINEERING"
        assert any("GOOGLE_SAFE_BROWSING_THREAT" in f for f in result.flags)
        # Score should be clamped to 100 (TLD 35 + typo 50 + WHOIS 40 + SB 50 = 175)
        assert result.risk_score == 100.0


# ──────────────────────────────────────────────
# FR-5: Domain Age Flagging with Registrar tests
# ──────────────────────────────────────────────

class TestDomainAgeFlagging:
    """Tests for domain age < 30 days flagging and registrar capture (FR-5)."""

    def setup_method(self):
        domain_cache_clear()
        whois_cache_clear()

    @pytest.mark.asyncio
    async def test_new_domain_flag_format(self):
        """
        Domain age < 30 days must append 'NEW_DOMAIN (<30 days)' to flags.
        """
        req = _make_request(extracted_url="https://brand-new-phish.top/login")

        with _patch_whois_and_safebrowsing(
            whois_return=(10, "Shady Registrar LLC", 40.0, ["NEW_DOMAIN (<30 days)"]),
        ):
            result = await analyze_url(req)

        assert result.domain_age_days == 10
        assert any("NEW_DOMAIN" in f and "<30 days" in f for f in result.flags), (
            f"Expected 'NEW_DOMAIN (<30 days)' flag, got: {result.flags}"
        )

    @pytest.mark.asyncio
    async def test_registrar_captured_in_result(self):
        """
        When WHOIS returns registrar info, the UrlAgentResult must
        include it in the registrar field.
        """
        req = _make_request(extracted_url="https://evil-phish.top/login")

        with _patch_whois_and_safebrowsing(
            whois_return=(5, "NameCheap, Inc.", 40.0, ["NEW_DOMAIN (<30 days)"]),
        ):
            result = await analyze_url(req)

        assert result.registrar == "NameCheap, Inc."

    @pytest.mark.asyncio
    async def test_registrar_none_when_whois_fails(self):
        """
        When WHOIS fails and falls back, registrar should be None.
        """
        req = _make_request(extracted_url="https://some-domain.com/page")

        with _patch_whois_and_safebrowsing(
            whois_return=(None, None, 0.0, ["WHOIS_TIMEOUT_FALLBACK (TLD benign — no penalty)"]),
        ):
            result = await analyze_url(req)

        assert result.registrar is None

    @pytest.mark.asyncio
    async def test_old_domain_no_new_domain_flag(self):
        """
        Domain age >= 30 days must NOT produce a NEW_DOMAIN flag.
        """
        req = _make_request(extracted_url="https://sbi.co.in/portal")

        with _patch_whois_and_safebrowsing(
            whois_return=(3650, "GoDaddy.com, LLC", 0.0, []),
        ):
            result = await analyze_url(req)

        assert not any("NEW_DOMAIN" in f for f in result.flags)
        assert result.registrar == "GoDaddy.com, LLC"

    def test_lookup_domain_age_returns_tuple_with_registrar(self):
        """
        _lookup_domain_age must return (age_days, registrar) tuple
        or None on failure.
        """
        import types
        mock_mod = types.ModuleType("whois")

        from datetime import datetime, timezone

        class MockWhoisResult:
            creation_date = datetime(2024, 9, 15, tzinfo=timezone.utc)
            registrar = "TestRegistrar Corp"

        mock_mod.whois = lambda d: MockWhoisResult()
        sys.modules["whois"] = mock_mod

        try:
            whois_cache_clear()
            result = _lookup_domain_age("test-registrar.com")

            assert result is not None
            assert isinstance(result, tuple)
            assert len(result) == 2
            age_days, registrar = result
            assert isinstance(age_days, int)
            assert age_days > 0
            assert registrar == "TestRegistrar Corp"
        finally:
            if "whois" in sys.modules:
                del sys.modules["whois"]


# ──────────────────────────────────────────────
# FR-7: Expanded Brand Watchlist tests
# ──────────────────────────────────────────────

class TestExpandedBrandWatchlist:
    """Tests for the expanded brand_domains.json (FR-7)."""

    def setup_method(self):
        domain_cache_clear()
        whois_cache_clear()
        # Force reload of brand data
        import agents.url_agent as _mod
        _mod._brand_data_cache = None

    @pytest.mark.asyncio
    async def test_irctc_phishing_detected(self):
        """Fake IRCTC domain should be detected as typosquatting."""
        req = _make_request(
            extracted_url="https://irctc-booking-refund.top/claim"
        )
        with _patch_whois_and_safebrowsing(
            whois_return=(None, None, 0.0, []),
        ):
            result = await analyze_url(req)

        assert result.is_typosquatting is True
        assert result.target_brand == "IRCTC"

    @pytest.mark.asyncio
    async def test_irctc_official_not_flagged(self):
        """Official IRCTC domain must NOT be flagged as typosquatting."""
        req = _make_request(
            extracted_url="https://irctc.co.in/nget/train-search"
        )
        with _patch_whois_and_safebrowsing(
            whois_return=(3650, None, 0.0, []),
        ):
            result = await analyze_url(req)

        assert result.is_typosquatting is False

    @pytest.mark.asyncio
    async def test_indianrail_official_not_flagged(self):
        """indianrail.gov.in is a legitimate IRCTC domain."""
        req = _make_request(
            extracted_url="https://indianrail.gov.in/enquiry"
        )
        with _patch_whois_and_safebrowsing(
            whois_return=(5000, None, 0.0, []),
        ):
            result = await analyze_url(req)

        # 'indianrail' keyword should match IRCTC but domain is official
        assert result.is_typosquatting is False

    @pytest.mark.asyncio
    async def test_bses_phishing_detected(self):
        """Fake BSES domain should be detected."""
        req = _make_request(
            extracted_url="https://bses-bill-payment.top/pay"
        )
        with _patch_whois_and_safebrowsing(
            whois_return=(None, None, 0.0, []),
        ):
            result = await analyze_url(req)

        assert result.is_typosquatting is True
        assert "BSES" in (result.target_brand or "")

    @pytest.mark.asyncio
    async def test_uppcl_phishing_detected(self):
        """Fake UPPCL domain should be detected."""
        req = _make_request(
            extracted_url="https://uppclonline-billpay.xyz/verify"
        )
        with _patch_whois_and_safebrowsing(
            whois_return=(None, None, 0.0, []),
        ):
            result = await analyze_url(req)

        assert result.is_typosquatting is True
        assert "UPPCL" in (result.target_brand or "")

    @pytest.mark.asyncio
    async def test_tneb_phishing_detected(self):
        """Fake TNEB domain should be detected."""
        req = _make_request(
            extracted_url="https://tneb-bill-payment.top/login"
        )
        with _patch_whois_and_safebrowsing(
            whois_return=(None, None, 0.0, []),
        ):
            result = await analyze_url(req)

        assert result.is_typosquatting is True
        assert "TNEB" in (result.target_brand or "")

    @pytest.mark.asyncio
    async def test_paytm_official_not_flagged(self):
        """Official Paytm domain must NOT be flagged."""
        req = _make_request(
            extracted_url="https://paytm.com/offer"
        )
        with _patch_whois_and_safebrowsing(
            whois_return=(3000, "GoDaddy", 0.0, []),
        ):
            result = await analyze_url(req)

        assert result.is_typosquatting is False

    @pytest.mark.asyncio
    async def test_phonepe_official_not_flagged(self):
        """Official PhonePe domain must NOT be flagged."""
        req = _make_request(
            extracted_url="https://phonepe.com/pay"
        )
        with _patch_whois_and_safebrowsing(
            whois_return=(2000, None, 0.0, []),
        ):
            result = await analyze_url(req)

        assert result.is_typosquatting is False

    @pytest.mark.asyncio
    async def test_googlepay_official_not_flagged(self):
        """Official Google Pay domain must NOT be flagged."""
        req = _make_request(
            extracted_url="https://pay.google.com/send"
        )
        with _patch_whois_and_safebrowsing(
            whois_return=(5000, None, 0.0, []),
        ):
            result = await analyze_url(req)

        # gpay keyword matches but pay.google.com is official
        assert result.is_typosquatting is False
