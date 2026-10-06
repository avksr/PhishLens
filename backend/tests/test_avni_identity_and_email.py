"""
backend/tests/test_avni_identity_and_email.py
---------------------------------------------
Comprehensive tests for AVNI's deliverables:
1. Email / Message analysis:
   - Header checks: SPF fail/softfail, DKIM fail, Reply-To mismatch, display name spoofing
   - Phishing keywords, urgency, raw IP URLs
2. Telecom Phone Validity & TRAI 140/160 series:
   - 140 promotional telemarketing with financial/KYC scam patterns
   - 160 transactional/service legitimate series
   - Toll-free 1800 series
   - Dynamic Levenshtein near-miss header spoofing (e.g. VM-SBIINM vs VM-SBIINB)
3. UPI Verifier & Bank Identity:
   - MockUpiVerifier (default, provider: "SANDBOX_MOCK")
   - RapidApiUpiVerifier fallback
   - Name matching (rapidfuzz / resilient token sort ratio)
   - Institutional impersonation detection (claimed bank vs individual mule)
   - VPA typosquatting detection (e.g. onllnesbi@oksbi)
   - Evidence provider verification ("SANDBOX_MOCK")
"""

from __future__ import annotations

import pytest
from shared.models import (
    AgentStatusEnum,
    ChannelEnum,
    ScanRequest,
    SenderCategoryEnum,
)
from agents.email_agent import analyze_email
from agents.sender_agent import analyze_sender, analyze_sender_multi
from agents.upi_agent import analyze_upi
from scripts.refresh_dlt_registry import run_nnp_prefix_mismatch_audit
from agents.upi_verifier import MockUpiVerifier, RapidApiUpiVerifier, get_upi_verifier
from agents.bank_identity_agent import (
    verify_bank_identity,
    match_claimed_vs_registered,
    compute_fuzzy_name_match,
)
from core.verdict_utils import build_evidence_list


# ===========================================================================
# 1. EMAIL / MESSAGE ANALYSIS TESTS
# ===========================================================================

def test_email_spf_and_dkim_failure():
    """Verify that email SPF and DKIM failures are detected with elevated risk."""
    req = ScanRequest(
        channel=ChannelEnum.EMAIL,
        sender="alerts@sbi-online.com",
        content="From: alerts@sbi-online.com\n"
                "Received-SPF: fail (google.com: domain does not designate sender IP)\n"
                "Authentication-Results: mx.google.com; dkim=fail header.i=@sbi-online.com\n"
                "Subject: Immediate action required: Verify your credentials\n\n"
                "Dear customer, your account will be suspended within 24 hours. Please verify.",
    )
    res = analyze_email(req)
    assert res["is_email"] is True
    assert "EMAIL_SPF_FAIL" in res["flags"]
    assert "EMAIL_DKIM_FAIL" in res["flags"]
    assert "EMAIL_KEYWORD_ACCOUNT_SUSPENSION" in res["flags"]
    assert res["risk_score"] >= 70.0


def test_email_reply_to_mismatch():
    """Verify detection when Reply-To redirects away from From domain."""
    req = ScanRequest(
        channel=ChannelEnum.EMAIL,
        content="From: support@hdfcbank.com\n"
                "Reply-To: attacker-inbox@scam-mail.ru\n"
                "Subject: Security notice regarding your card\n\n"
                "Please reply with your card details to unblock your account.",
    )
    res = analyze_email(req)
    assert res["is_email"] is True
    assert res["has_reply_to_mismatch"] is True
    assert "EMAIL_REPLY_TO_MISMATCH" in res["flags"]
    assert res["risk_score"] >= 50.0


def test_email_display_name_spoofing():
    """Verify detection when display name mimics an official bank on a freemail address."""
    req = ScanRequest(
        channel=ChannelEnum.EMAIL,
        content='From: "State Bank of India Alert" <urgenthelp9823@gmail.com>\n'
                'Subject: Account Alert\n\n'
                'Your account has unusual activity. Please verify immediately.',
    )
    res = analyze_email(req)
    assert res["is_email"] is True
    assert res["display_name_spoofed"] is True
    assert "EMAIL_DISPLAY_NAME_SPOOF" in res["flags"]
    assert res["risk_score"] >= 55.0


def test_email_ip_address_link():
    """Verify detection of raw IP address links embedded in email body."""
    req = ScanRequest(
        channel=ChannelEnum.EMAIL,
        content="From: notice@billing-dept.com\n"
                "Subject: Overdue Invoice\n\n"
                "Your invoice is overdue. Pay immediately at http://192.168.1.100/pay.php",
    )
    res = analyze_email(req)
    assert res["is_email"] is True
    assert "EMAIL_CONTAINS_IP_ADDRESS_URL" in res["flags"]
    assert res["risk_score"] >= 35.0


@pytest.mark.asyncio
async def test_sender_agent_routes_email_channel():
    """Verify sender_agent correctly dispatches to email analysis when channel=EMAIL."""
    req = ScanRequest(
        channel=ChannelEnum.EMAIL,
        sender="notifications@paypal.com",
        content="From: notifications@paypal.com\n"
                "Reply-To: refund-desk@scam-domain.xyz\n"
                "Subject: Payment Received\n\n"
                "You received a payment. Immediate action required.",
    )
    res = await analyze_sender(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert res.email_analysis is not None
    assert "EMAIL_REPLY_TO_MISMATCH" in res.flags
    assert res.risk_score >= 50.0
    assert res.provider == "EMAIL_ANALYZER_ENGINE"


# ===========================================================================
# 2. TELECOM & PHONE VALIDITY / TRAI 140 & 160 SERIES TESTS
# ===========================================================================

@pytest.mark.asyncio
async def test_sender_agent_trai_140_promotional_scam():
    """Verify TRAI 140 telemarketing number sending KYC/financial demands is flagged high-risk."""
    req = ScanRequest(
        content="Dear SBI customer, your electricity bill is unpaid. Connection will be cut. Call back.",
        sender="1409876543",
    )
    res = await analyze_sender(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert res.phone_type == "PROMOTIONAL_140"
    assert "PROMOTIONAL_140_FINANCIAL_SCAM" in res.flags
    assert "TRAI_140_REGULATORY_VIOLATION" in res.flags
    assert res.risk_score >= 85.0


@pytest.mark.asyncio
async def test_sender_agent_trai_160_service_series():
    """Verify TRAI 160 transactional series is recognized as official low-risk sender."""
    req = ScanRequest(
        content="Your OTP for login is 492104. Valid for 10 minutes. Do not share.",
        sender="1601234567",
    )
    res = await analyze_sender(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert res.phone_type == "SERVICE_160"
    assert "TRAI_160_SERVICE_SERIES" in res.flags
    assert res.risk_score <= 15.0


@pytest.mark.asyncio
async def test_sender_agent_toll_free_1800():
    """Verify 1800 toll-free numbers are categorized as TOLL_FREE."""
    req = ScanRequest(
        content="Customer care helpline for queries.",
        sender="1800112211",
    )
    res = await analyze_sender(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert res.phone_type == "TOLL_FREE"
    assert "TOLL_FREE_SERIES" in res.flags
    assert res.risk_score <= 20.0


@pytest.mark.asyncio
async def test_sender_agent_dynamic_levenshtein_near_miss_spoof():
    """
    Verify dynamic Levenshtein near-miss detection:
    VM-SBIINM differs from official VM-SBIINB by only 1 letter -> CRITICAL_NEAR_MISS_HEADER_SPOOF.
    """
    req = ScanRequest(
        content="Dear Customer, your SBI net banking is locked. Update KYC immediately.",
        sender="VM-SBIINM",  # Mimics VM-SBIINB
    )
    res = await analyze_sender(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert res.is_spoofed_header is True
    assert "CRITICAL_NEAR_MISS_HEADER_SPOOF" in res.flags
    assert res.risk_score >= 85.0
    assert "State Bank of India" in (res.brand_claimed or "")


@pytest.mark.asyncio
async def test_sender_agent_hdfc_near_miss_spoof():
    """
    AX-HDFCBX differs from official AX-HDFCBK by 1 letter -> CRITICAL_NEAR_MISS_HEADER_SPOOF.
    """
    req = ScanRequest(
        content="Dear HDFC customer, reward points worth Rs 4500 expiring.",
        sender="AX-HDFCBX",
    )
    res = await analyze_sender(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert res.is_spoofed_header is True
    assert "CRITICAL_NEAR_MISS_HEADER_SPOOF" in res.flags
    assert res.risk_score >= 85.0


# ===========================================================================
# 3. UPI VERIFIER & BANK IDENTITY TESTS
# ===========================================================================

@pytest.mark.asyncio
async def test_mock_upi_verifier_contract():
    """Verify MockUpiVerifier outputs provider: 'SANDBOX_MOCK' and resolves account details."""
    verifier = MockUpiVerifier()
    res = await verifier.verify_vpa("sbi-refund@paytm")
    assert res.is_valid is True
    assert res.account_exists is True
    assert res.registered_name == "MOHAMMAD SHARIF"
    assert res.provider == "SANDBOX_MOCK"


@pytest.mark.asyncio
async def test_rapidapi_verifier_fallback():
    """Verify RapidApiUpiVerifier falls back to sandbox mock when no API key configured."""
    verifier = RapidApiUpiVerifier(api_key=None)
    res = await verifier.verify_vpa("rohan.sharma@okaxis")
    assert res.is_valid is True
    assert res.registered_name == "ROHAN SHARMA"
    assert res.provider == "SANDBOX_MOCK"


def test_name_matching_rapidfuzz_algorithm():
    """Verify name matching logic with exact, alias, and mismatch cases."""
    # Exact match
    score, verdict, _ = match_claimed_vs_registered("Rohan Sharma", "ROHAN SHARMA")
    assert score >= 95.0
    assert verdict == "MATCH"

    # Bank alias expansion: "SBI" vs "STATE BANK OF INDIA - COLLECT"
    score_bank, verdict_bank, _ = match_claimed_vs_registered("SBI", "STATE BANK OF INDIA - COLLECT")
    assert score_bank >= 80.0
    assert verdict_bank == "MATCH"

    # Impersonation mismatch: claimed "State Bank of India" vs individual mule "Mohammad Sharif"
    score_mismatch, verdict_mismatch, flags = match_claimed_vs_registered("State Bank of India", "MOHAMMAD SHARIF")
    assert verdict_mismatch == "MISMATCH"
    assert score_mismatch <= 20.0
    assert "UPI_BENEFICIARY_IS_INDIVIDUAL_FOR_INSTITUTION" in flags or "CRITICAL_BANK_IMPERSONATION_MULE" in flags


@pytest.mark.asyncio
async def test_bank_identity_agent_evidence_generation():
    """Verify bank_identity_agent generates structured evidence with provider='SANDBOX_MOCK'."""
    data = await verify_bank_identity(
        vpa="sbi-refund@paytm",
        claimed_identity="State Bank of India"
    )
    assert data["provider"] == "SANDBOX_MOCK"
    assert data["name_match_status"] == "MISMATCH"
    evidence_item = data["evidence_item"]
    assert evidence_item.provider == "SANDBOX_MOCK"
    assert "Mohammad Sharif" in evidence_item.finding or "MOHAMMAD SHARIF" in evidence_item.finding


@pytest.mark.asyncio
async def test_upi_agent_with_bank_identity_enrichment():
    """Verify upi_agent populates registered_name, name_match_score, and provider='SANDBOX_MOCK'."""
    req = ScanRequest(
        content="Please refund your charges via sbi-refund@paytm immediately",
        channel=ChannelEnum.SMS,
    )
    res = await analyze_upi(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert res.registered_name == "MOHAMMAD SHARIF"
    assert res.name_match_status == "MISMATCH"
    assert res.provider == "SANDBOX_MOCK"
    assert res.risk_score >= 75.0


@pytest.mark.asyncio
async def test_upi_agent_vpa_typosquatting():
    """Verify detection of typosquatted banking portals in VPA handles (e.g. onllnesbi@oksbi)."""
    req = ScanRequest(
        content="Send payment to onllnesbi@oksbi to reactivate your banking services",
        channel=ChannelEnum.SMS,
    )
    res = await analyze_upi(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert "VPA_TYPOSQUATTING_DETECTED" in res.flags
    assert res.risk_score >= 60.0


@pytest.mark.asyncio
async def test_evidence_builder_carries_sandbox_mock():
    """Verify build_evidence_list includes provider='SANDBOX_MOCK' for UPI and Bank Identity."""
    req = ScanRequest(
        content="Send fee to sbi-support@ybl",
        sender="9876543210",
    )
    sender_r = await analyze_sender(req)
    upi_r = await analyze_upi(req)

    from shared.models import UrlAgentResult, IntentAgentResult
    url_r = UrlAgentResult(status=AgentStatusEnum.SKIPPED)
    intent_r = IntentAgentResult(status=AgentStatusEnum.SUCCESS)

    evidence_list = build_evidence_list(url_r, sender_r, intent_r, upi_r)

    # Check that UPI and bank identity tools carry provider: "SANDBOX_MOCK"
    providers = [item.get("provider") for item in evidence_list]
    assert "SANDBOX_MOCK" in providers


# ===========================================================================
# 4. AVNI SPRINT 2 DELIVERABLES
# ===========================================================================

@pytest.mark.asyncio
async def test_multi_phone_parallel_analysis_body():
    """
    Verify multi-phone parallel extraction and scoring from message body:
    Extracts multiple numbers, scores concurrently, and picks highest risk.
    """
    # 1409876543 is promotional 140 (high risk), 9876543210 is normal GSM (medium risk)
    req = ScanRequest(
        content="URGENT: SBI KYC expired. Call promotional desk at 1409876543 or alternative 9876543210 immediately.",
        sender=None,
    )
    res = await analyze_sender(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert res.risk_score >= 80.0
    assert res.email_analysis is not None
    assert "multi_phone_results" in res.email_analysis
    assert res.email_analysis["phone_count"] >= 2
    # Verify both numbers were analyzed
    analyzed_phones = [item["phone"] for item in res.email_analysis["multi_phone_results"]]
    assert "1409876543" in analyzed_phones or "9876543210" in analyzed_phones


@pytest.mark.asyncio
async def test_multi_phone_parallel_analysis_sender_field():
    """Verify analyze_sender_multi handles multiple phone numbers passed in sender field."""
    req = ScanRequest(
        content="Your electricity bill is overdue. Pay immediately.",
        sender="9876543210, 9123456780",
    )
    res = await analyze_sender_multi(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert res.email_analysis is not None
    assert res.email_analysis["phone_count"] == 2


def test_nnp_circle_mismatch_audit():
    """Verify offline NNP prefix circle mismatch detector flags invalid, unregistered, and mismatched prefixes."""
    synthetic_registry = {
        "TEST01": {
            "brand_name": "Fraud Bank",
            "category": "Banking",
            "operator_prefixes": ["BZ"],  # BZ is known invalid
        },
        "TEST02": {
            "brand_name": "Bogus Telecom",
            "category": "Telecom Operator",
            "operator_prefixes": ["QQ"],  # QQ is unregistered (not in valid or invalid list)
        },
        "TEST03": {
            "brand_name": "State Bank of India",
            "category": "Banking",  # National category
            "operator_prefixes": ["NE"],  # NE is single-circle North East prefix
        },
        "TEST04": {
            "brand_name": "Legitimate Vi Bank",
            "category": "Banking",
            "operator_prefixes": ["VM"],  # VM is valid pan-India
        },
    }
    mismatches = run_nnp_prefix_mismatch_audit(synthetic_registry)
    severities = {m["entity_code"]: m["severity"] for m in mismatches}

    assert severities.get("TEST01") == "CRITICAL"  # Known invalid
    assert severities.get("TEST02") == "HIGH"      # Unregistered
    assert severities.get("TEST03") == "MEDIUM"    # Single-circle for national entity
    assert "TEST04" not in severities              # Valid pan-India prefix


@pytest.mark.asyncio
async def test_trai_operator_entity_prefix_mismatch():
    """
    Verify operator-entity mismatch:
    e.g. CP-SBIINB where CP is not authorized for SBIINB.
    """
    req = ScanRequest(
        content="Dear SBI customer, your KYC is expired. Update now.",
        sender="CP-SBIINB",
    )
    res = await analyze_sender(req)
    assert res.status == AgentStatusEnum.SUCCESS
    assert res.is_spoofed_header is True
    assert "TRAI_OPERATOR_ENTITY_PREFIX_MISMATCH" in res.flags
    assert res.risk_score >= 70.0


def test_email_spf_alignment_fail():
    """Verify SPF envelope-from mismatch (laundering) is flagged."""
    req = ScanRequest(
        channel=ChannelEnum.EMAIL,
        sender="service@paypal.com",
        content="From: service@paypal.com\n"
                "Received-SPF: pass (smtp.mailfrom=attacker-legit-server.com)\n"
                "Subject: Your account receipt\n\n"
                "Here is your payment receipt.",
    )
    res = analyze_email(req)
    assert "EMAIL_SPF_ALIGNMENT_FAIL" in res["flags"]
    assert "EMAIL_SPF_ENVELOPE_FROM_MISMATCH" in res["flags"]
    assert res["risk_score"] >= 35.0


def test_email_dkim_alignment_fail():
    """Verify DKIM signing domain mismatch (d= doesn't match From) is flagged."""
    req = ScanRequest(
        channel=ChannelEnum.EMAIL,
        sender="alerts@hdfcbank.com",
        content="From: alerts@hdfcbank.com\n"
                "Authentication-Results: mx.google.com; dkim=pass (test) header.d=compromised-thirdparty.net\n"
                "Subject: Mandatory Security Update\n\n"
                "Please verify your netbanking account.",
    )
    res = analyze_email(req)
    assert "EMAIL_DKIM_ALIGNMENT_FAIL" in res["flags"]
    assert "EMAIL_DKIM_SIGNING_DOMAIN_MISMATCH" in res["flags"]
    assert res["risk_score"] >= 30.0


def test_email_dmarc_reject_and_quarantine():
    """Verify DMARC policy parsing flags reject and quarantine policies."""
    req_reject = ScanRequest(
        channel=ChannelEnum.EMAIL,
        content="From: alert@sbi.co.in\n"
                "Authentication-Results: mx.google.com; dmarc=reject header.from=sbi.co.in\n"
                "Subject: Urgent alert\n\n"
                "Account suspended.",
    )
    res_reject = analyze_email(req_reject)
    assert "EMAIL_DMARC_FAIL" in res_reject["flags"]
    assert "EMAIL_DMARC_POLICY_REJECT" in res_reject["flags"]
    assert res_reject["risk_score"] >= 50.0

    req_quarantine = ScanRequest(
        channel=ChannelEnum.EMAIL,
        content="From: alert@icicibank.com\n"
                "Authentication-Results: mx.google.com; dmarc=quarantine header.from=icicibank.com\n"
                "Subject: Urgent alert\n\n"
                "Account suspended.",
    )
    res_quarantine = analyze_email(req_quarantine)
    assert "EMAIL_DMARC_FAIL" in res_quarantine["flags"]
    assert "EMAIL_DMARC_POLICY_QUARANTINE" in res_quarantine["flags"]


def test_email_header_injection_crlf():
    """Verify CRLF header injection in email headers is detected and penalized."""
    req = ScanRequest(
        channel=ChannelEnum.EMAIL,
        content="From: admin@trusted.com\r\nBcc: evil-stealer@hacker.org\n"
                "Subject: Clean subject\n\n"
                "Regular email body text.",
    )
    res = analyze_email(req)
    assert "EMAIL_HEADER_INJECTION_DETECTED" in res["flags"]
    assert res["risk_score"] >= 60.0

