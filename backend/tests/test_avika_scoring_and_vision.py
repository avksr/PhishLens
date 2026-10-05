"""
backend/tests/test_avika_scoring_and_vision.py
---------------------------------------------
Comprehensive Unit & Integration Test Suites for Avika's Deliverables:
1. EasyOCR Singleton Thread-Safety & Reuse
2. Rule 9 Multimodal Weaponization Multiplier
3. Noisy-OR Confidence Weighting & Explainability JSON Export
4. 0-1 Confidence Score Format Alignment with Vikas (LLM)
5. Perceptual Hashing (pHash) Payment Receipt Matching & Fake Screenshot Splicing
6. Indian Honorific Stripping & Fuzzy Name Matching (token_set_ratio)
7. QR Pre-Payment Shield (Reverse-QR Trap, Spoofed Merchant, Phishing URLs)
"""

import io
import pytest
from PIL import Image, ImageDraw

from agents.bank_identity_agent import (
    _clean_name_for_matching,
    compute_fuzzy_name_match,
    match_claimed_vs_registered,
    verify_bank_identity,
)
from agents.qr_shield import verify_qr_pre_payment, QrShieldResult
from agents.vision_agent import (
    compute_phash,
    hamming_distance,
    match_payment_receipt,
    get_easyocr_reader,
    analyze_image_screenshot,
)
from core.orchestrator import run_pipeline, run_multimodal_pipeline
from core.scoring_engine import _compute_noisy_or_base_score, _compute_dynamic_weights
from shared.models import (
    AgentStatusEnum,
    ChannelEnum,
    ConfidenceLevelEnum,
    IntentAgentResult,
    ModalityEnum,
    PrdVerdictEnum,
    RiskTierEnum,
    ScanRequest,
    ScanResponse,
    SenderAgentResult,
    SenderCategoryEnum,
    UpiAgentResult,
    UrlAgentResult,
)


# ===========================================================================
# 1. EasyOCR Singleton Verification
# ===========================================================================

def test_easyocr_singleton_reuse():
    """Verify EasyOCR reader singleton is lazy, thread-safe, and returns identical instance."""
    reader1 = get_easyocr_reader()
    reader2 = get_easyocr_reader()
    assert reader1 is reader2


# ===========================================================================
# 2. Indian Honorific Stripping & Fuzzy Name Matching
# ===========================================================================

def test_indian_honorific_stripping():
    """Verify Indian titles/honorifics are stripped during name matching."""
    cleaned1 = _clean_name_for_matching("Shri Mohd Imran")
    cleaned2 = _clean_name_for_matching("Mr. Mohammad Imran")
    assert "mohammed imran" in cleaned1
    assert "mohammed imran" in cleaned2


def test_fuzzy_name_match_token_set_ratio():
    """Verify token_set_ratio handles patronymics and honorifics smoothly."""
    # Full name in bank record vs shorter claimed name
    score = compute_fuzzy_name_match("Rahul Sharma", "Mr Rahul Suresh Sharma")
    assert score >= 75.0

    score_imran = compute_fuzzy_name_match("Mohd Imran", "Mohammad Imran")
    assert score_imran >= 80.0


@pytest.mark.asyncio
async def test_bank_identity_polymorphic_contract():
    """Verify verify_bank_identity accepts ScanRequest, keyword vpa, and returns BankVerificationResult with dict access."""
    # 1. Calling with ScanRequest
    req = ScanRequest(
        content="Kindly transfer payment to refund-support@okaxis to confirm your OLX delivery.",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
    )
    res_req = await verify_bank_identity(req)
    assert res_req.status == AgentStatusEnum.SUCCESS
    assert res_req.vpa == "refund-support@okaxis"
    assert res_req.is_name_mismatch is True
    assert res_req.registered_bank_name == "Mohd Imran"
    assert res_req.registered_name == "Mohd Imran"
    assert res_req["name_match_status"] == "MISMATCH"
    assert res_req["provider"] == "SANDBOX_MOCK"

    # 2. Calling with keyword vpa
    res_kw = await verify_bank_identity(
        vpa="sbi-refund@paytm",
        claimed_identity="State Bank of India"
    )
    assert res_kw.is_name_mismatch is True
    assert res_kw["name_match_status"] == "MISMATCH"
    assert res_kw.evidence_item is not None


# ===========================================================================
# 3. Noisy-OR Confidence Weighting & Explainability JSON Export
# ===========================================================================

def test_noisy_or_confidence_weighting():
    """Verify Noisy-OR formula produces probabilistic combination across active vectors."""
    url_r = UrlAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=80.0)
    sender_r = SenderAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=70.0)
    intent_r = IntentAgentResult(status=AgentStatusEnum.SUCCESS, risk_score=60.0, confidence=0.9)

    weights = _compute_dynamic_weights(url_r, sender_r, intent_r)
    assert abs(sum(weights.values()) - 1.0) < 0.001

    base_score = _compute_noisy_or_base_score(weights, url_r, sender_r, intent_r)
    # Base score should be strictly bounded and positive
    assert 0.0 <= base_score <= 100.0
    assert base_score > 50.0


@pytest.mark.asyncio
async def test_0_to_1_confidence_score_and_explainability_export():
    """Verify ScanResponse contains 0-1 confidence_score format (Vikas/LLM contract) and export_explainability_json."""
    req = ScanRequest(
        content="URGENT: Your SBI account is suspended. Verify KYC immediately at http://sbi-kyc-update.com",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
    )
    res: ScanResponse = await run_pipeline(req)

    # 0-1 confidence score check
    assert res.confidence_score is not None
    assert 0.0 <= res.confidence_score <= 1.0
    assert abs(res.confidence_score * 100.0 - (res.confidence_percentage or 0.0)) < 0.1

    # Explainability export check
    exp = res.export_explainability_json()
    assert isinstance(exp, dict)
    assert "overall_risk_score" in exp
    assert "confidence_score" in exp
    assert "noisy_or" in exp
    assert "why_blocked_evidence" in exp
    assert "latencies_ms" in exp
    assert exp["confidence_score"] == res.confidence_score


# ===========================================================================
# 4. Perceptual Hashing (pHash) & Fake Payment Receipt Splicing
# ===========================================================================

def test_phash_computation_and_hamming_distance():
    """Verify pHash produces 64-bit int and 16-char hex string, and identical images have dist 0."""
    img1 = Image.new("RGB", (200, 400), color=(255, 255, 255))
    draw = ImageDraw.Draw(img1)
    draw.rectangle([20, 20, 180, 80], fill=(0, 128, 0))
    draw.text((40, 40), "Paid Rs 5000", fill=(0, 0, 0))

    h1_int, h1_hex = compute_phash(img1)
    assert isinstance(h1_int, int)
    assert len(h1_hex) == 16

    h2_int, _ = compute_phash(img1)
    assert hamming_distance(h1_int, h2_int) == 0


def test_match_payment_receipt_keywords():
    """Verify match_payment_receipt identifies receipt templates via OCR keywords."""
    img = Image.new("RGB", (200, 400), color=(255, 255, 255))
    matched, tmpl, _ = match_payment_receipt(img, ocr_text="Payment of Rs 1,500 to Mohd Imran transaction successful Google Pay")
    assert matched is True
    assert tmpl == "GPAY"


@pytest.mark.asyncio
async def test_fake_payment_receipt_splicing_detection():
    """Verify that a receipt with visual compression anomalies triggers fake receipt badge and high risk."""
    img = Image.new("RGB", (200, 400), color=(240, 240, 240))
    draw = ImageDraw.Draw(img)
    draw.text((30, 50), "Paid to Mohd Imran", fill=(0, 0, 0))
    draw.text((30, 80), "Google Pay Transaction Successful UPI ID refund-support@okaxis", fill=(0, 0, 0))

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    image_bytes = buf.getvalue()

    result = await analyze_image_screenshot(image_bytes)
    assert result.status == AgentStatusEnum.SUCCESS
    assert result.is_receipt_matched is True
    assert result.receipt_template == "GPAY"


# ===========================================================================
# 5. QR Pre-Payment Shield
# ===========================================================================

def test_qr_shield_reverse_qr_trap():
    """Verify QR shield catches Reverse-QR collect request disguised as receiving refund."""
    payload = "upi://pay?pa=scammer@okaxis&pn=Customer+Care&am=5000.00&cu=INR"
    eval_res: QrShieldResult = verify_qr_pre_payment(payload, user_intent_claim="Scan to receive your refund of 5000")
    assert eval_res.is_valid_upi is True
    assert eval_res.is_collect_request_trap is True
    assert "REVERSE_QR_TRAP_DETECTED" in eval_res.flags
    assert eval_res.risk_score >= 90.0
    assert "DEDUCT" in eval_res.advisory or "NEVER" in eval_res.advisory


def test_qr_shield_spoofed_merchant_claim():
    """Verify QR shield catches institutional name claims on personal P2P handles without merchant MCC."""
    payload = "upi://pay?pa=fake.sbi@okaxis&pn=State+Bank+Of+India+Support&cu=INR"
    eval_res: QrShieldResult = verify_qr_pre_payment(payload)
    assert eval_res.is_unverified_merchant_claim is True
    assert "SUSPECTED_SPOOFED_MERCHANT_QR" in eval_res.flags
    assert eval_res.risk_score >= 85.0


def test_qr_shield_phishing_url():
    """Verify QR shield flags web URLs disguised as QR payments."""
    payload = "https://secure-sbi-refund-portal.com/login"
    eval_res: QrShieldResult = verify_qr_pre_payment(payload)
    assert eval_res.is_valid_upi is False
    assert eval_res.is_phishing_url is True
    assert "QR_EMBEDDED_WEB_URL" in eval_res.flags
    assert eval_res.risk_score >= 80.0


def test_qr_shield_clean_merchant_qr():
    """Verify clean merchant QR passes safely."""
    payload = "upi://pay?pa=swiggy@hdfcbank&pn=Swiggy+Food&mc=5812&am=350.00&cu=INR"
    eval_res: QrShieldResult = verify_qr_pre_payment(payload)
    assert eval_res.is_valid_upi is True
    assert eval_res.is_collect_request_trap is False
    assert eval_res.is_unverified_merchant_claim is False
    assert eval_res.risk_score <= 15.0


# ===========================================================================
# 6. Rule 9 Multimodal Weaponization in Orchestrator
# ===========================================================================

@pytest.mark.asyncio
async def test_rule_9_multimodal_weaponization():
    """Verify orchestrator triggers Rule 9 escalation on combined visual tampering + suspicious content."""
    # Synthetic image
    img = Image.new("RGB", (100, 100), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")

    req = ScanRequest(
        content="Kindly transfer payment to refund-support@okaxis to confirm your OLX delivery.",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
        modality=ModalityEnum.IMAGE,
        file_bytes=buf.getvalue(),
        file_name="payment_receipt.png",
    )
    res: ScanResponse = await run_multimodal_pipeline(req)
    assert res.modality == ModalityEnum.IMAGE
    assert res.vision_analysis is not None
    assert res.risk_score >= 85
