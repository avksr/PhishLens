"""
backend/tests/test_nextgen_agents.py
------------------------------------
Tests for Next-Gen PhishLens Multimodal & Financial OSINT Pipeline:
1. Bank Identity Verification (Name mismatch)
2. Parallel OSINT (Path A Crowdsource & Path B Forum search)
3. AI Text Detection (Synthetic templates & burstiness)
4. Vision AI (ELA tampering & OCR extraction)
5. Document Fraud (MRZ validation & metadata)
6. Threat Multiplier & Dynamic Badges
"""

import io
import pytest
from PIL import Image

from agents.ai_text_agent import analyze_ai_text
from agents.bank_identity_agent import verify_bank_identity
from agents.document_agent import analyze_document_fraud, validate_mrz_checksum
from agents.osint_agent import analyze_osint
from agents.vision_agent import analyze_image_screenshot, perform_ela
from core.orchestrator import run_multimodal_pipeline, run_pipeline
from shared.models import (
    AgentStatusEnum,
    ChannelEnum,
    ModalityEnum,
    RiskTierEnum,
    ScanRequest,
)


@pytest.mark.asyncio
async def test_bank_identity_name_mismatch():
    """Verify that institutional claim with individual registered name flags mismatch."""
    req = ScanRequest(
        content="Kindly transfer payment to refund-support@okaxis to confirm your OLX delivery.",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
    )
    result = await verify_bank_identity(req)
    assert result.status == AgentStatusEnum.SUCCESS
    assert result.vpa == "refund-support@okaxis"
    assert result.is_name_mismatch is True
    assert "NAME_MISMATCH_DETECTED" in result.flags
    assert result.registered_bank_name == "Mohd Imran"


@pytest.mark.asyncio
async def test_bank_identity_clean_handle():
    """Verify that standard personal handle without mismatch flags clean."""
    req = ScanRequest(
        content="Here is my lunch split: avksr@okaxis",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
    )
    result = await verify_bank_identity(req)
    assert result.status == AgentStatusEnum.SUCCESS
    assert result.vpa == "avksr@okaxis"
    assert result.is_name_mismatch is False


@pytest.mark.asyncio
async def test_osint_crowdsourced_hit():
    """Verify Path A finds pre-seeded OLX scam complaints."""
    req = ScanRequest(
        content="Send deposit to refund-support@okaxis",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
    )
    result = await analyze_osint(req)
    assert result.status == AgentStatusEnum.SUCCESS
    assert result.total_complaints >= 5
    assert result.risk_level == "KNOWN_SCAMMER"
    assert "OLX" in (result.proof_snippet or "")
    assert "CROWDSOURCED_SCAM_FLAGGED" in result.flags


@pytest.mark.asyncio
async def test_ai_text_detector_phishing_template():
    """Verify AI text detector flags rigid synthetic templates."""
    req = ScanRequest(
        content=(
            "We regret to inform you that your account has been suspended. "
            "Important security notification regarding your account. "
            "Please follow the secure link below to verify your details immediately."
        ),
        channel=ChannelEnum.EMAIL,
    )
    result = await analyze_ai_text(req)
    assert result.status == AgentStatusEnum.SUCCESS
    assert result.is_ai_generated is True
    assert result.ai_probability >= 0.70
    assert "SYNTHETIC_AI_TEXT_DETECTED" in result.flags


@pytest.mark.asyncio
async def test_vision_ela_analysis():
    """Verify Error Level Analysis runs cleanly on generated image bytes."""
    img = Image.new("RGB", (200, 200), color=(73, 109, 137))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    image_bytes = buf.getvalue()

    result = await analyze_image_screenshot(image_bytes)
    assert result.status == AgentStatusEnum.SUCCESS
    assert result.ela_anomaly_score >= 0.0


def test_mrz_checksum_algorithm():
    """Verify ICAO 9303 modulo-10 algorithm correctly validates and invalidates check digits."""
    # Data: 'L898902C3', check digit: '6' (ICAO sample)
    data = "L898902C3"
    assert validate_mrz_checksum(data, "6") is True
    # Tampered check digit
    assert validate_mrz_checksum(data, "9") is False


@pytest.mark.asyncio
async def test_document_fraud_clean():
    """Verify clean document returns low risk score."""
    # Simple empty PDF
    import pypdf

    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=100, height=100)
    buf = io.BytesIO()
    writer.write(buf)
    pdf_bytes = buf.getvalue()

    result = await analyze_document_fraud(pdf_bytes)
    assert result.status == AgentStatusEnum.SUCCESS
    assert result.is_forged is False


@pytest.mark.asyncio
async def test_full_pipeline_with_badges_and_proof():
    """Verify end-to-end scan pipeline generates badges and escalates to CRITICAL on OLX fake UPI."""
    req = ScanRequest(
        content="Warning: Send ₹500 immediately to refund-support@okaxis to confirm your OLX furniture order.",
        sender="+919876543210",
        channel=ChannelEnum.SMS,
    )
    response = await run_pipeline(req)
    assert response.overall_risk_score >= 78
    assert response.risk_tier == RiskTierEnum.CRITICAL
    assert "💳 Fake UPI Detected" in response.active_badges
    assert response.proof_attached is not None
    assert "OLX" in response.proof_attached


@pytest.mark.asyncio
async def test_multimodal_pipeline_image():
    """Verify run_multimodal_pipeline processes image inputs."""
    img = Image.new("RGB", (150, 150), color=(200, 100, 50))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    image_bytes = buf.getvalue()

    response = await run_multimodal_pipeline(
        file_bytes=image_bytes,
        filename="screenshot.png",
        mime_type="image/png",
        optional_text="Suspicious payment screenshot for refund-support@okaxis",
        sender="+919876543210",
    )
    assert response.modality == ModalityEnum.IMAGE
    assert response.vision_analysis is not None
    assert response.overall_risk_score >= 50
