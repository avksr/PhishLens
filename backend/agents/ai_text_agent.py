"""
backend/agents/ai_text_agent.py
--------------------------------
AI Text & Synthetic Phishing Copy Detection Agent for PhishLens.

Responsibilities:
1. Detect synthetic, LLM-generated phishing copy (RoBERTa / ZeroTrue / Heuristics).
2. Analyze sentence structure predictability, uniform perplexity, and AI templates.
3. Output probability score (0.0 to 1.0) and risk flags.

Author  : VIKAS — NLP & Psycholinguistic AI
Module  : PhishLens v2.0
"""

from __future__ import annotations

import logging
import math
import os
import re
import time
from typing import List, Tuple

import httpx
from shared.models import (
    AgentStatusEnum,
    AiTextAgentResult,
    ScanRequest,
)

logger = logging.getLogger("phishlens.ai_text")

# Typical AI-generated phishing sentence openings & transitions
_AI_PHISHING_TEMPLATES = [
    re.compile(r"\bwe regret to inform you that\b", re.I),
    re.compile(r"\bimportant security notification regarding your\b", re.I),
    re.compile(r"\bto prevent permanent deactivation(?: of)?\b", re.I),
    re.compile(r"\bfailure to comply will result in immediate\b", re.I),
    re.compile(r"\bplease follow the secure link below to verify\b", re.I),
    re.compile(r"\bkindly update your kyc details to avoid\b", re.I),
    re.compile(r"\byour immediate attention is required to resolve\b", re.I),
    re.compile(r"\bas per reserve bank of india guidelines\b", re.I),
]


def _calculate_perplexity_and_burstiness(text: str) -> Tuple[float, float, float]:
    """
    Offline statistical linguistic analyzer:
    1. Unigram frequency entropy (perplexity proxy)
    2. Sentence length variance (burstiness)
    Human writing has high burstiness; AI text has uniform sentence lengths.
    """
    words = re.findall(r"\b[a-zA-Z]{2,}\b", text.lower())
    if len(words) < 5:
        return 0.0, 0.0, 0.0

    # 1. Frequency distribution entropy
    counts = {}
    for w in words:
        counts[w] = counts.get(w, 0) + 1
    total = len(words)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())

    # 2. Sentence lengths
    sentences = re.split(r"[.!?]+", text)
    lengths = [len(s.split()) for s in sentences if len(s.split()) > 0]
    if len(lengths) > 1:
        mean_len = sum(lengths) / len(lengths)
        variance = sum((l - mean_len) ** 2 for l in lengths) / len(lengths)
        std_dev = math.sqrt(variance)
        burstiness = (std_dev - mean_len) / (std_dev + mean_len + 1e-5)
    else:
        burstiness = -0.5  # Low variance = uniform

    # Probability estimation: Low entropy + Low burstiness = High AI probability
    ai_prob = 0.40
    if entropy < 3.8:
        ai_prob += 0.25
    if burstiness < -0.2:
        ai_prob += 0.20

    return entropy, burstiness, min(1.0, max(0.0, ai_prob))


async def analyze_ai_text(req: ScanRequest) -> AiTextAgentResult:
    """
    Analyzes content for synthetic AI generation signatures.
    Uses Hugging Face Inference API if token is present, else fast offline heuristics.
    """
    t_start = time.perf_counter()
    content = req.content.strip()

    if len(content.split()) < 4:
        latency_ms = round((time.perf_counter() - t_start) * 1000, 2)
        return AiTextAgentResult(
            status=AgentStatusEnum.SKIPPED,
            risk_score=0.0,
            is_ai_generated=False,
            ai_probability=0.0,
            details="Text too short for reliable AI text detection.",
            latency_ms=latency_ms,
        )

    flags: List[str] = []
    hf_token = os.getenv("HF_TOKEN")
    ai_probability = 0.0

    # Attempt Hugging Face Inference API if configured
    if hf_token:
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.post(
                    "https://api-inference.huggingface.co/models/roberta-base-openai-detector",
                    headers={"Authorization": f"Bearer {hf_token}"},
                    json={"inputs": content},
                )
                if res.status_code == 200:
                    data = res.json()
                    # data is typically [[{'label': 'Fake', 'score': 0.85}, ...]]
                    if isinstance(data, list) and len(data) > 0:
                        inner = data[0] if isinstance(data[0], list) else data
                        for item in inner:
                            if item.get("label") in ["Fake", "LABEL_1"]:
                                ai_probability = float(item.get("score", 0.0))
                                flags.append("HF_ROBERTA_AI_DETECTOR_ACTIVE")
        except Exception as e:
            logger.debug(f"HF Inference error, falling back to heuristics: {e}")

    # Fallback / Supplement with statistical heuristics
    entropy, burstiness, heuristic_prob = _calculate_perplexity_and_burstiness(content)
    if ai_probability == 0.0:
        ai_probability = heuristic_prob

    # Check for rigid AI phishing templates
    template_hits = 0
    for pat in _AI_PHISHING_TEMPLATES:
        if pat.search(content):
            template_hits += 1

    if template_hits >= 2:
        ai_probability = max(ai_probability, 0.82)
        flags.append("AI_PHISHING_TEMPLATE_STRUCTURE")
    elif template_hits == 1:
        ai_probability = max(ai_probability, 0.65)
        flags.append("FORMAL_COERCIVE_AI_PHRASING")

    is_ai = ai_probability >= 0.70
    if is_ai:
        flags.append("SYNTHETIC_AI_TEXT_DETECTED")
        flags.append("LOW_BURSTINESS_UNIFORM_STRUCTURE")

    risk_score = round(ai_probability * 100.0, 1)
    latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

    details = (
        f"AI Text Analysis: {ai_probability * 100:.1f}% probability of synthetic/bot generation. "
        + ("Highly structured template detected." if is_ai else "Natural human variance detected.")
    )

    return AiTextAgentResult(
        status=AgentStatusEnum.SUCCESS,
        risk_score=risk_score,
        is_ai_generated=is_ai,
        ai_probability=round(ai_probability, 3),
        perplexity_score=round(entropy, 2),
        flags=flags,
        details=details,
        latency_ms=latency_ms,
    )
