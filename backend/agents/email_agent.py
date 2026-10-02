"""
backend/agents/email_agent.py
-----------------------------
Email & Message Security Analysis Agent for PhishLens (ScamShield AI).

Responsibilities:
1. Header Security Verification:
   - SPF Validation: pass, softfail, fail, neutral, none.
   - DKIM Validation: pass, fail, invalid, missing.
   - Reply-To Mismatch: compares From domain vs Reply-To domain to detect return redirection.
   - Display Name Spoofing: institutional display name on consumer/freemail or unrelated domains.
2. Email Body & Pattern Heuristics:
   - Urgent panic/extortion/suspension keywords.
   - Credential harvesting lures and fake invoice/tax patterns.
   - Suspicious links, IP hosts, and mismatched anchor domains.
3. Universal Parsing:
   - Ingests RFC 822 raw email strings or structured dictionaries from metadata.
   - Seamlessly invoked when channel is EMAIL or when email headers are present.

Author  : AVNI — Sender Identity, Email & UPI Intelligence
Module  : PhishLens v1.0
"""

from __future__ import annotations

import email
import email.policy
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from shared.models import AgentStatusEnum, ScanRequest

# ---------------------------------------------------------------------------
# Pre-compiled Patterns
# ---------------------------------------------------------------------------
_EMAIL_ADDR_RE = re.compile(r"[\w.+-]+@([\w-]+\.[\w.-]+)")
_URL_RE = re.compile(r"https?://[^\s<>\"']+")
_IP_HOST_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|\b)")

# Common free webmail domains
_FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "ymail.com", "hotmail.com", "outlook.com",
    "live.com", "icloud.com", "aol.com", "protonmail.com", "zoho.com",
    "gmx.com", "mail.com", "rediffmail.com", "yandex.com", "mail.ru"
}

# Major bank and authority keywords for display-name spoof detection
_KNOWN_INSTITUTION_KEYWORDS = [
    "sbi", "state bank", "hdfc", "icici", "axis bank", "punjab national bank",
    "kotak", "bank of baroda", "canara", "reserve bank of india", "rbi",
    "income tax", "incometax", "uidai", "aadhaar", "epfo", "irctc", "paypal",
    "microsoft security", "apple support", "google alert", "netflix billing"
]

# Phishing and urgency keyword patterns in email
_EMAIL_PHISHING_KEYWORDS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"\b(account.*(?:suspended|locked|blocked|frozen|disabled))\b", re.I),
     "EMAIL_KEYWORD_ACCOUNT_SUSPENSION", 25.0),
    (re.compile(r"\b(verify.*(?:identity|password|credentials|billing|account))\b", re.I),
     "EMAIL_KEYWORD_VERIFY_CREDENTIALS", 20.0),
    (re.compile(r"\b(immediate action required|urgent attention|within 24 hours|within 12 hours)\b", re.I),
     "EMAIL_KEYWORD_URGENCY_PRESSURE", 20.0),
    (re.compile(r"\b(unauthorized login|unusual activity|suspicious login attempt)\b", re.I),
     "EMAIL_KEYWORD_FAKE_SECURITY_ALERT", 20.0),
    (re.compile(r"\b(invoice.*(?:overdue|attached|unpaid|payment pending)|remittance advice)\b", re.I),
     "EMAIL_KEYWORD_INVOICE_BAIT", 15.0),
    (re.compile(r"\b(wire transfer|cryptocurrency|bitcoin payment|send btc)\b", re.I),
     "EMAIL_KEYWORD_EXTORTION_PAYMENT", 30.0),
    (re.compile(r"\b(tax refund available|lottery winning|inheritance notice)\b", re.I),
     "EMAIL_KEYWORD_FINANCIAL_BAIT", 25.0),
]


def _extract_domain(email_str: str) -> Optional[str]:
    """Extract and lowercase the domain part of an email address."""
    match = _EMAIL_ADDR_RE.search(email_str)
    if match:
        return match.group(1).lower().strip()
    return None


def _parse_email_headers_and_body(content: str, metadata: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, str], str]:
    """
    Parse RFC 822 format text or extract structured headers from metadata.
    Returns: (headers_dict_lowercase_keys, body_text)
    """
    headers: Dict[str, str] = {}
    body = content

    # 1. Check if metadata provides structured headers
    if metadata:
        meta_headers = metadata.get("headers") or metadata.get("email_headers")
        if isinstance(meta_headers, dict):
            for k, v in meta_headers.items():
                headers[k.lower()] = str(v)

    # 2. Check if content looks like raw RFC 822 email
    content_has_email_headers = any(
        re.search(rf"^{h}:", content, re.MULTILINE | re.IGNORECASE)
        for h in ["from", "to", "subject", "reply-to", "received", "authentication-results", "received-spf"]
    )

    if content_has_email_headers:
        try:
            msg = email.message_from_string(content, policy=email.policy.default)
            for k, v in msg.items():
                headers[k.lower()] = str(v)
            payload = msg.get_payload()
            if isinstance(payload, str):
                body = payload
            elif isinstance(payload, list):
                # Multipart payload: gather plain text parts
                parts = []
                for p in payload:
                    if hasattr(p, "get_content"):
                        try:
                            parts.append(p.get_content())
                        except Exception:
                            parts.append(str(p))
                    else:
                        parts.append(str(p))
                body = "\n".join(parts)
        except Exception:
            # Fall back to using content as body
            pass

    return headers, body


def analyze_email(req: ScanRequest) -> Dict[str, Any]:
    """
    Core Email / Message security analysis pipeline.
    Inspects SPF, DKIM, Reply-To, Display Name, Links, and Phishing vocabulary.
    Returns structured analysis dictionary suitable for inclusion in SenderAgentResult.
    """
    headers, body = _parse_email_headers_and_body(req.content, req.metadata)

    flags: List[str] = []
    risk_score = 0.0

    # Sender field from request or From header
    from_header = headers.get("from") or req.sender or ""
    reply_to_header = headers.get("reply-to", "")
    auth_results = headers.get("authentication-results", "")
    spf_header = headers.get("received-spf", "")
    dkim_sig = headers.get("dkim-signature", "")

    from_domain = _extract_domain(from_header)
    reply_to_domain = _extract_domain(reply_to_header) if reply_to_header else None

    # ------------------------------------------------------------------
    # 1. Header Checks: SPF
    # ------------------------------------------------------------------
    spf_status = "NONE"
    spf_search_text = (spf_header + " " + auth_results).lower()

    if "spf=fail" in spf_search_text or "fail" in spf_header.lower():
        spf_status = "FAIL"
        flags.append("EMAIL_SPF_FAIL")
        risk_score += 45.0
    elif "spf=softfail" in spf_search_text or "softfail" in spf_header.lower():
        spf_status = "SOFTFAIL"
        flags.append("EMAIL_SPF_SOFTFAIL")
        risk_score += 30.0
    elif "spf=pass" in spf_search_text or "pass" in spf_header.lower():
        spf_status = "PASS"
        flags.append("EMAIL_SPF_PASS")
    elif "spf=neutral" in spf_search_text:
        spf_status = "NEUTRAL"
        flags.append("EMAIL_SPF_NEUTRAL")
        risk_score += 10.0

    # ------------------------------------------------------------------
    # 2. Header Checks: DKIM
    # ------------------------------------------------------------------
    dkim_status = "NONE"
    dkim_search_text = auth_results.lower()

    if "dkim=fail" in dkim_search_text or "dkim=temperror" in dkim_search_text:
        dkim_status = "FAIL"
        flags.append("EMAIL_DKIM_FAIL")
        risk_score += 35.0
    elif "dkim=pass" in dkim_search_text:
        dkim_status = "PASS"
        flags.append("EMAIL_DKIM_PASS")
    elif dkim_sig:
        dkim_status = "PRESENT"
    else:
        dkim_status = "MISSING"

    # ------------------------------------------------------------------
    # 3. Header Checks: Reply-To Mismatch
    # ------------------------------------------------------------------
    has_reply_to_mismatch = False
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        has_reply_to_mismatch = True
        flags.append("EMAIL_REPLY_TO_MISMATCH")
        flags.append("SUSPICIOUS_REDIRECTED_REPLY_TO")
        risk_score += 50.0

    # ------------------------------------------------------------------
    # 4. Display Name Spoofing
    # ------------------------------------------------------------------
    display_name_spoofed = False
    if from_header:
        display_part = from_header.split("<")[0].strip().strip('"').lower() if "<" in from_header else ""
        if display_part and from_domain:
            claims_institution = any(inst in display_part for inst in _KNOWN_INSTITUTION_KEYWORDS)
            is_freemail_or_unrelated = (from_domain in _FREE_WEBMAIL_DOMAINS) or not any(
                inst.replace(" ", "") in from_domain for inst in ["sbi", "hdfc", "icici", "axis", "kotak", "rbi", "incometax", "gov", "nic"]
            )
            if claims_institution and is_freemail_or_unrelated:
                display_name_spoofed = True
                flags.append("EMAIL_DISPLAY_NAME_SPOOF")
                flags.append("IMPERSONATING_AUTHORITY_ON_UNOFFICIAL_DOMAIN")
                risk_score += 55.0

    # ------------------------------------------------------------------
    # 5. Phishing Keywords & Panic Patterns
    # ------------------------------------------------------------------
    keyword_score = 0.0
    for pattern, flag_name, contribution in _EMAIL_PHISHING_KEYWORDS:
        if pattern.search(body) or pattern.search(headers.get("subject", "")):
            keyword_score += contribution
            flags.append(flag_name)
    risk_score += min(keyword_score, 45.0)

    # ------------------------------------------------------------------
    # 6. Embedded Links & IP Address Hosts
    # ------------------------------------------------------------------
    found_urls = _URL_RE.findall(body)
    ip_urls = _IP_HOST_RE.findall(body)
    if ip_urls:
        flags.append("EMAIL_CONTAINS_IP_ADDRESS_URL")
        risk_score += 35.0

    # Discrepancy between sender domain and link domains
    if from_domain and found_urls:
        parsed_hosts = []
        for u in found_urls:
            try:
                host = urllib.parse.urlparse(u).netloc.lower().split(":")[0]
                if host:
                    parsed_hosts.append(host)
            except Exception:
                pass
        # If message claims bank domain but all links point to third-party domain
        if parsed_hosts and not any(from_domain in h or h in from_domain for h in parsed_hosts):
            if any(inst in from_header.lower() for inst in ["sbi", "hdfc", "icici", "axis", "bank"]):
                flags.append("EMAIL_LINK_DOMAIN_MISMATCH_SENDER")
                risk_score += 30.0

    final_score = max(0.0, min(100.0, risk_score))

    # Details construction
    reasons = []
    if "EMAIL_SPF_FAIL" in flags:
        reasons.append("SPF authentication failed (unauthorized sending IP)")
    if "EMAIL_SPF_SOFTFAIL" in flags:
        reasons.append("SPF softfail (sender IP not designated)")
    if "EMAIL_DKIM_FAIL" in flags:
        reasons.append("DKIM cryptographic signature verification failed")
    if has_reply_to_mismatch:
        reasons.append(f"Reply-To address ('{reply_to_header}') differs from From address ('{from_header}')")
    if display_name_spoofed:
        reasons.append(f"Display name claims an official brand but sender address domain is '{from_domain}'")
    if "EMAIL_CONTAINS_IP_ADDRESS_URL" in flags:
        reasons.append("Email contains links directly pointing to raw IP addresses")

    detail_str = (
        f"Email analysis completed. Risk: {final_score:.1f}/100. "
        + ("; ".join(reasons) if reasons else "No major email header anomalies detected.")
    )

    return {
        "is_email": bool(headers or req.channel.value == "email" or from_domain),
        "from_header": from_header,
        "from_domain": from_domain,
        "reply_to": reply_to_header or None,
        "reply_to_domain": reply_to_domain,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "has_reply_to_mismatch": has_reply_to_mismatch,
        "display_name_spoofed": display_name_spoofed,
        "flags": flags,
        "risk_score": final_score,
        "details": detail_str,
        "url_count": len(found_urls),
        "provider": "EMAIL_ANALYZER_ENGINE",
    }
