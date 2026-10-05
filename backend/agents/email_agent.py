"""
backend/agents/email_agent.py
-----------------------------
Email & Message Security Analysis Agent for PhishLens (ScamShield AI).

Responsibilities:
1. Header Security Verification (Upgraded — AVNI Sprint 2):
   - SPF Validation: pass, softfail, fail, neutral, none.
   - SPF Alignment: verified sending domain matches From: domain (catches laundering).
   - DKIM Validation: pass, fail, invalid, missing, temperror.
   - DKIM Alignment: d= tag domain matches From: domain.
   - DMARC Policy Parsing: quarantine / reject / none.
   - Multi Authentication-Results header chaining (catches split-auth attacks).
   - Reply-To Mismatch: compares From domain vs Reply-To domain.
   - Display Name Spoofing: institutional display name on consumer/freemail.
   - Header Injection: detects CRLF / newline injection in From/Subject.
2. Email Body & Pattern Heuristics:
   - Urgent panic/extortion/suspension keywords.
   - Credential harvesting lures and fake invoice/tax patterns.
   - Suspicious links, IP hosts, and mismatched anchor domains.
3. Universal Parsing:
   - Ingests RFC 822 raw email strings or structured dictionaries from metadata.
   - Seamlessly invoked when channel is EMAIL or when email headers are present.

Author  : AVNI — Sender Identity, Email & UPI Intelligence
Module  : PhishLens v1.0 (Sprint 2 — SPF/DKIM Upgrade)
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

# Header injection detection: CRLF / bare newline in a header value
_HEADER_INJECTION_RE = re.compile(r"[\r\n]", re.MULTILINE)

# DKIM d= tag extractor (from DKIM-Signature header)
_DKIM_DOMAIN_RE = re.compile(r"\bd=([\w.-]+)", re.IGNORECASE)

# DMARC policy extractor from Authentication-Results header
_DMARC_POLICY_RE = re.compile(
    r"dmarc=([\w]+)(?:\s|;|$)(?:.*?header\.from=([\w.-]+))?",
    re.IGNORECASE,
)

# SPF aligned domain (smtp.mailfrom / envelope-from)
_SPF_ENVELOPEFROM_RE = re.compile(
    r"smtp\.mailfrom=([\w.@+-]+)",
    re.IGNORECASE,
)

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


def _extract_root_domain(domain: str) -> str:
    """
    Extract the eTLD+1 root domain from a full domain.
    e.g. 'mail.sbi.co.in' -> 'sbi.co.in', 'smtp.hdfc.com' -> 'hdfc.com'
    This is used for SPF/DKIM alignment checks so subdomain variations
    don't create false positives.
    """
    if not domain:
        return domain
    parts = domain.lower().split(".")
    # Handle common 2-part TLDs (co.in, com.au, org.uk, net.in, etc.)
    two_part_tlds = {
        "co.in", "com.au", "org.uk", "net.in", "gov.in", "ac.in",
        "edu.au", "org.au", "co.uk", "me.uk", "org.in"
    }
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_part_tlds:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _domains_aligned(domain_a: Optional[str], domain_b: Optional[str]) -> bool:
    """
    Check if two email domains are aligned at the root-domain level.
    Returns True if both share the same eTLD+1 root domain.
    """
    if not domain_a or not domain_b:
        return False
    return _extract_root_domain(domain_a) == _extract_root_domain(domain_b)


def _check_header_injection(value: str) -> bool:
    """
    Detect CRLF / bare newline injection in a header value.
    Attackers inject \r\n to forge additional headers.
    Returns True if injection attempt is detected.
    """
    return bool(_HEADER_INJECTION_RE.search(value))


def _extract_dkim_domain(dkim_signature_header: str) -> Optional[str]:
    """Extract the signing domain (d= tag) from a DKIM-Signature header."""
    match = _DKIM_DOMAIN_RE.search(dkim_signature_header)
    return match.group(1).lower().strip() if match else None


def _parse_dmarc_from_auth_results(auth_results_combined: str) -> Tuple[str, Optional[str]]:
    """
    Parse DMARC disposition and header.from domain from Authentication-Results.
    Returns: (dmarc_status, header_from_domain)
    - dmarc_status: 'pass', 'fail', 'quarantine', 'reject', 'none', 'NONE'
    """
    match = _DMARC_POLICY_RE.search(auth_results_combined)
    if match:
        dmarc_result = match.group(1).lower()
        header_from = match.group(2).lower() if match.group(2) else None
        return dmarc_result, header_from
    return "NONE", None


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
    Core Email / Message security analysis pipeline (Sprint 2 — upgraded).

    Checks (in order):
    1. Header injection in From / Subject.
    2. SPF — status + envelope domain alignment.
    3. DKIM — status + d= signing domain alignment.
    4. DMARC — policy disposition (quarantine/reject/fail).
    5. Multi-Authentication-Results chaining (catches split-auth attacks).
    6. Reply-To mismatch.
    7. Display name spoofing.
    8. Phishing keywords & panic patterns.
    9. Embedded links & raw-IP address hosts.

    Returns structured analysis dictionary suitable for inclusion in SenderAgentResult.
    """
    headers, body = _parse_email_headers_and_body(req.content, req.metadata)

    flags: List[str] = []
    risk_score = 0.0

    # Sender field from request or From header
    from_header = headers.get("from") or req.sender or ""
    reply_to_header = headers.get("reply-to", "")
    dkim_sig = headers.get("dkim-signature", "")
    spf_header = headers.get("received-spf", "")

    # Aggregate ALL Authentication-Results headers (some servers split them)
    # The standard library only returns the last occurrence; we scan raw content.
    all_auth_results_parts: List[str] = []
    if headers.get("authentication-results"):
        all_auth_results_parts.append(headers["authentication-results"])
    # Also scan raw content for any additional Authentication-Results lines
    for line in req.content.splitlines():
        if line.lower().startswith("authentication-results:") and line not in all_auth_results_parts:
            all_auth_results_parts.append(line.split(":", 1)[-1].strip())
    auth_results = " ".join(all_auth_results_parts)

    from_domain = _extract_domain(from_header)
    reply_to_domain = _extract_domain(reply_to_header) if reply_to_header else None

    # ------------------------------------------------------------------
    # 0. Header Injection Detection (new — Sprint 2)
    # ------------------------------------------------------------------
    injection_found = False
    for _inj_hdr_name, _inj_hdr_val in [
        ("sender", req.sender or ""),
        ("from", from_header),
        ("reply-to", reply_to_header),
        ("subject", headers.get("subject", "")),
    ]:
        if _inj_hdr_val and _check_header_injection(_inj_hdr_val):
            flags.append("EMAIL_HEADER_INJECTION_DETECTED")
            flags.append(f"EMAIL_HEADER_INJECTION_{_inj_hdr_name.upper().replace('-', '_')}")
            risk_score += 60.0
            injection_found = True
            break

    if not injection_found and req.metadata and isinstance(req.metadata.get("headers"), dict):
        for _m_name, _m_val in req.metadata["headers"].items():
            if _check_header_injection(str(_m_val)):
                flags.append("EMAIL_HEADER_INJECTION_DETECTED")
                flags.append(f"EMAIL_HEADER_INJECTION_{str(_m_name).upper().replace('-', '_')}")
                risk_score += 60.0
                injection_found = True
                break

    if not injection_found:
        raw_header_part = req.content.split("\n\n", 1)[0] if "\n\n" in req.content else req.content
        if re.search(r"\r\n(?:bcc|cc|to|subject)\s*:", raw_header_part, re.IGNORECASE) or re.search(r"(?:from|subject):[^\r\n]*\r\n(?:bcc|cc):", raw_header_part, re.IGNORECASE):
            flags.append("EMAIL_HEADER_INJECTION_DETECTED")
            flags.append("EMAIL_HEADER_INJECTION_CRLF")
            risk_score += 60.0
            injection_found = True

    # ------------------------------------------------------------------
    # 1. Header Checks: SPF (status + envelope alignment)
    # ------------------------------------------------------------------
    spf_status = "NONE"
    spf_search_text = (spf_header + " " + auth_results).lower()

    if "spf=fail" in spf_search_text or ("fail" in spf_header.lower() and "softfail" not in spf_header.lower()):
        spf_status = "FAIL"
        flags.append("EMAIL_SPF_FAIL")
        risk_score += 45.0
    elif "spf=softfail" in spf_search_text or "softfail" in spf_header.lower():
        spf_status = "SOFTFAIL"
        flags.append("EMAIL_SPF_SOFTFAIL")
        risk_score += 30.0
    elif "spf=pass" in spf_search_text or ("pass" in spf_header.lower() and spf_header):
        spf_status = "PASS"
        flags.append("EMAIL_SPF_PASS")
    elif "spf=neutral" in spf_search_text:
        spf_status = "NEUTRAL"
        flags.append("EMAIL_SPF_NEUTRAL")
        risk_score += 10.0
    elif "spf=permerror" in spf_search_text or "permerror" in spf_header.lower():
        spf_status = "PERMERROR"
        flags.append("EMAIL_SPF_PERMERROR")
        risk_score += 20.0

    # SPF Envelope-From Alignment (catches laundering: SPF passes for unrelated domain)
    spf_envelope_match = _SPF_ENVELOPEFROM_RE.search(spf_search_text)
    if spf_envelope_match and from_domain and spf_status == "PASS":
        envelope_domain = _extract_domain(spf_envelope_match.group(1)) or spf_envelope_match.group(1)
        if envelope_domain and not _domains_aligned(envelope_domain, from_domain):
            flags.append("EMAIL_SPF_ALIGNMENT_FAIL")
            flags.append("EMAIL_SPF_ENVELOPE_FROM_MISMATCH")
            risk_score += 35.0  # SPF passes for a domain that doesn't match From:

    # ------------------------------------------------------------------
    # 2. Header Checks: DKIM (status + signing domain alignment)
    # ------------------------------------------------------------------
    dkim_status = "NONE"
    dkim_search_text = auth_results.lower()
    dkim_signing_domain: Optional[str] = None

    if "dkim=fail" in dkim_search_text:
        dkim_status = "FAIL"
        flags.append("EMAIL_DKIM_FAIL")
        risk_score += 35.0
    elif "dkim=temperror" in dkim_search_text:
        dkim_status = "TEMPERROR"
        flags.append("EMAIL_DKIM_TEMPERROR")
        risk_score += 20.0
    elif "dkim=permerror" in dkim_search_text:
        dkim_status = "PERMERROR"
        flags.append("EMAIL_DKIM_PERMERROR")
        risk_score += 25.0
    elif "dkim=pass" in dkim_search_text:
        dkim_status = "PASS"
        flags.append("EMAIL_DKIM_PASS")
        # Extract signing domain for alignment check
        dkim_signing_domain = _extract_dkim_domain(dkim_sig) if dkim_sig else None
        if not dkim_signing_domain:
            # Fall back to parsing d= from the auth-results text
            _d_match = _DKIM_DOMAIN_RE.search(auth_results)
            if _d_match:
                dkim_signing_domain = _d_match.group(1).lower()
    elif dkim_sig:
        dkim_status = "PRESENT"
        dkim_signing_domain = _extract_dkim_domain(dkim_sig)
    else:
        dkim_status = "MISSING"

    # DKIM Signing Domain Alignment
    if dkim_status == "PASS" and dkim_signing_domain and from_domain:
        if not _domains_aligned(dkim_signing_domain, from_domain):
            flags.append("EMAIL_DKIM_ALIGNMENT_FAIL")
            flags.append("EMAIL_DKIM_SIGNING_DOMAIN_MISMATCH")
            risk_score += 30.0  # Valid DKIM but for wrong domain — laundering attack

    # ------------------------------------------------------------------
    # 2.5. DMARC Policy Check (new — Sprint 2)
    # ------------------------------------------------------------------
    dmarc_status, dmarc_header_from = _parse_dmarc_from_auth_results(auth_results)
    if dmarc_status in ("fail", "quarantine", "reject"):
        flags.append("EMAIL_DMARC_FAIL")
        if dmarc_status == "reject":
            flags.append("EMAIL_DMARC_POLICY_REJECT")
            risk_score += 50.0
        elif dmarc_status == "quarantine":
            flags.append("EMAIL_DMARC_POLICY_QUARANTINE")
            risk_score += 40.0
        else:
            risk_score += 35.0
    elif dmarc_status == "pass":
        flags.append("EMAIL_DMARC_PASS")

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
    if "EMAIL_HEADER_INJECTION_DETECTED" in flags:
        reasons.append("CRLF/newline header injection attempt detected")
    if "EMAIL_SPF_FAIL" in flags:
        reasons.append("SPF authentication failed (unauthorized sending IP)")
    if "EMAIL_SPF_SOFTFAIL" in flags:
        reasons.append("SPF softfail (sender IP not designated)")
    if "EMAIL_SPF_ALIGNMENT_FAIL" in flags:
        reasons.append("SPF passes for a domain not aligned with the From: address (laundering)")
    if "EMAIL_DKIM_FAIL" in flags:
        reasons.append("DKIM cryptographic signature verification failed")
    if "EMAIL_DKIM_ALIGNMENT_FAIL" in flags:
        reasons.append(
            f"DKIM signature is for domain '{dkim_signing_domain}' which doesn't match "
            f"From: domain '{from_domain}' (potential laundering attack)"
        )
    if "EMAIL_DMARC_FAIL" in flags:
        reasons.append(f"DMARC policy enforcement failed (disposition: {dmarc_status})")
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
        "dkim_signing_domain": dkim_signing_domain,
        "dmarc_status": dmarc_status,
        "has_reply_to_mismatch": has_reply_to_mismatch,
        "display_name_spoofed": display_name_spoofed,
        "flags": flags,
        "risk_score": final_score,
        "details": detail_str,
        "url_count": len(found_urls),
        "provider": "EMAIL_ANALYZER_ENGINE",
    }
