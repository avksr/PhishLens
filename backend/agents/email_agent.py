"""
backend/agents/email_agent.py
-----------------------------
Deep Email Security & Forensic Analysis Agent for PhishLens (ScamShield AI).

Responsibilities:
1. Deep RFC 822 / MIME Forensic Parser for Raw .eml Uploads:
   - Universal ingestion of raw .eml bytes or text strings.
   - Full MIME tree traversal: plain-text, HTML, and attachment extraction.
   - Hop-by-hop MTA routing inspection (Received: headers chain) and client IP discovery.
   - Header injection detection: CRLF / newline injection in From, Subject, Reply-To.
2. Deep SPF/DKIM/DMARC Forensic Parser:
   - SPF Validation: status (pass, softfail, fail, neutral, permerror, none).
   - SPF Alignment: envelope-from (smtp.mailfrom) vs From: header domain.
   - SPF Permissive Check: detects overly broad mechanisms (e.g. +all).
   - DKIM Cryptographic Tag Parsing: v, a, d, s, c, h, bh, b, t, x.
   - DKIM Weak Algorithm Flagging: detects deprecated rsa-sha1.
   - DKIM Unsigned From Header: catches signature bypass where From: is omitted from h=.
   - DKIM Expiration Check: evaluates expiration timestamp (x=).
   - DKIM Alignment: d= signing domain vs From: domain (catches domain laundering).
   - DMARC Policy Disposition: quarantine, reject, none.
   - DMARC Alignment Synthesis: validates RFC 7489 requirement (at least one of SPF or DKIM aligned).
3. Email Body, Attachment & HTML Forensics:
   - Suspicious and executable attachments (.exe, .scr, .iso, .vbs, .js, .hta, .xlsm, .zip double-ext).
   - HTML hidden text (zero-font, display:none, visibility:hidden, opacity:0).
   - Mismatched anchor domain lures (<a href="evil.com">legit.com</a>).
   - Urgent panic, extortion, invoice bait, and credential harvesting keywords.
   - Embedded URLs and raw-IP hosts.

Author : AVNI — Sender Identity, Telecom & Email Intelligence
Module : PhishLens v1.0 (Deep SPF/DKIM/DMARC Forensic Parser)
"""

from __future__ import annotations

import email
import email.policy
import html
import ipaddress
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union

from shared.models import AgentStatusEnum, ScanRequest

# ---------------------------------------------------------------------------
# Pre-compiled Patterns
# ---------------------------------------------------------------------------
_EMAIL_ADDR_RE = re.compile(r"[\w.+-]+@([\w-]+\.[\w.-]+)")
_URL_RE = re.compile(r"https?://[^\s<>\"']+")
_IP_HOST_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|\b)")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Header injection detection: CRLF / bare newline in a header value
_HEADER_INJECTION_RE = re.compile(r"[\r\n]", re.MULTILINE)

# DKIM tag extractors
_DKIM_TAG_RE = re.compile(r"([a-z]+)=([^;]+)", re.IGNORECASE)
_DKIM_DOMAIN_RE = re.compile(r"\bd=([\w.-]+)", re.IGNORECASE)

# DMARC policy extractor from Authentication-Results header
_DMARC_POLICY_RE = re.compile(
    r"dmarc=([\w]+)(?:\s|;|$)(?:.*?header\.from=([\w.-]+))?",
    re.IGNORECASE,
)

# SPF envelope / client-ip extractors
_SPF_ENVELOPEFROM_RE = re.compile(
    r"(?:smtp\.mailfrom|envelope-from|identity)=([\w.@+-]+)",
    re.IGNORECASE,
)
_SPF_CLIENT_IP_RE = re.compile(
    r"(?:client-ip|ip)=([0-9a-fA-F:.]+)",
    re.IGNORECASE,
)

# HTML anchor tag matcher for text vs href mismatch
_HTML_ANCHOR_RE = re.compile(
    r"<a\s+(?:[^>]*?\s+)?href=[\"'](https?://[^\"']+)[\"'][^>]*>(.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)

# Hidden text / zero font CSS styles
_HTML_HIDDEN_STYLE_RE = re.compile(
    r"style=[\"'][^\"']*(?:font-size\s*:\s*0(?:px)?|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^\"']*[\"']",
    re.IGNORECASE,
)

# Malicious / high-risk attachment extensions
_EXECUTABLE_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".pif", ".vbs", ".js", ".wsf",
    ".hta", ".cpl", ".msi", ".jar", ".com"
}
_DANGEROUS_ARCHIVE_OR_IMAGE_EXTS = {
    ".iso", ".img", ".vhd", ".vhdx", ".dmg"
}
_MACRO_EXTS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm"
}

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
    if not email_str:
        return None
    match = _EMAIL_ADDR_RE.search(email_str)
    if match:
        return match.group(1).lower().strip()
    return None


def _extract_root_domain(domain: str) -> str:
    """
    Extract the eTLD+1 root domain from a full domain.
    e.g. 'mail.sbi.co.in' -> 'sbi.co.in', 'smtp.hdfc.com' -> 'hdfc.com'
    Used for SPF/DKIM/DMARC alignment checks so subdomain variations
    don't trigger false positives.
    """
    if not domain:
        return domain
    parts = domain.lower().split(".")
    two_part_tlds = {
        "co.in", "com.au", "org.uk", "net.in", "gov.in", "ac.in",
        "edu.au", "org.au", "co.uk", "me.uk", "org.in", "nic.in"
    }
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_part_tlds:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _domains_aligned(domain_a: Optional[str], domain_b: Optional[str]) -> bool:
    """Check if two email domains are aligned at the eTLD+1 root domain level."""
    if not domain_a or not domain_b:
        return False
    return _extract_root_domain(domain_a) == _extract_root_domain(domain_b)


def _check_header_injection(value: str) -> bool:
    """Detect CRLF / bare newline injection in a header value."""
    return bool(_HEADER_INJECTION_RE.search(value))


def _parse_dkim_tags(dkim_header_val: str) -> Dict[str, str]:
    """Parse all tag-value pairs from a DKIM-Signature header."""
    tags: Dict[str, str] = {}
    for match in _DKIM_TAG_RE.finditer(dkim_header_val):
        tag_key = match.group(1).lower().strip()
        tag_val = match.group(2).strip().replace("\r", "").replace("\n", "").replace(" ", "")
        tags[tag_key] = tag_val
    return tags


def _parse_received_hops(received_headers: List[str]) -> List[Dict[str, Any]]:
    """
    Forensically parse Received: MTA routing hops.
    Extracts sender host, sending IP, receiving MTA, and timestamp.
    """
    hops: List[Dict[str, Any]] = []
    for raw in received_headers:
        cleaned = " ".join(raw.split())
        ip_match = _IPV4_RE.search(cleaned)
        extracted_ip = ip_match.group(0) if ip_match else None
        
        is_private = False
        if extracted_ip:
            try:
                ip_obj = ipaddress.ip_address(extracted_ip)
                is_private = (
                    ip_obj.is_loopback
                    or ip_obj.is_link_local
                    or (ip_obj.version == 4 and (
                        ip_obj in ipaddress.ip_network("10.0.0.0/8")
                        or ip_obj in ipaddress.ip_network("172.16.0.0/12")
                        or ip_obj in ipaddress.ip_network("192.168.0.0/16")
                    ))
                )
            except ValueError:
                pass

        # Extract "by <mta>"
        by_match = re.search(r"\bby\s+([^\s;]+)", cleaned, re.I)
        from_match = re.search(r"\bfrom\s+([^\s;]+)", cleaned, re.I)

        hops.append({
            "raw": cleaned[:200],
            "ip": extracted_ip,
            "is_private_ip": is_private,
            "from_host": from_match.group(1) if from_match else None,
            "by_mta": by_match.group(1) if by_match else None,
        })
    return hops


def _extract_attachments_forensics(msg: email.message.EmailMessage) -> List[Dict[str, Any]]:
    """Inspect all MIME attachments for hazardous extensions and double extensions."""
    attachments: List[Dict[str, Any]] = []
    for part in msg.walk():
        fn = part.get_filename()
        content_disposition = str(part.get("Content-Disposition", ""))
        is_attachment = ("attachment" in content_disposition.lower()) or bool(fn)
        
        if is_attachment and fn:
            fn_clean = fn.strip()
            fn_lower = fn_clean.lower()
            
            # Check for double extension e.g. document.pdf.exe
            dots = fn_lower.split(".")
            is_double_ext = len(dots) >= 3 and any(f".{d}" in _EXECUTABLE_EXTS for d in dots[1:])
            
            # Check extension category
            ext = "." + dots[-1] if len(dots) > 1 else ""
            is_executable = ext in _EXECUTABLE_EXTS or is_double_ext
            is_dangerous_archive = ext in _DANGEROUS_ARCHIVE_OR_IMAGE_EXTS
            is_macro = ext in _MACRO_EXTS

            attachments.append({
                "filename": fn_clean,
                "content_type": part.get_content_type(),
                "extension": ext,
                "is_executable": is_executable,
                "is_dangerous_archive": is_dangerous_archive,
                "is_macro": is_macro,
                "is_double_extension": is_double_ext,
                "size_bytes": len(part.get_payload(decode=True) or b""),
            })
    return attachments


def parse_raw_eml(eml_input: Union[str, bytes]) -> Dict[str, Any]:
    """
    Deep Forensic Email Parser for Raw .eml Uploads.
    
    Accepts raw RFC 822 / MIME .eml bytes or string.
    Returns comprehensive forensic report covering:
    - Envelope & Metadata (From, Reply-To, Subject, Date, Message-ID)
    - Deep SPF (Status, Client IP, Envelope-From, Alignment, +all check)
    - Deep DKIM (Status, Tags, Selector, Algorithm, Expiration, Alignment, Signed Headers)
    - Deep DMARC (Policy, Subdomain Policy, Disposition, Alignment Requirement)
    - MTA Hop Chain & Originating IP
    - MIME Attachments & Malware Risk
    - HTML Forensics (Zero-Font / Hidden Elements, Anchor Domain Mismatches)
    """
    if isinstance(eml_input, bytes):
        msg = email.message_from_bytes(eml_input, policy=email.policy.default)
        raw_str = eml_input.decode("utf-8", errors="ignore")
    else:
        msg = email.message_from_string(eml_input, policy=email.policy.default)
        raw_str = eml_input

    # Flatten headers dictionary
    headers: Dict[str, str] = {}
    received_list: List[str] = []
    auth_results_list: List[str] = []
    dkim_signatures_list: List[str] = []

    for k, v in msg.items():
        k_lower = k.lower()
        headers[k_lower] = str(v)
        if k_lower == "received":
            received_list.append(str(v))
        elif k_lower == "authentication-results":
            auth_results_list.append(str(v))
        elif k_lower == "dkim-signature":
            dkim_signatures_list.append(str(v))

    # Also scan raw string for any additional Authentication-Results or DKIM-Signature headers
    for line in raw_str.splitlines():
        line_clean = line.strip()
        if line_clean.lower().startswith("authentication-results:") and line_clean not in auth_results_list:
            auth_results_list.append(line_clean.split(":", 1)[-1].strip())
        elif line_clean.lower().startswith("dkim-signature:") and line_clean not in dkim_signatures_list:
            dkim_signatures_list.append(line_clean.split(":", 1)[-1].strip())

    combined_auth_results = " ".join(auth_results_list)
    received_spf_hdr = headers.get("received-spf", "")

    # Extract Body Parts
    plain_body = ""
    html_body = ""
    for part in msg.walk():
        c_type = part.get_content_type()
        if c_type == "text/plain" and not plain_body:
            try:
                plain_body = part.get_content()
            except Exception:
                plain_body = str(part.get_payload() or "")
        elif c_type == "text/html" and not html_body:
            try:
                html_body = part.get_content()
            except Exception:
                html_body = str(part.get_payload() or "")

    combined_body = plain_body + "\n" + html_body if html_body else plain_body
    if not combined_body.strip():
        # Fallback to msg payload directly
        raw_payload = msg.get_payload()
        combined_body = str(raw_payload) if not isinstance(raw_payload, list) else ""

    from_header = headers.get("from", "")
    from_domain = _extract_domain(from_header)
    reply_to_header = headers.get("reply-to", "")
    reply_to_domain = _extract_domain(reply_to_header) if reply_to_header else None

    flags: List[str] = []
    risk_score = 0.0

    # ------------------------------------------------------------------
    # 0. Header Injection Check
    # ------------------------------------------------------------------
    injection_found = False
    for hdr_name, hdr_val in [
        ("from", from_header),
        ("reply-to", reply_to_header),
        ("subject", headers.get("subject", "")),
    ]:
        if hdr_val and _check_header_injection(hdr_val):
            flags.append("EMAIL_HEADER_INJECTION_DETECTED")
            flags.append(f"EMAIL_HEADER_INJECTION_{hdr_name.upper().replace('-', '_')}")
            risk_score += 60.0
            injection_found = True
            break

    if not injection_found:
        raw_header_part = raw_str.split("\n\n", 1)[0] if "\n\n" in raw_str else raw_str
        if (
            re.search(r"\r\n(?:bcc|cc|to|subject)\s*:", raw_header_part, re.IGNORECASE)
            or re.search(r"(?:from|subject):[^\r\n]*\r\n(?:bcc|cc):", raw_header_part, re.IGNORECASE)
        ):
            flags.append("EMAIL_HEADER_INJECTION_DETECTED")
            flags.append("EMAIL_HEADER_INJECTION_CRLF")
            risk_score += 60.0

    # ------------------------------------------------------------------
    # 1. Deep SPF Analysis
    # ------------------------------------------------------------------
    spf_status = "NONE"
    spf_search_text = (received_spf_hdr + " " + combined_auth_results).lower()

    if "spf=fail" in spf_search_text or ("fail" in received_spf_hdr.lower() and "softfail" not in received_spf_hdr.lower()):
        spf_status = "FAIL"
        flags.append("EMAIL_SPF_FAIL")
        risk_score += 45.0
    elif "spf=softfail" in spf_search_text or "softfail" in received_spf_hdr.lower():
        spf_status = "SOFTFAIL"
        flags.append("EMAIL_SPF_SOFTFAIL")
        risk_score += 30.0
    elif "spf=pass" in spf_search_text or ("pass" in received_spf_hdr.lower() and received_spf_hdr):
        spf_status = "PASS"
        flags.append("EMAIL_SPF_PASS")
    elif "spf=neutral" in spf_search_text:
        spf_status = "NEUTRAL"
        flags.append("EMAIL_SPF_NEUTRAL")
        risk_score += 10.0
    elif "spf=permerror" in spf_search_text or "permerror" in received_spf_hdr.lower():
        spf_status = "PERMERROR"
        flags.append("EMAIL_SPF_PERMERROR")
        risk_score += 20.0

    # Extract client IP and envelope from
    spf_client_ip_match = _SPF_CLIENT_IP_RE.search(received_spf_hdr or combined_auth_results)
    spf_client_ip = spf_client_ip_match.group(1) if spf_client_ip_match else None

    spf_envelope_match = _SPF_ENVELOPEFROM_RE.search(received_spf_hdr or combined_auth_results)
    spf_envelope_domain = None
    spf_aligned = False
    if spf_envelope_match:
        raw_env = spf_envelope_match.group(1).strip()
        spf_envelope_domain = _extract_domain(raw_env) or raw_env.lower()
        if from_domain and spf_envelope_domain:
            spf_aligned = _domains_aligned(spf_envelope_domain, from_domain)
            if spf_status == "PASS" and not spf_aligned:
                flags.append("EMAIL_SPF_ALIGNMENT_FAIL")
                flags.append("EMAIL_SPF_ENVELOPE_FROM_MISMATCH")
                risk_score += 35.0

    # Check for permissive SPF wildcard (+all)
    if "+all" in spf_search_text or "redirect=+all" in spf_search_text:
        flags.append("EMAIL_SPF_PERMISSIVE_WILDCARD")
        risk_score += 25.0

    # ------------------------------------------------------------------
    # 2. Deep DKIM Analysis
    # ------------------------------------------------------------------
    dkim_status = "NONE"
    dkim_signing_domain: Optional[str] = None
    dkim_tags: Dict[str, str] = {}
    dkim_aligned = False
    dkim_sig = dkim_signatures_list[0] if dkim_signatures_list else ""

    if dkim_sig:
        dkim_tags = _parse_dkim_tags(dkim_sig)
        dkim_signing_domain = dkim_tags.get("d", "").lower() or None

    dkim_search_text = combined_auth_results.lower()
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
        if not dkim_signing_domain:
            _d_match = _DKIM_DOMAIN_RE.search(combined_auth_results)
            if _d_match:
                dkim_signing_domain = _d_match.group(1).lower()
    elif dkim_sig:
        dkim_status = "PRESENT"
    else:
        dkim_status = "MISSING"

    # DKIM Deep Forensic Tag Checks
    dkim_from_signed = True
    dkim_is_expired = False
    if dkim_tags:
        # Check signed headers (h=) - From MUST be signed!
        signed_headers = [h.strip().lower() for h in dkim_tags.get("h", "").split(":")]
        if signed_headers and "from" not in signed_headers:
            dkim_from_signed = False
            flags.append("EMAIL_DKIM_UNSIGNED_FROM_HEADER")
            risk_score += 30.0

        # Check weak signature algorithm (rsa-sha1 is cryptographically broken)
        alg = dkim_tags.get("a", "").lower()
        if "sha1" in alg:
            flags.append("EMAIL_DKIM_WEAK_ALGORITHM")
            risk_score += 20.0

        # Check expiration (x=)
        if "x" in dkim_tags:
            try:
                exp_ts = int(dkim_tags["x"])
                if exp_ts < time.time() and exp_ts > 0:
                    dkim_is_expired = True
                    flags.append("EMAIL_DKIM_SIGNATURE_EXPIRED")
                    risk_score += 25.0
            except ValueError:
                pass

    # DKIM Alignment with From: header
    if dkim_signing_domain and from_domain:
        dkim_aligned = _domains_aligned(dkim_signing_domain, from_domain)
        if dkim_status == "PASS" and not dkim_aligned:
            flags.append("EMAIL_DKIM_ALIGNMENT_FAIL")
            flags.append("EMAIL_DKIM_SIGNING_DOMAIN_MISMATCH")
            risk_score += 30.0

    # ------------------------------------------------------------------
    # 3. Deep DMARC Analysis
    # ------------------------------------------------------------------
    dmarc_status = "NONE"
    dmarc_policy: Optional[str] = None
    dmarc_header_from: Optional[str] = None

    dmarc_match = _DMARC_POLICY_RE.search(combined_auth_results)
    if dmarc_match:
        dmarc_status = dmarc_match.group(1).lower()
        dmarc_header_from = dmarc_match.group(2).lower() if dmarc_match.group(2) else None
        
        # Policy extraction from p= or policy= tag
        p_match = re.search(r"\bp=([\w]+)", combined_auth_results, re.I)
        dmarc_policy = p_match.group(1).lower() if p_match else dmarc_status

        if dmarc_status in ("fail", "quarantine", "reject"):
            flags.append("EMAIL_DMARC_FAIL")
            if dmarc_status == "reject" or dmarc_policy == "reject":
                flags.append("EMAIL_DMARC_POLICY_REJECT")
                risk_score += 50.0
            elif dmarc_status == "quarantine" or dmarc_policy == "quarantine":
                flags.append("EMAIL_DMARC_POLICY_QUARANTINE")
                risk_score += 40.0
            else:
                risk_score += 35.0
        elif dmarc_status == "pass":
            flags.append("EMAIL_DMARC_PASS")

    # DMARC Alignment Evaluation (RFC 7489 requirement: SPF aligned pass OR DKIM aligned pass)
    dmarc_alignment_passed = (spf_status == "PASS" and spf_aligned) or (dkim_status == "PASS" and dkim_aligned)
    if (spf_status == "PASS" or dkim_status == "PASS") and not dmarc_alignment_passed and from_domain:
        if "EMAIL_DMARC_ALIGNMENT_FAIL" not in flags:
            flags.append("EMAIL_DMARC_ALIGNMENT_FAIL")
            risk_score += 25.0

    # ------------------------------------------------------------------
    # 4. Reply-To Mismatch
    # ------------------------------------------------------------------
    has_reply_to_mismatch = False
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        has_reply_to_mismatch = True
        flags.append("EMAIL_REPLY_TO_MISMATCH")
        flags.append("SUSPICIOUS_REDIRECTED_REPLY_TO")
        risk_score += 50.0

    # ------------------------------------------------------------------
    # 5. Display Name Spoofing
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
    # 6. MTA Routing Hops & Originating IP
    # ------------------------------------------------------------------
    mta_hops = _parse_received_hops(received_list)
    originating_ip = headers.get("x-originating-ip", "").strip("[] ") or headers.get("x-sender-ip", "").strip("[] ")
    if not originating_ip:
        # Pick the oldest/first public IP in the Received: chain (closest to sender)
        for hop in reversed(mta_hops):
            if hop["ip"] and not hop["is_private_ip"]:
                originating_ip = hop["ip"]
                break
    if not originating_ip and spf_client_ip:
        originating_ip = spf_client_ip
    if not originating_ip and mta_hops:
        for hop in reversed(mta_hops):
            if hop["ip"]:
                originating_ip = hop["ip"]
                break

    # ------------------------------------------------------------------
    # 7. Attachment Forensics
    # ------------------------------------------------------------------
    attachments = _extract_attachments_forensics(msg)
    for att in attachments:
        if att["is_executable"]:
            flags.append("EMAIL_EXECUTABLE_ATTACHMENT")
            risk_score += 55.0
            break
        elif att["is_dangerous_archive"]:
            flags.append("EMAIL_SUSPICIOUS_ATTACHMENT")
            risk_score += 40.0
            break
        elif att["is_macro"]:
            flags.append("EMAIL_MACRO_ATTACHMENT")
            risk_score += 35.0
            break

    # ------------------------------------------------------------------
    # 8. HTML Body & Anchor Forensics
    # ------------------------------------------------------------------
    anchor_mismatches: List[Dict[str, str]] = []
    has_hidden_elements = False

    if html_body:
        # Check hidden CSS text
        if _HTML_HIDDEN_STYLE_RE.search(html_body):
            has_hidden_elements = True
            flags.append("EMAIL_HTML_HIDDEN_TEXT_DETECTED")
            risk_score += 25.0

        # Check anchor text domain vs href domain mismatch
        for a_match in _HTML_ANCHOR_RE.finditer(html_body):
            href_url = a_match.group(1)
            display_text = html.unescape(a_match.group(2)).strip()
            # If display text looks like a URL e.g. "https://sbi.co.in"
            if display_text.startswith("http://") or display_text.startswith("https://") or "www." in display_text:
                disp_domain = _extract_domain(display_text) or urllib.parse.urlparse(
                    display_text if "://" in display_text else "http://" + display_text
                ).netloc.lower().split(":")[0]
                href_domain = urllib.parse.urlparse(href_url).netloc.lower().split(":")[0]
                if disp_domain and href_domain and not _domains_aligned(disp_domain, href_domain):
                    anchor_mismatches.append({"display": display_text, "destination": href_url})
                    if "EMAIL_HTML_ANCHOR_DOMAIN_MISMATCH" not in flags:
                        flags.append("EMAIL_HTML_ANCHOR_DOMAIN_MISMATCH")
                        risk_score += 40.0

    # ------------------------------------------------------------------
    # 9. Body Keyword & Link Checks
    # ------------------------------------------------------------------
    keyword_score = 0.0
    for pattern, flag_name, contribution in _EMAIL_PHISHING_KEYWORDS:
        if pattern.search(combined_body) or pattern.search(headers.get("subject", "")):
            keyword_score += contribution
            flags.append(flag_name)
    risk_score += min(keyword_score, 45.0)

    found_urls = _URL_RE.findall(combined_body)
    ip_urls = _IP_HOST_RE.findall(combined_body)
    if ip_urls:
        flags.append("EMAIL_CONTAINS_IP_ADDRESS_URL")
        risk_score += 35.0

    if from_domain and found_urls:
        parsed_hosts = []
        for u in found_urls:
            try:
                host = urllib.parse.urlparse(u).netloc.lower().split(":")[0]
                if host:
                    parsed_hosts.append(host)
            except Exception:
                pass
        if parsed_hosts and not any(from_domain in h or h in from_domain for h in parsed_hosts):
            if any(inst in from_header.lower() for inst in ["sbi", "hdfc", "icici", "axis", "bank"]):
                flags.append("EMAIL_LINK_DOMAIN_MISMATCH_SENDER")
                risk_score += 30.0

    final_score = max(0.0, min(100.0, risk_score))

    # Construct details and reasons
    reasons = []
    if "EMAIL_HEADER_INJECTION_DETECTED" in flags:
        reasons.append("CRLF/newline header injection attempt detected")
    if "EMAIL_SPF_FAIL" in flags:
        reasons.append("SPF authentication failed (unauthorized sending IP)")
    if "EMAIL_SPF_SOFTFAIL" in flags:
        reasons.append("SPF softfail (sender IP not designated)")
    if "EMAIL_SPF_ALIGNMENT_FAIL" in flags:
        reasons.append("SPF passes for a domain not aligned with the From: address (laundering attack)")
    if "EMAIL_DKIM_FAIL" in flags:
        reasons.append("DKIM cryptographic signature verification failed")
    if "EMAIL_DKIM_ALIGNMENT_FAIL" in flags:
        reasons.append(f"DKIM signature is for domain '{dkim_signing_domain}' which does not align with From: domain '{from_domain}'")
    if "EMAIL_DKIM_UNSIGNED_FROM_HEADER" in flags:
        reasons.append("DKIM signature header (h=) omits the From: header (signature bypass risk)")
    if "EMAIL_DKIM_SIGNATURE_EXPIRED" in flags:
        reasons.append("DKIM cryptographic signature timestamp is expired")
    if "EMAIL_DMARC_FAIL" in flags:
        reasons.append(f"DMARC policy enforcement failed (disposition: {dmarc_status})")
    if "EMAIL_EXECUTABLE_ATTACHMENT" in flags:
        reasons.append("Dangerous executable attachment discovered in email body")
    if "EMAIL_HTML_ANCHOR_DOMAIN_MISMATCH" in flags:
        reasons.append("HTML deceptive link: displayed bank URL differs from actual clicked destination")
    if has_reply_to_mismatch:
        reasons.append(f"Reply-To address ('{reply_to_header}') differs from From address ('{from_header}')")
    if display_name_spoofed:
        reasons.append(f"Display name claims an official brand but sender address domain is '{from_domain}'")
    if "EMAIL_CONTAINS_IP_ADDRESS_URL" in flags:
        reasons.append("Email contains links directly pointing to raw IP addresses")

    detail_str = (
        f"Email forensic analysis completed. Risk: {final_score:.1f}/100. "
        + ("; ".join(reasons) if reasons else "No major email header anomalies detected.")
    )

    forensic_report = {
        "spf": {
            "status": spf_status,
            "client_ip": spf_client_ip,
            "envelope_from": spf_envelope_domain,
            "aligned": spf_aligned,
            "raw_header": received_spf_hdr,
        },
        "dkim": {
            "status": dkim_status,
            "signing_domain": dkim_signing_domain,
            "selector": dkim_tags.get("s"),
            "algorithm": dkim_tags.get("a"),
            "headers_signed": [h.strip() for h in dkim_tags.get("h", "").split(":") if h.strip()],
            "from_signed": dkim_from_signed,
            "is_expired": dkim_is_expired,
            "aligned": dkim_aligned,
        },
        "dmarc": {
            "status": dmarc_status,
            "policy": dmarc_policy,
            "header_from": dmarc_header_from,
            "alignment_passed": dmarc_alignment_passed,
        },
        "mta_hops": mta_hops,
        "originating_ip": originating_ip,
        "attachments": attachments,
        "html_forensics": {
            "has_hidden_elements": has_hidden_elements,
            "anchor_mismatches": anchor_mismatches,
        },
    }

    return {
        "is_email": bool(headers or from_domain or received_list or auth_results_list),
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
        "forensic_report": forensic_report,
        "provider": "EMAIL_FORENSIC_PARSER",
    }


def analyze_email(req: ScanRequest) -> Dict[str, Any]:
    """
    Core Email / Message security analysis pipeline entry point.
    Compatible with ScanRequest and raw .eml ingestion.
    """
    raw_content = req.content
    # Check if metadata provides a separate raw_eml
    if req.metadata:
        if "raw_eml" in req.metadata:
            raw_content = str(req.metadata["raw_eml"])
        elif "eml_content" in req.metadata:
            raw_content = str(req.metadata["eml_content"])

    res = parse_raw_eml(raw_content)

    # If sender or headers were specifically supplied in req.sender or req.metadata
    if req.sender and not res.get("from_header"):
        res["from_header"] = req.sender
        res["from_domain"] = _extract_domain(req.sender)

    return res
