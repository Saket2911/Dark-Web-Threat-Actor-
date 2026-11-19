"""Identifier normalization and validation.

Identifier values are canonicalised per type so that the relationship engine
compares like with like. Names are never used to merge actors: only an exact
canonical identifier value match creates a shared-identifier link.
"""

import ipaddress
import re

# Identifier types supported by the platform, mapped to a UI label.
IDENTIFIER_TYPES = {
    "pgp": "PGP fingerprint",
    "wallet": "Cryptocurrency wallet",
    "email": "Email address",
    "domain": "Domain",
    "ip": "IP address",
    "username": "Username",
    "cert": "Certificate fingerprint",
    "url": "URL",
    "infra": "Infrastructure value",
}

# Types that can be validated strictly.
STRICT_TYPES = {"email", "domain", "ip"}

TYPE_ALIASES = {
    "cryptocurrency": "wallet",
    "crypto": "wallet",
    "btc": "wallet",
    "xmr": "wallet",
    "eth": "wallet",
    "email_address": "email",
    "e-mail": "email",
    "pgp_fingerprint": "pgp",
    "fingerprint": "pgp",
    "pgp_key": "pgp",
    "user": "username",
    "handle": "username",
    "hostname": "domain",
    "ipv4": "ip",
    "ipv6": "ip",
    "certificate": "cert",
    "tls_cert": "cert",
    "link": "url",
}


def normalize_identifier(id_type: str, value: str) -> tuple[str, str]:
    """Return a canonical ``(type, value)`` pair.

    Raises:
        ValueError: when the value is empty or fails validation for a strict
            type (email, domain, IP address).
    """
    raw_type = (id_type or "").strip().lower()
    kind = TYPE_ALIASES.get(raw_type, raw_type)
    if kind not in IDENTIFIER_TYPES:
        raise ValueError(
            f"unsupported identifier type '{id_type}'. "
            f"Supported: {', '.join(sorted(IDENTIFIER_TYPES))}"
        )

    text = (value or "").strip()
    if not text:
        raise ValueError("identifier value is empty")

    if kind == "pgp":
        compact = re.sub(r"[\s:]", "", text).upper()
        hex_only = re.sub(r"[^A-F0-9]", "", compact)
        if len(hex_only) >= 32 and hex_only == compact:
            return kind, hex_only
        # Demonstration fingerprints (non-hex placeholders) are preserved
        # verbatim so seeded scenarios remain comparable.
        return kind, compact

    if kind == "email":
        email = text.lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise ValueError(f"invalid email address: {text}")
        return kind, email

    if kind == "domain":
        domain = re.sub(r"^https?://", "", text.lower()).split("/")[0].strip(".")
        if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", domain):
            raise ValueError(f"invalid domain: {text}")
        return kind, domain

    if kind == "ip":
        host = text.split("/")[0].strip()
        if host.count(":") == 1 and "." in host:
            host = host.split(":")[0]
        try:
            return kind, str(ipaddress.ip_address(host))
        except ValueError as exc:
            raise ValueError(f"invalid IP address: {text}") from exc

    if kind == "wallet":
        wallet = re.sub(r"\s+", "", text)
        if len(wallet) < 8:
            raise ValueError(
                "wallet identifier is too short (minimum 8 characters); "
                "provide the full on-chain address"
            )
        if not re.fullmatch(r"[A-Za-z0-9:_-]+", wallet):
            raise ValueError(f"invalid wallet identifier: {text}")
        return kind, wallet

    if kind == "cert":
        return kind, re.sub(r"\s+", "", text).lower()

    if kind == "url":
        return kind, text.lower()

    return kind, text


def validate_identifier(id_type: str, value: str) -> tuple[str, str]:
    """Alias kept for callers that prefer an explicit validation name."""
    return normalize_identifier(id_type, value)
