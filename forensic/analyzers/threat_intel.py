import re

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click"]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"
]


def is_ip_literal_url(domain: str) -> bool:
    """Check if a 'domain' is actually a raw IP address - a major red flag."""
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return bool(re.match(ip_pattern, domain))


def has_suspicious_tld(domain: str) -> bool:
    """Check if domain uses a TLD commonly abused for free/disposable domains."""
    return any(domain.lower().endswith(tld) for tld in SUSPICIOUS_TLDS)


def is_url_shortener(domain: str) -> bool:
    """Check if domain is a known URL shortening service (hides real destination)."""
    return domain.lower() in URL_SHORTENERS


def analyze_domain(domain: str):
    """Run all heuristic checks on a single domain and return a risk assessment."""
    flags = []

    if is_ip_literal_url(domain):
        flags.append("uses_raw_ip_address")
    if has_suspicious_tld(domain):
        flags.append("suspicious_free_tld")
    if is_url_shortener(domain):
        flags.append("url_shortener_hides_destination")

    risk_score = len(flags) * 30  # simple scoring: 30 points per red flag

    return {
        "domain": domain,
        "risk_score": min(risk_score, 100),
        "flags": flags,
        "risk_level": "high" if risk_score >= 60 else "medium" if risk_score >= 30 else "low"
    }


def analyze_all_domains(domains: list):
    """Run heuristic analysis on every domain found in the email."""
    return [analyze_domain(d) for d in domains]