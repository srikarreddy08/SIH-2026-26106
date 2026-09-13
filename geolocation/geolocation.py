"""
Geolocation-based risk scoring for email forensics.

Three checks, each grounded in a real detection concept rather than
guesswork:

1. domain_mismatch_check   - does the sender's claimed domain resolve
                              to a location consistent with where the
                              mail actually came from?
2. timeline_consistency_check - do the Received-header timestamps make
                              sense (monotonic, no huge unexplained
                              gaps)? A known technique for spotting
                              forged/inserted headers.
3. asn_reputation_check    - is the sending IP on a residential/cloud/
                              VPN network rather than legitimate mail
                              infrastructure?

IP and domain lookups go through ipwho.is (free, no key needed for
basic use). Network calls are isolated behind small resolver functions
so they can be swapped for a mock in tests, or for a paid provider
(ipinfo.io, MaxMind) later without touching the scoring logic.
"""

import socket
from email.utils import parsedate_to_datetime

import requests


# --------------------------------
# CACHING
# ipwho.is has rate limits on the free tier, and the same relay IPs
# (Gmail, Outlook servers) repeat across many emails - cache in memory
# for the life of the process. Swap for a Redis/disk cache in prod.
# --------------------------------

_geo_cache = {}


def geolocate_ip(ip: str) -> dict:
    """Looks up country/city/ASN/org for an IP via ipwho.is.
    Returns {} on failure so callers can degrade gracefully instead
    of crashing on a bad lookup or rate limit."""
    if not ip:
        return {}
    if ip in _geo_cache:
        return _geo_cache[ip]

    try:
        response = requests.get(f"https://ipwho.is/{ip}", timeout=5)
        data = response.json()
        if not data.get("success", True):
            result = {}
        else:
            result = {
                "country": data.get("country"),
                "country_code": data.get("country_code"),
                "city": data.get("city"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "asn": data.get("connection", {}).get("asn"),
                "org": data.get("connection", {}).get("org") or data.get("connection", {}).get("isp"),
            }
    except (requests.RequestException, ValueError):
        result = {}

    _geo_cache[ip] = result
    return result


def resolve_domain_ip(domain: str) -> str:
    """Resolves a sending domain to an IP as a stand-in for 'where
    this domain's mail infrastructure is expected to be'. Not perfect
    (A record, not MX-specific), but a workable, dependency-free proxy.
    Returns None on failure."""
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, UnicodeError):
        return None


def reverse_dns(ip: str) -> str:
    """Returns the PTR (reverse DNS) hostname for an IP, or None."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


# --------------------------------
# CHECK 1: Domain mismatch
# --------------------------------

def domain_mismatch_check(from_domain: str, sending_ip: str) -> dict:
    """Compares the country the sender's domain resolves to against
    the country the mail actually came from. A mismatch doesn't prove
    spoofing on its own (legitimate cloud mail providers route through
    many countries) but combined with other signals it's a solid
    contributor to the overall score."""
    reasons = []
    score = 0

    domain_ip = resolve_domain_ip(from_domain) if from_domain else None
    domain_geo = geolocate_ip(domain_ip) if domain_ip else {}
    sender_geo = geolocate_ip(sending_ip)

    domain_country = domain_geo.get("country_code")
    sender_country = sender_geo.get("country_code")

    if domain_country and sender_country and domain_country != sender_country:
        score += 25
        reasons.append(
            f"Domain '{from_domain}' resolves to {domain_country}, "
            f"but mail was sent from {sender_country}"
        )
    elif not domain_country or not sender_country:
        # Not enough data to compare - don't penalize, just note it
        reasons.append("Could not fully resolve domain or sender location for comparison")

    return {
        "score": score,
        "reasons": reasons,
        "domain_geo": domain_geo,
        "sender_geo": sender_geo,
    }


# --------------------------------
# CHECK 2: Timeline consistency
# --------------------------------

def timeline_consistency_check(received_hops: list, max_gap_hours: int = 6) -> dict:
    """Received headers should show non-decreasing timestamps as you
    read from the oldest (bottom) hop to the newest (top) hop, since
    each hop is stamped when that server received the message from
    the previous one. Real anomalies to catch:

    - Timestamps that go BACKWARD (a strong sign of a forged/inserted
      header - whoever forged it didn't bother keeping times consistent)
    - Unexplained multi-hour gaps between consecutive hops (could be a
      queued spam run, a compromised relay, or a spoofed header)

    Note: near-instant hops (even across countries) are NORMAL for
    real internet routing - that alone is not suspicious."""
    reasons = []
    score = 0

    timestamps = []
    for hop in received_hops:
        raw = hop.get("raw", "")
        try:
            date_part = raw.split(";")[-1].strip()
            timestamps.append(parsedate_to_datetime(date_part))
        except (ValueError, IndexError, TypeError):
            continue

    if len(timestamps) < 2:
        return {"score": 0, "reasons": ["Not enough timestamped hops to check timeline"]}

    # Received headers are newest-first, so reverse to go oldest -> newest
    timestamps = list(reversed(timestamps))

    for earlier, later in zip(timestamps, timestamps[1:]):
        delta_seconds = (later - earlier).total_seconds()
        if delta_seconds < 0:
            score += 30
            reasons.append("Hop timestamps go backward in time - likely a forged header")
        elif delta_seconds > max_gap_hours * 3600:
            score += 15
            hours = round(delta_seconds / 3600, 1)
            reasons.append(f"Unexplained {hours}h gap between two relay hops")

    return {"score": min(score, 100), "reasons": reasons}


# --------------------------------
# CHECK 3: ASN / hosting reputation
# --------------------------------

# Seed list - extend with real ASN org name substrings relevant to
# your threat model. This is intentionally a soft/simple string match
# for the hackathon; a production version would use an ASN type feed.
SUSPICIOUS_ORG_KEYWORDS = (
    "vpn", "proxy", "tor exit", "digitalocean", "linode", "ovh",
    "amazon", "aws", "google cloud", "azure", "hosting"
)

# Note: cloud providers appear here because legitimate transactional
# mail rarely originates directly from a raw cloud IP for a bank/gov
# domain - it's a soft signal, not a verdict. A real Gmail/Outlook
# relay IP won't match these, since ipwho.is reports it as Google/MS.
LEGITIMATE_MAIL_ORGS = ("google", "microsoft", "outlook", "yahoo", "proton")


def asn_reputation_check(sending_ip: str) -> dict:
    reasons = []
    score = 0

    geo = geolocate_ip(sending_ip)
    org = (geo.get("org") or "").lower()

    is_legit_mail_org = any(keyword in org for keyword in LEGITIMATE_MAIL_ORGS)
    is_suspicious_org = any(keyword in org for keyword in SUSPICIOUS_ORG_KEYWORDS)

    if is_suspicious_org and not is_legit_mail_org:
        score += 30
        reasons.append(f"Sending IP belongs to '{geo.get('org', 'unknown')}' - hosting/VPN network, not typical mail infrastructure")

    ptr = reverse_dns(sending_ip)
    if ptr is None:
        score += 10
        reasons.append("Sending IP has no reverse DNS (PTR) record - common for misconfigured or malicious senders")

    return {"score": min(score, 100), "reasons": reasons, "org": geo.get("org"), "ptr": ptr}


# --------------------------------
# COMBINE: overall geo risk score
# Same pattern as header_rules.score_headers() - one capped 0-100
# score plus a flat reason list for the forensic report.
# --------------------------------

def score_geolocation(from_domain: str, sending_ip: str, received_hops: list) -> dict:
    domain = domain_mismatch_check(from_domain, sending_ip)
    timeline = timeline_consistency_check(received_hops)
    asn = asn_reputation_check(sending_ip)

    total_score = min(100, domain["score"] + timeline["score"] + asn["score"])
    reasons = domain["reasons"] + timeline["reasons"] + asn["reasons"]

    return {
        "geo_risk_score": total_score,
        "domain_check": domain,
        "timeline_check": timeline,
        "asn_check": asn,
        "reasons": reasons,
    }
