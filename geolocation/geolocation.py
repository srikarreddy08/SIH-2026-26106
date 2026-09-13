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


# ipwho.is only returns VPN/proxy/Tor/hosting flags when explicitly
# requested via the "fields" parameter (dot notation for nested
# fields) - they are NOT in the default payload.
IPWHO_FIELDS = (
    "ip,success,country,country_code,city,latitude,longitude,"
    "connection.asn,connection.org,connection.isp,"
    "security.vpn,security.proxy,security.tor,security.hosting"
)


def geolocate_ip(ip: str) -> dict:
    """Looks up country/city/ASN/org AND real VPN/proxy/Tor/hosting
    flags for an IP via ipwho.is. Returns {} on failure so callers can
    degrade gracefully instead of crashing on a bad lookup or rate limit."""
    if not ip:
        return {}
    if ip in _geo_cache:
        return _geo_cache[ip]

    try:
        response = requests.get(
            f"https://ipwho.is/{ip}", params={"fields": IPWHO_FIELDS}, timeout=5
        )
        data = response.json()
        if not data.get("success", True):
            result = {}
        else:
            connection = data.get("connection", {}) or {}
            security = data.get("security", {}) or {}
            org = connection.get("org") or connection.get("isp")
            is_hosting = security.get("hosting", False)

            result = {
                "country": data.get("country"),
                "country_code": data.get("country_code"),
                "city": data.get("city"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "asn": connection.get("asn"),
                "org": org,
                # Real flags from the provider, not string-guessing on org name
                "is_vpn": security.get("vpn", False),
                "is_proxy": security.get("proxy", False),
                "is_tor": security.get("tor", False),
                "is_hosting": is_hosting,
                "network_type": "Datacenter" if is_hosting else ("Residential/ISP" if org else "Unknown"),
                # City-level IP geolocation is inherently approximate - if we
                # have a city AND an org name, call it higher confidence;
                # country-only data is marked lower confidence rather than
                # presenting an unverified city as fact.
                "location_confidence": "High" if (data.get("city") and org) else ("Medium" if data.get("country") else "Low"),
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
    """Uses ipwho.is's real vpn/proxy/tor/hosting flags where available
    (accurate), falling back to org-name keyword matching only if the
    security fields are missing (e.g. rate-limited or older cached
    entry) - keeps working in degraded mode instead of failing silently."""
    reasons = []
    score = 0

    geo = geolocate_ip(sending_ip)
    org = (geo.get("org") or "").lower()
    has_security_flags = "is_vpn" in geo

    if has_security_flags:
        if geo.get("is_tor"):
            score += 40
            reasons.append("Sending IP is a known Tor exit node")
        if geo.get("is_vpn"):
            score += 25
            reasons.append("Sending IP is a known VPN endpoint")
        if geo.get("is_proxy"):
            score += 25
            reasons.append("Sending IP is a known proxy")
        if geo.get("is_hosting") and not any(k in org for k in LEGITIMATE_MAIL_ORGS):
            score += 15
            reasons.append(f"Sending IP is on datacenter/hosting infrastructure ('{geo.get('org', 'unknown')}'), not typical mail infrastructure")
    else:
        # Degraded fallback: weaker signal, only used if the API didn't
        # return security fields for this lookup (e.g. rate limited).
        is_legit_mail_org = any(keyword in org for keyword in LEGITIMATE_MAIL_ORGS)
        is_suspicious_org = any(keyword in org for keyword in SUSPICIOUS_ORG_KEYWORDS)
        if is_suspicious_org and not is_legit_mail_org:
            score += 20
            reasons.append(f"Sending IP belongs to '{geo.get('org', 'unknown')}' (org-name heuristic - security flags unavailable)")

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


# --------------------------------
# HOP PATH FOR MAP DISPLAY
# Turns the raw Received-header hop list into an ordered, geolocated
# path the frontend can drop straight onto a map - markers + a line
# connecting them in relay order.
# --------------------------------

def build_hop_path(received_hops: list, flagged_ips: set = None) -> list:
    """Returns hops oldest -> newest (the actual relay order), each
    with coordinates and a flag for whether that hop contributed to
    a risk score - so the frontend can color it differently on the map.
    Hops with no resolvable IP or failed geolocation are skipped
    rather than breaking the path."""
    flagged_ips = flagged_ips or set()
    path = []

    # Received headers are newest-first in the raw email; reverse so
    # the map draws the path in the order the mail actually traveled.
    for hop in reversed(received_hops):
        ip = hop.get("ip")
        if not ip:
            continue
        geo = geolocate_ip(ip)
        if not geo.get("latitude") or not geo.get("longitude"):
            continue
        path.append({
            "ip": ip,
            "country": geo.get("country"),
            "city": geo.get("city"),
            "lat": geo.get("latitude"),
            "lon": geo.get("longitude"),
            "org": geo.get("org"),
            "flagged": ip in flagged_ips,
        })

    return path


# --------------------------------
# SOURCE INTELLIGENCE CARD
# Formats one IP's lookup into the exact display shape for a frontend
# "source intelligence" panel. Pure formatting - no new lookups beyond
# geolocate_ip(), so it's cheap to call right before rendering.
# --------------------------------

def build_source_intelligence(ip: str) -> dict:
    geo = geolocate_ip(ip)
    if not geo:
        return {
            "ip_address": ip,
            "country": "Unknown",
            "city": "Unknown",
            "asn": "Unknown",
            "network_type": "Unknown",
            "vpn_proxy": "Unknown",
            "tor": "Unknown",
            "location_confidence": "Low",
        }

    vpn_or_proxy = geo.get("is_vpn") or geo.get("is_proxy")
    return {
        "ip_address": ip,
        "country": geo.get("country") or "Unknown",
        "city": geo.get("city") or "Unknown",
        "asn": geo.get("asn") or "Unknown",
        "network_type": geo.get("network_type", "Unknown"),
        "vpn_proxy": "Possible" if vpn_or_proxy else "Not detected",
        "tor": "Detected" if geo.get("is_tor") else "Not detected",
        "location_confidence": geo.get("location_confidence", "Low"),
    }