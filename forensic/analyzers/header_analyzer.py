import ipaddress
import re
import requests


def is_public_ip(ip: str) -> bool:
    """Validate that the string is a valid, publicly routable IP address."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def extract_ips(msg):
    """Pull all IPs from Received headers, then filter to only public ones."""
    received_headers = msg.get_all("received") or []
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    extracted_ips = []
    for header in received_headers:
        extracted_ips.extend(re.findall(ip_pattern, header))

    seen = set()
    candidate_ips = [ip for ip in extracted_ips if not (ip in seen or seen.add(ip))]
    public_ips = [ip for ip in candidate_ips if is_public_ip(ip)]

    return candidate_ips, public_ips


def get_received_hops(msg):
    """Return each Received header as an ordered hop record: the raw header
    text plus the first public IP found in it. Order matches the headers as
    they appear on the message (newest hop first) -- this is exactly the
    shape the geolocation engine's relay-chain analysis and hop-path map
    expect (see geolocation.find_trust_boundary / build_hop_path)."""
    received_headers = msg.get_all("received") or []
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    hops = []
    for header in received_headers:
        ips_in_header = re.findall(ip_pattern, header)
        public_ip = next((ip for ip in ips_in_header if is_public_ip(ip)), None)
        hops.append({"raw": header, "ip": public_ip})

    return hops


def get_location(ip: str):
    """Retrieve full location data from ipwho.is for a public IP."""
    try:
        response = requests.get(f"https://ipwho.is/{ip}", timeout=5)
        data = response.json()

        if not data.get("success", True):
            print("DEBUG - ipwho.is error:", data)
            return None

        return {
            "query_ip": ip,
            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "region": data.get("region"),
            "city": data.get("city"),
            "zip": data.get("postal"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "timezone": (data.get("timezone") or {}).get("id"),
            "isp": (data.get("connection") or {}).get("isp"),
            "org": (data.get("connection") or {}).get("org")
        }
    except requests.RequestException as e:
        print("DEBUG - geolocation error:", e)
        return None


def locate_sender(public_ips):
    """Try each public IP (oldest hop first) until one resolves to a location."""
    for ip in reversed(public_ips):
        loc = get_location(ip)
        if loc:
            return loc
    return None


def check_authentication(msg):
    """Check SPF, DKIM, and DMARC results from email headers."""
    auth_results = msg.get("Authentication-Results", "")

    def extract_result(text, keyword):
        match = re.search(rf"{keyword}=(\w+)", text, re.IGNORECASE)
        return match.group(1).lower() if match else "not_found"

    return {
        "spf": extract_result(auth_results, "spf"),
        "dkim": extract_result(auth_results, "dkim"),
        "dmarc": extract_result(auth_results, "dmarc")
    }
KNOWN_RELAY_ISPS = [
    "google", "microsoft", "outlook", "amazon", "yahoo",
    "mailchimp", "sendgrid", "mailgun"
]


def classify_ip_source(location):
    """Label whether this IP looks like a known relay/provider or a real origin."""
    if not location:
        return "unknown"

    isp = (location.get("isp") or "").lower()
    org = (location.get("org") or "").lower()

    for keyword in KNOWN_RELAY_ISPS:
        if keyword in isp or keyword in org:
            return "likely_relay_server"

    return "likely_origin"