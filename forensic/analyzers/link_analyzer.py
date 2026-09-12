import re


def extract_urls(msg):
    """Pull all URLs out of the email body (plain text and HTML parts)."""
    urls = []

    if msg.is_multipart():
        parts = msg.walk()
    else:
        parts = [msg]

    for part in parts:
        content_type = part.get_content_type()
        if content_type in ("text/plain", "text/html"):
            try:
                body = part.get_payload(decode=True).decode(errors="ignore")
            except Exception:
                continue

            url_pattern = r'https?://[^\s"\'<>]+'
            urls.extend(re.findall(url_pattern, body))

    # Deduplicate while preserving order
    seen = set()
    unique_urls = [u for u in urls if not (u in seen or seen.add(u))]
    return unique_urls


def extract_domain(url: str) -> str:
    """Pull just the domain out of a full URL."""
    match = re.search(r'https?://([^/]+)/?', url)
    return match.group(1) if match else url