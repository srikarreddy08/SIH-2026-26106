import email
import email.utils
import re


def parse_email(contents: bytes):
    """Parse raw email bytes into a message object and extract basic fields."""
    msg = email.message_from_bytes(contents)
    basic_info = {
        "from": msg.get("from"),
        "to": msg.get("to"),
        "subject": msg.get("subject"),
        "date": msg.get("date"),
    }
    return basic_info, msg


def extract_body_text(msg) -> str:
    """Pull the plain-text body out of the email, for feeding to the AI model."""
    if msg.is_multipart():
        parts = msg.walk()
    else:
        parts = [msg]

    for part in parts:
        if part.get_content_type() == "text/plain":
            try:
                return part.get_payload(decode=True).decode(errors="ignore")
            except Exception:
                continue

    # Fall back to HTML body (stripped of tags) if no plain-text part exists
    for part in ([msg] if not msg.is_multipart() else msg.walk()):
        if part.get_content_type() == "text/html":
            try:
                html = part.get_payload(decode=True).decode(errors="ignore")
                return re.sub(r"<[^>]+>", " ", html)
            except Exception:
                continue

    return ""


def extract_from_domain(from_header: str) -> str:
    """Pull just the domain out of the email's From header, e.g.
    '"Alice" <alice@example.com>' -> 'example.com'. Used by the
    geolocation engine to compare the claimed sending domain against
    where the mail actually came from."""
    if not from_header:
        return None

    _, address = email.utils.parseaddr(from_header)
    if "@" not in address:
        return None

    return address.rsplit("@", 1)[-1].lower()