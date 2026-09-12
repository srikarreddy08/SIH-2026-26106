import email
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