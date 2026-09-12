import email


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