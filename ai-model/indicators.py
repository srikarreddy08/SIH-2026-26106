import re


SUSPICIOUS_PATTERNS = {
    "urgent_language": [
        "urgent",
        "immediately",
        "act now",
        "as soon as possible",
        "within 24 hours"
    ],

    "account_threat": [
        "account suspended",
        "account will be closed",
        "account blocked",
        "permanently suspended"
    ],

    "credential_request": [
        "password",
        "verify your password",
        "login details",
        "username and password",
        "credentials"
    ],

    "financial_request": [
        "bank account",
        "credit card",
        "payment",
        "wire transfer",
        "account number"
    ]
}


def detect_indicators(email_text):
    text = email_text.lower()

    detected = []

    for category, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            if re.search(re.escape(pattern), text):
                detected.append({
                    "category": category,
                    "indicator": pattern
                })

    return detected