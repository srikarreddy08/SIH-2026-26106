from inference import predict_email


test_emails = [
    {
        "name": "Phishing",
        "text": """
        URGENT! Your bank account will be permanently suspended.
        Click the link immediately and verify your password and account details.
        """
    },
    {
        "name": "Normal",
        "text": """
        Hi team,

        The meeting has been scheduled for tomorrow at 10 AM.
        Please review the attached project documents before the meeting.

        Regards,
        Rahul
        """
    },
    {
        "name": "Credential Scam",
        "text": """
        Your Microsoft account requires immediate verification.
        Confirm your username and password within 24 hours to prevent account closure.
        """
    }
]


for email in test_emails:
    result = predict_email(email["text"])

    print("\n-------------------------")
    print("Email:", email["name"])
    print("Prediction:", result["prediction"])
    print("Phishing Probability:", result["phishing_probability"])
    print("Risk Level:", result["risk_level"])
    print("Indicators:", result["indicators"])