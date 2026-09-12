from inference import predict_email


email_text = """
Dear customer,

Your account has been temporarily suspended.
Please verify your password immediately to restore access.

Click the link below to verify your account.
"""


result = predict_email(email_text)

print("\nAI ANALYSIS")
print("======================")
print("Prediction:", result["prediction"])
print("Phishing Probability:", result["phishing_probability"])
print("Risk Level:", result["risk_level"])
print("Indicators:", result["indicators"])