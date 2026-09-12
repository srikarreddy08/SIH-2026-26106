from pathlib import Path
import joblib


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model" / "email_threat_model.joblib"

model = joblib.load(MODEL_PATH)


def predict_email(email_text):
    """
    Predict whether an email is suspicious/phishing.

    Returns:
        dict containing prediction, probability and risk level.
    """

    probabilities = model.predict_proba([email_text])[0]
    classes = model.classes_

    phishing_probability = probabilities[list(classes).index(1)]

    if phishing_probability >= 0.80:
        risk_level = "HIGH"
    elif phishing_probability >= 0.50:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    prediction = 1 if phishing_probability >= 0.50 else 0

    return {
        "prediction": prediction,
        "phishing_probability": round(float(phishing_probability), 4),
        "risk_level": risk_level
    }

if __name__ == "__main__":
    email = """
    URGENT: Your account has been suspended.
    Please verify your password immediately.
    """

    result = predict_email(email)

    print(result)