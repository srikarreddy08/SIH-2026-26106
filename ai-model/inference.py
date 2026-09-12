from pathlib import Path
import joblib

from indicators import detect_indicators


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model" / "email_threat_model.joblib"

model = joblib.load(MODEL_PATH)


def predict_email(email_text):

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

    indicators = detect_indicators(email_text)
    indicator_messages = [item["indicator"] for item in indicators]

    return {
    "prediction": prediction,
    "phishing_probability": round(float(phishing_probability), 4),
    "risk_level": risk_level,
    "indicators": indicators,
    "indicator_count": len(indicators),
    "indicator_messages": indicator_messages
}