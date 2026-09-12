from pathlib import Path
import joblib


# -----------------------------
# LOAD TRAINED MODEL
# -----------------------------

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model" / "email_threat_model.joblib"

model = joblib.load(MODEL_PATH)


# -----------------------------
# TEST EMAIL
# -----------------------------

email = """
URGENT: Your account has been suspended.
Please verify your password immediately by clicking the link below.
Failure to verify your account will result in permanent suspension.
"""


# -----------------------------
# PREDICTION
# -----------------------------

prediction = model.predict([email])[0]

probabilities = model.predict_proba([email])[0]
classes = model.classes_


# -----------------------------
# DISPLAY RESULT
# -----------------------------

print("Prediction:", prediction)

print("\nClass probabilities:")

for label, probability in zip(classes, probabilities):
    print(f"Class {label}: {probability:.2%}")


# Probability of phishing (class 1)
phishing_probability = probabilities[list(classes).index(1)]

print(f"\nPhishing probability: {phishing_probability:.2%}")


# -----------------------------
# RISK LEVEL
# -----------------------------

if phishing_probability >= 0.80:
    risk = "HIGH"
elif phishing_probability >= 0.50:
    risk = "MEDIUM"
else:
    risk = "LOW"

print("Risk level:", risk)