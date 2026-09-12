from pathlib import Path
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score


BASE_DIR = Path(__file__).resolve().parent

DATA_PATH = BASE_DIR / "data" / "processed.csv"
MODEL_PATH = BASE_DIR / "model" / "email_threat_model.joblib"


# Load dataset
df = pd.read_csv(DATA_PATH)

X = df["text_combined"]
y = df["label"]


# Create the same test split used during training
_, X_test, _, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# Load trained model
model = joblib.load(MODEL_PATH)


# Predict test set
predictions = model.predict(X_test)


# Evaluate
accuracy = accuracy_score(y_test, predictions)

print("MODEL EVALUATION")
print("================")

print(f"\nAccuracy: {accuracy:.4f}")

print("\nClassification Report:")
print(classification_report(y_test, predictions))

print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions))