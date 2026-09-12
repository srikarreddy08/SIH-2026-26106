from pathlib import Path

import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix


# --------------------------------
# PATHS
# --------------------------------

BASE_DIR = Path(__file__).resolve().parent

DATA_PATH = BASE_DIR / "data" / "processed.csv"
MODEL_DIR = BASE_DIR / "model"
MODEL_PATH = MODEL_DIR / "email_threat_model.joblib"


# --------------------------------
# LOAD DATA
# --------------------------------

df = pd.read_csv(DATA_PATH)

X = df["text_combined"]
y = df["label"]


# --------------------------------
# TRAIN / TEST SPLIT
# --------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))


# --------------------------------
# TF-IDF + LOGISTIC REGRESSION
# --------------------------------

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            max_features=20000,
            ngram_range=(1, 2)
        )
    ),

    (
        "classifier",
        LogisticRegression(
            max_iter=1000
        )
    )
])


# --------------------------------
# TRAIN
# --------------------------------

print("\nTraining model...")

model.fit(X_train, y_train)

print("Training complete!")


# --------------------------------
# EVALUATE
# --------------------------------

predictions = model.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, predictions))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))


# --------------------------------
# SAVE MODEL
# --------------------------------

MODEL_DIR.mkdir(exist_ok=True)

joblib.dump(model, MODEL_PATH)

print("\nModel saved to:")
print(MODEL_PATH)