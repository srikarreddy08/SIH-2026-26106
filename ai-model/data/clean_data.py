from pathlib import Path
import pandas as pd
import re

BASE_DIR = Path(__file__).resolve().parent

# Load original dataset
df = pd.read_csv(BASE_DIR / "phishing_email.csv")

# Remove missing/empty emails
df = df.dropna(subset=["text_combined"])
df["text_combined"] = df["text_combined"].astype(str)
df = df[df["text_combined"].str.strip() != ""]

# Remove duplicate emails
df = df.drop_duplicates(subset=["text_combined"])


# Text cleaning
def clean_email(text):
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    text = text.strip()
    return text


df["text_combined"] = df["text_combined"].apply(clean_email)

# Save processed dataset
df.to_csv(BASE_DIR / "processed.csv", index=False)

print("Cleaning complete!")
print("Processed dataset shape:", df.shape)
print("\nLabels:")
print(df["label"].value_counts())
print("\nSaved to:", BASE_DIR / "processed.csv")