from pathlib import Path
import pandas as pd

# Find the folder where this script is located
BASE_DIR = Path(__file__).resolve().parent

# Load dataset
csv_path = BASE_DIR / "phishing_email.csv"
df = pd.read_csv(csv_path)


# -----------------------------
# BASIC INFORMATION
# -----------------------------

print("Dataset shape:")
print(df.shape)

print("\nColumns:")
print(df.columns.tolist())


# -----------------------------
# LABEL DISTRIBUTION
# -----------------------------

print("\nLabel distribution:")
print(df["label"].value_counts())

print("\nLabel percentages:")
print(df["label"].value_counts(normalize=True) * 100)


# -----------------------------
# MISSING VALUES
# -----------------------------

print("\nMissing values:")
print(df.isnull().sum())


# -----------------------------
# EMPTY EMAILS
# -----------------------------

empty_emails = (
    df["text_combined"]
    .fillna("")
    .str.strip()
    .eq("")
    .sum()
)

print("\nEmpty emails:")
print(empty_emails)


# -----------------------------
# DUPLICATES
# -----------------------------

duplicate_count = df["text_combined"].duplicated().sum()

print("\nDuplicate emails:")
print(duplicate_count)


# -----------------------------
# EMAIL LENGTH
# -----------------------------

email_lengths = df["text_combined"].str.len()

print("\nEmail length statistics:")
print(email_lengths.describe())