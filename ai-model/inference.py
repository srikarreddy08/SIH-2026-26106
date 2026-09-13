"""
Inference bridge for the trained phishing-detection pipeline.

backend/main.py does `from inference import predict_email` with the
ai-model folder added directly to sys.path (see main.py's sys.path
setup) -- this module is what makes that import work.

Why this file needs to exist at all
------------------------------------
train_model.py builds its TfidfVectorizer as:
    TfidfVectorizer(preprocessor=clean_text, ...)
and then joblib.dump()s the fitted pipeline. joblib/pickle stores a
*reference* to clean_text (its module + name), not the function body.
Since train_model.py was run directly as a script, that reference was
recorded as `__main__.clean_text`. Loading the pipeline from anywhere
else (a FastAPI app started via uvicorn, a test runner, this module
itself) fails with:
    AttributeError: Can't get attribute 'clean_text' on <module '__main__' ...>
because whatever process is running doesn't have a `clean_text` in
ITS `__main__` module.

Fix: reproduce clean_text here byte-for-byte and register it into
sys.modules["__main__"] before loading the model, so the unpickler
finds exactly what it's looking for no matter how this process was
started. This is done once, at import time.
"""

import os
import re
import sys

import joblib

# --- Exact copy of the cleaning logic from train_model.py's clean_text ---
# Must stay in sync with train_model.py if that file is ever retrained/edited.
_URL_RE = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_NUMBER_RE = re.compile(r"\b\d[\d,]*\.?\d*\b")
_NON_ALNUM_RE = re.compile(r"[^a-zA-Z0-9\s!$?%]")
_MULTI_SPACE_RE = re.compile(r"\s+")
_REPEATED_CHAR_RE = re.compile(r"(.)\1{3,}")


def clean_text(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)

    text = _HTML_TAG_RE.sub(" ", text)
    text = _URL_RE.sub(" urltoken ", text)
    text = _EMAIL_RE.sub(" emailtoken ", text)
    text = _NUMBER_RE.sub(" numtoken ", text)
    text = _REPEATED_CHAR_RE.sub(r"\1\1\1", text)
    text = text.lower()
    text = _NON_ALNUM_RE.sub(" ", text)
    text = _MULTI_SPACE_RE.sub(" ", text).strip()
    return text


# Register under the exact name the pickled pipeline expects, regardless
# of what "__main__" actually is in this process (uvicorn, pytest, etc).
sys.modules["__main__"].clean_text = clean_text

# Resolve the model path relative to THIS file, not the process's current
# working directory, so it loads correctly no matter where the server
# is launched from.
_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "model",
    "phishing_tfidf_logreg_pipeline.joblib",
)

# Loaded once at import time and reused for every request.
_pipeline = joblib.load(_MODEL_PATH)


def predict_email(text: str) -> dict:
    """Score a single email's combined subject+body text.

    Returns {"label": 0|1, "phishing_probability": float}. label 1 means
    the model classifies the email as phishing.
    """
    proba = float(_pipeline.predict_proba([text])[0, 1])
    label = int(proba >= 0.5)
    return {"label": label, "phishing_probability": proba}
