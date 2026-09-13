"""
================================================================================
PHISHING EMAIL DETECTION - MODEL TRAINING PIPELINE
TF-IDF + Logistic Regression (compared against Linear SVM and Naive Bayes)
================================================================================

INPUT
-----
final_train.csv   columns: text, label, source   (label: 0=legit, 1=phishing/malicious)
final_test.csv    same schema, fully independent held-out set

These are the outputs of the dataset-engineering step (leakage-checked,
template-deduplicated). This script does NOT re-derive them; it assumes
final_train.csv and final_test.csv already contain no train/test overlap.

WHAT THIS SCRIPT DOES
----------------------
1. Loads train/test CSVs.
2. Cleans text with a stateless NLP preprocessor (no corpus statistics used,
   so it cannot leak information between folds or between train/test).
3. Builds a single sklearn Pipeline per candidate model:
       TfidfVectorizer  ->  Classifier
   so the vectorizer's vocabulary/IDF weights are fit fresh every time the
   pipeline is fit -- never on data outside the current training split.
4. Cross-validates every candidate with a GROUP-AWARE, STRATIFIED K-fold:
       - "groups" = near-duplicate/template clusters computed on the
         TRAINING SET ONLY, so a spam template cannot land in both the
         training portion and the validation portion of the same fold.
       - "stratified" = class balance preserved across folds.
5. Tunes the chosen model (Logistic Regression) with GridSearchCV using the
   same leakage-safe CV splitter.
6. Refits the best pipeline on 100% of final_train.csv.
7. Touches final_test.csv exactly once, for a single final evaluation pass.
8. Prints a CV comparison table AND a held-out test comparison table across
   all candidate models, plus full metrics/plots for the final chosen model.
9. Saves the trained pipeline (vectorizer + classifier bundled together) to
   disk with joblib.

DATA-LEAKAGE SAFEGUARDS (see inline comments for exact locations)
-------------------------------------------------------------------
  [L1] Text cleaning is a pure per-row function -> safe regardless of where
       it runs, but it is wrapped as a sklearn Transformer and placed INSIDE
       the Pipeline anyway, so the whole pipeline is one fit/transform unit.
  [L2] TfidfVectorizer lives inside the Pipeline, not fit once up front, so
       cross_validate() and GridSearchCV() refit its vocabulary/IDF on ONLY
       each fold's training rows.
  [L3] Cross-validation uses StratifiedGroupKFold with template groups
       computed on the training set, preventing near-duplicate leakage
       between the train/validation portions of a fold.
  [L4] final_test.csv is loaded but never seen by .fit(); it is only ever
       passed to .transform()/.predict() of an already-fitted pipeline.
  [L5] Hyperparameter search (GridSearchCV) also uses the group-aware CV
       splitter, so hyperparameters are never chosen using test-set
       performance or using leaky folds.
"""

import re
import json
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import joblib

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.svm import LinearSVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline
from sklearn.model_selection import StratifiedGroupKFold, cross_validate, GridSearchCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, classification_report, RocCurveDisplay,
    precision_recall_fscore_support,
)
from sklearn.metrics.pairwise import cosine_similarity

warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

# ==============================================================================
# CONFIG
# ==============================================================================
SEED = 42
TRAIN_PATH = "final_train.csv"
TEST_PATH = "final_test.csv"
N_SPLITS = 5
NEAR_DUP_SIM_THRESHOLD = 0.85   # same threshold used at dataset-build time
MODEL_OUT_PATH = "phishing_tfidf_logreg_pipeline.joblib"
COMPARISON_CV_OUT = "model_comparison_cv.csv"
COMPARISON_TEST_OUT = "model_comparison_test.csv"
ROC_PLOT_OUT = "roc_curves.png"
CM_PLOT_OUT = "confusion_matrix.png"

np.random.seed(SEED)


# ==============================================================================
# STEP 1 -- LOAD DATA
# ==============================================================================
def load_data(train_path=TRAIN_PATH, test_path=TEST_PATH):
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    for name, df in [("train", train_df), ("test", test_df)]:
        assert {"text", "label", "source"}.issubset(df.columns), \
            f"{name} set missing required columns"
        assert set(df["label"].unique()).issubset({0, 1}), \
            f"{name} set has non-binary labels"
        assert df["text"].isnull().sum() == 0, f"{name} set has null text"

    print(f"Loaded train: {len(train_df)} rows  |  test: {len(test_df)} rows")
    print(f"Train class balance: {train_df['label'].value_counts(normalize=True).round(3).to_dict()}")
    print(f"Test  class balance: {test_df['label'].value_counts(normalize=True).round(3).to_dict()}")

    # [L4] final_test.csv is loaded here for later evaluation ONLY. It is not
    # touched again until the single evaluate_on_test() call at the end.
    return train_df, test_df


# ==============================================================================
# STEP 2 -- NLP / TOKENIZATION PIPELINE
# ==============================================================================
URL_RE = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
HTML_TAG_RE = re.compile(r"<[^>]+>")
NUMBER_RE = re.compile(r"\b\d[\d,]*\.?\d*\b")
NON_ALNUM_RE = re.compile(r"[^a-zA-Z0-9\s!$?%]")
MULTI_SPACE_RE = re.compile(r"\s+")
REPEATED_CHAR_RE = re.compile(r"(.)\1{3,}")  # e.g. "!!!!!!" or "soooo"


def clean_text(text: str) -> str:
    """
    Pure, stateless per-email cleaning function used as the TfidfVectorizer's
    `preprocessor`. It uses no corpus-level statistics (no vocabulary, no
    document frequencies) -- it looks at exactly one email at a time -- so
    running it before or inside the Pipeline makes no difference for leakage.
    It is kept inside the Pipeline (via `preprocessor=clean_text` below)
    purely so the whole model is one self-contained, shippable object.

    Design choices, specific to phishing/spam detection:
      - URLs / email addresses / raw numbers are NORMALIZED to placeholder
        tokens (urltoken / emailtoken / numtoken) rather than removed. The
        PRESENCE of a link or an embedded address is one of the strongest
        phishing signals; keeping literal domains as features would instead
        make the model memorize specific campaigns and generalize worse.
      - Elongated punctuation/letters ("!!!!!", "sooooo") are collapsed --
        common in scam/urgency language -- so TF-IDF doesn't fragment the
        vocabulary over cosmetic variants of the same signal.
      - Stopwords are handled by TfidfVectorizer(stop_words="english")
        downstream (no external corpus download required).
    """
    if not isinstance(text, str):
        text = str(text)

    text = HTML_TAG_RE.sub(" ", text)
    text = URL_RE.sub(" urltoken ", text)
    text = EMAIL_RE.sub(" emailtoken ", text)
    text = NUMBER_RE.sub(" numtoken ", text)
    text = REPEATED_CHAR_RE.sub(r"\1\1\1", text)
    text = text.lower()
    text = NON_ALNUM_RE.sub(" ", text)
    text = MULTI_SPACE_RE.sub(" ", text).strip()
    return text


class TextCleaner(BaseEstimator, TransformerMixin):
    """
    Thin sklearn-Transformer wrapper around clean_text so it can sit as an
    explicit Pipeline step. Stateless: fit() does nothing and stores nothing
    learned from data, so it is identical whether called on a CV training
    fold, a CV validation fold, or the held-out test set. [L1]
    """
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return [clean_text(t) for t in X]


def build_vectorizer():
    """
    TF-IDF tokenizer/vectorizer. Vocabulary + IDF weights are LEARNED
    parameters -- this is exactly the object that must never be fit on
    validation or test data, which is why it always lives inside a
    Pipeline in this script rather than being fit once globally. [L2]
    """
    return TfidfVectorizer(
        preprocessor=clean_text,
        token_pattern=r"(?u)\b\w\w+\b",
        ngram_range=(1, 2),
        stop_words="english",
        sublinear_tf=True,
        min_df=2,
        max_df=0.95,
        max_features=30000,
    )


# ==============================================================================
# STEP 3 -- LEAKAGE-SAFE GROUPING FOR CROSS-VALIDATION
# ==============================================================================
def build_near_duplicate_groups(texts, threshold=NEAR_DUP_SIM_THRESHOLD):
    """
    Clusters near-duplicate / template emails within the TRAINING SET ONLY,
    using cosine similarity over a throwaway TF-IDF representation (this
    vectorizer is used only to compute groups for CV splitting -- it is
    completely separate from, and discarded before, the modeling pipeline).

    The resulting group ids are passed to StratifiedGroupKFold so that a
    template family (e.g. many near-identical spam-campaign emails) cannot
    be split across the training and validation portions of the same fold.
    Without this, cross-validated scores would be optimistically biased,
    because the model would effectively be "tested" on near-copies of
    emails it just trained on within that fold. [L3]

    NOTE: this grouping is computed independently here (this script does not
    assume the upstream dataset-engineering step exported group ids), using
    the same method and threshold for consistency.
    """
    vec = TfidfVectorizer(
        preprocessor=clean_text, ngram_range=(1, 2), min_df=1, max_features=20000
    )
    X = vec.fit_transform(texts)
    n = X.shape[0]

    parent = list(range(n))

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    chunk = 800
    for start in range(0, n, chunk):
        end = min(start + chunk, n)
        sims = cosine_similarity(X[start:end], X)
        for i_local in range(end - start):
            i = start + i_local
            hits = np.where(sims[i_local] >= threshold)[0]
            for j in hits:
                if j != i:
                    union(i, int(j))

    groups = np.array([find(i) for i in range(n)])
    n_groups = len(set(groups.tolist()))
    print(f"Training-set near-duplicate grouping: {n} rows -> {n_groups} groups "
          f"(threshold={threshold})")
    return groups


# ==============================================================================
# STEP 4 -- CANDIDATE MODELS
# ==============================================================================
def build_candidate_pipelines():
    """
    All candidates share the exact same TF-IDF step definition (re-built
    fresh per pipeline so fitted state is never shared between them) and
    differ only in the classifier -- an apples-to-apples comparison.

    - Logistic Regression: primary choice (well-calibrated probabilities,
      fast, interpretable coefficients, standard baseline for TF-IDF text
      classification -- matches the task brief).
    - Linear SVM (LinearSVC): usually competitive-or-better raw accuracy on
      sparse high-dimensional TF-IDF data; wrapped in CalibratedClassifierCV
      so it can also produce probabilities for a fair ROC-AUC comparison.
    - Multinomial Naive Bayes: classic, very fast text-classification
      baseline; useful as a sanity-check lower/upper bound.
    - SGDClassifier(loss="log_loss"): logistic regression trained via SGD,
      included as a scalability reference (relevant if this were scaled to
      the full 500k-row feature dataset later).
    """
    pipelines = {
        "Logistic Regression": Pipeline([
            ("tfidf", build_vectorizer()),
            ("clf", LogisticRegression(
                max_iter=2000, class_weight="balanced", random_state=SEED
            )),
        ]),
        "Linear SVM (calibrated)": Pipeline([
            ("tfidf", build_vectorizer()),
            ("clf", CalibratedClassifierCV(
                LinearSVC(class_weight="balanced", random_state=SEED, max_iter=5000),
                cv=3,
            )),
        ]),
        "Multinomial Naive Bayes": Pipeline([
            ("tfidf", build_vectorizer()),
            ("clf", MultinomialNB()),
        ]),
        "SGD (log-loss)": Pipeline([
            ("tfidf", build_vectorizer()),
            ("clf", SGDClassifier(
                loss="log_loss", class_weight="balanced", random_state=SEED
            )),
        ]),
    }
    return pipelines


# ==============================================================================
# STEP 5 -- LEAKAGE-SAFE CROSS-VALIDATION
# ==============================================================================
def cross_validate_candidates(pipelines, X_train, y_train, groups):
    """
    StratifiedGroupKFold: stratified on y (class balance kept across folds)
    AND grouped (a template's rows never split across a fold's train/val).
    Every pipeline is refit from scratch on each fold's TRAINING portion
    only -- cross_validate() clones the estimator per fold internally, so
    the TfidfVectorizer's vocabulary/IDF is learned fresh each time. [L2][L3]
    """
    cv = StratifiedGroupKFold(n_splits=N_SPLITS, shuffle=True, random_state=SEED)
    scoring = {
        "accuracy": "accuracy",
        "precision": "precision",
        "recall": "recall",
        "f1": "f1",
        "roc_auc": "roc_auc",
    }

    rows = []
    for name, pipe in pipelines.items():
        print(f"Cross-validating: {name} ...")
        result = cross_validate(
            pipe, X_train, y_train,
            cv=cv, groups=groups,
            scoring=scoring,
            n_jobs=-1,
            return_train_score=False,
        )
        row = {"model": name}
        for metric in scoring:
            vals = result[f"test_{metric}"]
            row[f"{metric}_mean"] = vals.mean()
            row[f"{metric}_std"] = vals.std()
        rows.append(row)

    cv_df = pd.DataFrame(rows).set_index("model")
    return cv_df


# ==============================================================================
# STEP 6 -- HYPERPARAMETER TUNING (chosen model: Logistic Regression)
# ==============================================================================
def tune_logistic_regression(X_train, y_train, groups):
    """
    Small, deliberately bounded grid search over the TF-IDF n-gram range and
    the Logistic Regression regularization strength C. Uses the SAME
    group-aware, stratified CV splitter as above, so hyperparameters are
    chosen without ever touching final_test.csv and without the near-
    duplicate leakage that a plain KFold would allow. [L5]
    """
    pipe = Pipeline([
        ("tfidf", build_vectorizer()),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED)),
    ])

    param_grid = {
        "tfidf__ngram_range": [(1, 1), (1, 2)],
        "clf__C": [0.1, 1.0, 3.0, 10.0],
    }

    cv = StratifiedGroupKFold(n_splits=N_SPLITS, shuffle=True, random_state=SEED)

    grid = GridSearchCV(
        pipe, param_grid=param_grid, scoring="f1",
        cv=cv, n_jobs=-1, refit=False,  # refit manually after inspecting groups
    )
    grid.fit(X_train, y_train, groups=groups)

    print("\nGridSearchCV results (leakage-safe CV, scored on F1):")
    res = pd.DataFrame(grid.cv_results_)[
        ["params", "mean_test_score", "std_test_score", "rank_test_score"]
    ].sort_values("rank_test_score")
    print(res.to_string(index=False))

    best_params = grid.best_params_
    print(f"\nBest params: {best_params}  (CV F1 = {grid.best_score_:.4f})")
    return best_params


# ==============================================================================
# STEP 7 -- FINAL FIT (100% of train) AND SINGLE TEST-SET EVALUATION
# ==============================================================================
def fit_final_pipeline(best_params, X_train, y_train):
    """
    Refits on the ENTIRE training set (all folds combined) using the
    hyperparameters chosen in Step 6. This is standard practice: CV is for
    model/hyperparameter SELECTION, the final artifact should still use
    every available labeled training example.
    """
    pipe = Pipeline([
        ("tfidf", build_vectorizer()),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED)),
    ])
    pipe.set_params(**best_params)
    pipe.fit(X_train, y_train)
    return pipe


def evaluate_on_test(pipe, X_test, y_test, model_name="Logistic Regression"):
    """
    The ONE place final_test.csv's labels are used. `pipe` was already fully
    fit before this function is called -- .predict()/.predict_proba() here
    only TRANSFORM the test text through the already-learned TF-IDF
    vocabulary/IDF weights; nothing is fit on test data. [L4]
    """
    y_pred = pipe.predict(X_test)
    if hasattr(pipe, "predict_proba"):
        y_score = pipe.predict_proba(X_test)[:, 1]
    else:
        y_score = pipe.decision_function(X_test)

    metrics = {
        "model": model_name,
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred),
        "roc_auc": roc_auc_score(y_test, y_score),
    }
    return metrics, y_pred, y_score


def evaluate_all_candidates_on_test(pipelines, X_train, y_train, X_test, y_test,
                                     prefit=None):
    """
    Fits every candidate on the FULL training set once, then evaluates each
    on the held-out test set exactly once -- for the final comparison table.
    This is separate from cross_validate_candidates(), which never touches
    final_test.csv at all.

    `prefit`: optional {name: already-fitted pipeline} overrides -- used so
    the "Logistic Regression" row in this table reports the SAME tuned
    model that was just reported in detail above, instead of silently
    re-fitting a second, differently-configured "Logistic Regression"
    with default hyperparameters (which would be confusing: two different
    numbers under one label).
    """
    prefit = prefit or {}
    rows = []
    fitted = {}
    for name, pipe in pipelines.items():
        if name in prefit:
            pipe = prefit[name]  # already fit on X_train/y_train with tuned params
        else:
            pipe.fit(X_train, y_train)
        fitted[name] = pipe
        metrics, _, _ = evaluate_on_test(pipe, X_test, y_test, model_name=name)
        rows.append(metrics)
    return pd.DataFrame(rows).set_index("model"), fitted


# ==============================================================================
# STEP 8 -- REPORTING / PLOTS
# ==============================================================================
def plot_roc_curves(fitted_pipelines, X_test, y_test, out_path=ROC_PLOT_OUT):
    fig, ax = plt.subplots(figsize=(6, 6))
    for name, pipe in fitted_pipelines.items():
        if hasattr(pipe, "predict_proba"):
            y_score = pipe.predict_proba(X_test)[:, 1]
        else:
            y_score = pipe.decision_function(X_test)
        RocCurveDisplay.from_predictions(y_test, y_score, name=name, ax=ax)
    ax.plot([0, 1], [0, 1], linestyle="--", color="gray", label="Chance")
    ax.set_title("ROC Curves - Held-out Test Set")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Saved ROC curve comparison to {out_path}")


def plot_confusion_matrix(y_test, y_pred, out_path=CM_PLOT_OUT, model_name="Logistic Regression"):
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(4.5, 4))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_title(f"Confusion Matrix - {model_name}\n(Held-out Test Set)")
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_xticks([0, 1]); ax.set_xticklabels(["Legit (0)", "Phishing (1)"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["Legit (0)", "Phishing (1)"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                     color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=14)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"Saved confusion matrix to {out_path}")


def top_features(pipe, n=15):
    """Most positive / negative Logistic Regression coefficients, mapped
    back to their TF-IDF terms -- a quick interpretability sanity-check."""
    if not isinstance(pipe.named_steps.get("clf"), LogisticRegression):
        return None
    vec = pipe.named_steps["tfidf"]
    clf = pipe.named_steps["clf"]
    terms = np.array(vec.get_feature_names_out())
    coefs = clf.coef_[0]
    top_pos = terms[np.argsort(coefs)[-n:]][::-1]
    top_neg = terms[np.argsort(coefs)[:n]]
    return pd.DataFrame({
        "top_phishing_indicators": top_pos,
        "top_legitimate_indicators": top_neg,
    })


# ==============================================================================
# MAIN
# ==============================================================================
def main():
    print("=" * 80)
    print("PHISHING EMAIL DETECTION - TRAINING PIPELINE")
    print("=" * 80)

    # ---- Step 1: load ----
    train_df, test_df = load_data()
    X_train_raw = train_df["text"].tolist()
    y_train = train_df["label"].values
    X_test_raw = test_df["text"].tolist()
    y_test = test_df["label"].values

    # ---- Step 3: leakage-safe CV groups (train set only) ----
    print("\n" + "-" * 80)
    print("Building near-duplicate groups for leakage-safe cross-validation")
    print("-" * 80)
    groups = build_near_duplicate_groups(X_train_raw)

    # ---- Step 4/5: cross-validate all candidates ----
    print("\n" + "-" * 80)
    print("CROSS-VALIDATION (StratifiedGroupKFold, 5 folds) -- MODEL COMPARISON")
    print("-" * 80)
    pipelines = build_candidate_pipelines()
    cv_results = cross_validate_candidates(pipelines, X_train_raw, y_train, groups)
    cv_results_display = cv_results[[c for c in cv_results.columns if c.endswith("_mean") or c.endswith("_std")]]
    cv_results_display = cv_results_display[sorted(cv_results_display.columns)]
    print("\nCross-validation results (mean +/- std across 5 leakage-safe folds):")
    print(cv_results.round(4).to_string())
    cv_results.round(4).to_csv(COMPARISON_CV_OUT)

    # ---- Step 6: tune the chosen model (Logistic Regression) ----
    print("\n" + "-" * 80)
    print("HYPERPARAMETER TUNING -- Logistic Regression (GridSearchCV, leakage-safe CV)")
    print("-" * 80)
    best_params = tune_logistic_regression(X_train_raw, y_train, groups)

    # ---- Step 7: refit best model on full train, evaluate once on test ----
    print("\n" + "-" * 80)
    print("FINAL MODEL -- refit on 100% of final_train.csv")
    print("-" * 80)
    final_pipe = fit_final_pipeline(best_params, X_train_raw, y_train)

    print("\n" + "-" * 80)
    print("HELD-OUT TEST SET EVALUATION (final_test.csv, touched once)")
    print("-" * 80)
    final_metrics, y_pred, y_score = evaluate_on_test(final_pipe, X_test_raw, y_test)
    print(json.dumps({k: round(v, 4) if isinstance(v, float) else v
                       for k, v in final_metrics.items()}, indent=2))
    print("\nClassification report:")
    print(classification_report(y_test, y_pred, target_names=["Legit (0)", "Phishing (1)"]))

    # ---- Step 8: comparison table for ALL candidates on the held-out test set ----
    print("\n" + "-" * 80)
    print("HELD-OUT TEST SET -- COMPARISON ACROSS ALL CANDIDATE MODELS")
    print("-" * 80)
    all_pipelines_for_test = build_candidate_pipelines()  # fresh, unfit copies
    test_comparison, fitted_pipelines = evaluate_all_candidates_on_test(
        all_pipelines_for_test, X_train_raw, y_train, X_test_raw, y_test,
        prefit={"Logistic Regression": final_pipe},  # use the TUNED model, not a default re-fit
    )
    print(test_comparison.round(4).to_string())
    test_comparison.round(4).to_csv(COMPARISON_TEST_OUT)

    # ---- plots ----
    plot_roc_curves(fitted_pipelines, X_test_raw, y_test)
    plot_confusion_matrix(y_test, y_pred, model_name="Logistic Regression (tuned)")

    # ---- interpretability ----
    feats = top_features(final_pipe)
    if feats is not None:
        print("\nTop TF-IDF terms driving Logistic Regression predictions:")
        print(feats.to_string(index=False))

    # ---- save model ----
    joblib.dump(final_pipe, MODEL_OUT_PATH)
    print(f"\nSaved final pipeline (TF-IDF + Logistic Regression) to {MODEL_OUT_PATH}")

    print("\n" + "=" * 80)
    print("DONE")
    print("=" * 80)

    return {
        "cv_results": cv_results,
        "test_comparison": test_comparison,
        "final_metrics": final_metrics,
        "best_params": best_params,
    }


def predict_email(text, model_path=MODEL_OUT_PATH):
    """
    Convenience function for scoring a brand-new, single email string with
    the saved pipeline (loads vectorizer + classifier together, so cleaning
    and vocabulary are applied exactly as during training).
    """
    pipe = joblib.load(model_path)
    proba = pipe.predict_proba([text])[0, 1]
    label = int(proba >= 0.5)
    return {"label": label, "phishing_probability": float(proba)}


if __name__ == "__main__":
    main()
