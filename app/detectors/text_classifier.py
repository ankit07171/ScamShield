"""Baseline text classifier: TF-IDF (word + char n-grams) + logistic regression.

Char n-grams help with Hinglish/Hindi/Marathi spelling variation. Swap this for a fine-tuned
multilingual transformer (e.g. MuRIL / XLM-R) once you have enough labelled data.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from . import DetectorResult, Reason

SEED = Path(__file__).resolve().parent.parent / "data" / "seed_messages.csv"
_URL = re.compile(r"(?:https?://|www\.)\S+|\b[\w-]+(?:\.[\w-]+)+/\S*", re.I)
_NUM = re.compile(r"\d+")


def normalize_text(text: str) -> str:
    """Module-level so the pickled pipeline can import it. Masks URLs and numbers."""
    text = _URL.sub(" urltoken ", text.lower())
    return _NUM.sub(" numtoken ", text)


def build_pipeline() -> Pipeline:
    feats = FeatureUnion([
        ("word", TfidfVectorizer(preprocessor=normalize_text, ngram_range=(1, 2), sublinear_tf=True)),
        ("char", TfidfVectorizer(preprocessor=normalize_text, analyzer="char_wb", ngram_range=(2, 5),
                                 sublinear_tf=True, min_df=2)),
    ])
    return Pipeline([("tfidf", feats),
                     ("clf", LogisticRegression(C=6.0, max_iter=2000, class_weight="balanced"))])


def load_dataset(path: Path = SEED) -> tuple[list[str], list[int]]:
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return [r["text"] for r in rows], [int(r["label"]) for r in rows]


def train_and_save(model_path: str, data_path: Path = SEED, threshold: float = 0.5, seed: int = 42) -> dict:
    """Evaluate on a held-out split, then refit on everything and save."""
    X, y = load_dataset(data_path)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=seed)
    pipe = build_pipeline().fit(Xtr, ytr)
    pred = (pipe.predict_proba(Xte)[:, 1] >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(yte, pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    metrics = {
        "n_train": len(Xtr), "n_test": len(Xte), "threshold": threshold,
        "precision": round(precision, 3), "recall": round(recall, 3),
        "f1": round(2 * precision * recall / (precision + recall), 3) if precision + recall else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else 0.0,
        "note": "Tiny seed dataset: numbers are indicative only. Re-run on a real held-out set.",
    }
    final = build_pipeline().fit(X, y)
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": final, "metrics": metrics}, model_path)
    return metrics


class TextClassifier:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.pipeline = None
        self.metrics: dict = {}

    def load(self) -> None:
        if not Path(self.model_path).exists():
            train_and_save(self.model_path)
        blob = joblib.load(self.model_path)
        self.pipeline, self.metrics = blob["pipeline"], blob.get("metrics", {})

    def predict_proba(self, text: str) -> float:
        return float(self.pipeline.predict_proba([text])[0, 1])

    def analyze(self, text: str) -> DetectorResult:
        p = self.predict_proba(text)
        # Ignore weak signal so ordinary messages are not nudged by model noise.
        contribution = max(0.0, (p - 0.35) / 0.65)
        reasons = []
        if p >= 0.6:
            reasons.append(Reason("ml_text", f"The wording closely matches known scam messages (model score {p:.0%}).",
                                  "text", contribution))
        return DetectorResult("text", contribution, reasons, {"raw_probability": round(p, 3)})
