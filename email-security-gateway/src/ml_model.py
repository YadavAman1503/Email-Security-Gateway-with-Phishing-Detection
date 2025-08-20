
import os
import argparse
import joblib
from typing import Any

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_CSV = os.path.join(BASE_DIR, "data", "sample_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "phish_clf.joblib")

def build_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(stop_words="english", ngram_range=(1,2), min_df=1)),
        ("clf", LogisticRegression(max_iter=200))
    ])

def train() -> None:
    df = pd.read_csv(DATA_CSV)
    X = df["text"].astype(str).tolist()
    y = df["label"].astype(int).tolist()

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    pipe = build_pipeline()
    pipe.fit(X_train, y_train)

    preds = pipe.predict(X_test)
    proba = pipe.predict_proba(X_test)[:,1]
    print("Accuracy:", accuracy_score(y_test, preds))
    print(classification_report(y_test, preds, digits=3))

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(pipe, MODEL_PATH)
    print(f"Saved model to {MODEL_PATH}")

def load_model() -> Any:
    if not os.path.exists(MODEL_PATH):
        train()
    return joblib.load(MODEL_PATH)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true", help="Train and save the model")
    args = ap.parse_args()
    if args.train:
        train()
    else:
        m = load_model()
        print("Model loaded:", m)
