#!/usr/bin/env python3
# train_models.py — labelled dataset pe ML classifier train karo.
# sklearn GUARDED hai — na ho toh politely exit karta hai (core unaffected).
#
# Features per event: [entropy, rate, is_canary, has_ransom_ext]
# Label: simulator se — honey+high-entropy => attack(1) else benign(0)
#
# Usage: python scripts/train_models.py
# Output: data/model.pkl + train/test metrics print

import os, sys, pickle, random

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from sentinel_canary import config
from sentinel_canary.simulator import EventSimulator


def build_dataset(seed=1337, n_extra=400):
    """Features + labels ka dataset banao (sim + thoda extra variety)."""
    X, y = [], []
    rng = random.Random(seed)
    for e in EventSimulator().events():
        is_can = 1.0 if "honey" in e["path"] else 0.0
        ext = 1.0 if e["path"].lower().endswith(tuple(config.RANSOM_EXTS)) else 0.0
        ent = e["entropy"]
        rate = 0.0  # single-event context — rate approximation
        label = 1 if (is_can and ent > 7) else 0
        X.append([ent, rate, is_can, ext]); y.append(label)
    # extra synthetic variety — entropy spectrum pe benign vs attack
    for _ in range(n_extra):
        atk = rng.random() < 0.5
        ent = rng.uniform(6.9, 8.0) if atk else rng.uniform(3.5, 6.5)
        is_can = rng.random() < (0.8 if atk else 0.1)
        rate = rng.uniform(6, 20) if atk else rng.uniform(0, 4)
        ext = rng.random() < (0.6 if atk else 0.02)
        X.append([ent, rate, is_can, ext]); y.append(1 if atk else 0)
    return X, y


def main():
    try:
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import (precision_score, recall_score,
                                     f1_score, confusion_matrix)
    except Exception:
        print("[ml] sklearn not installed -> pip install scikit-learn")
        print("     (optional feature — core project iske bina chalta hai)")
        sys.exit(0)

    X, y = build_dataset()
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25,
                                        random_state=42, stratify=y)
    clf = LogisticRegression(max_iter=1000)
    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)

    p = precision_score(yte, pred); r = recall_score(yte, pred)
    f1 = f1_score(yte, pred); cm = confusion_matrix(yte, pred)

    os.makedirs(os.path.dirname(config.ML_MODEL_PATH), exist_ok=True)
    with open(config.ML_MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)

    print(f"[ml] trained LogisticRegression on {len(Xtr)} samples")
    print(f"[ml] test: precision={p:.3f} recall={r:.3f} F1={f1:.3f}")
    print(f"[ml] confusion matrix:\n{cm}")
    print(f"[ml] model saved -> {config.ML_MODEL_PATH}")
    print("[ml] enable with config.USE_ML=True to blend into rule-score")


if __name__ == "__main__":
    main()
