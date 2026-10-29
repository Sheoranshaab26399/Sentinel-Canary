# ml_detector.py
# Optional ML classifier — sklearn LogisticRegression features pe predict karta hai.
# GUARDED: sklearn na ho toh gracefully off rehta hai, core pe koi asar nahi.
#
# Features (har event pe):
#   [entropy, rate(events/window), is_canary, has_ransom_ext]
# Label: 1 = attack, 0 = benign  (simulator ground-truth se generate)
#
# train_models.py model.pkl banata hai; predict_proba usko load karke probability deta hai.

import os
import pickle

from . import config

_MODEL = None
_LOADED = False


def available() -> bool:
    """sklearn installed hai + model file hai?"""
    try:
        import sklearn  # noqa
        return os.path.exists(config.ML_MODEL_PATH)
    except Exception:
        return False


def _load():
    global _MODEL, _LOADED
    if _LOADED:
        return _MODEL
    _LOADED = True
    if not os.path.exists(config.ML_MODEL_PATH):
        _MODEL = None
        return None
    try:
        with open(config.ML_MODEL_PATH, "rb") as f:
            _MODEL = pickle.load(f)
    except Exception:
        _MODEL = None
    return _MODEL


def featurize(entropy: float, rate: int, is_canary: bool, has_ransom_ext: bool):
    """Event -> feature vector."""
    return [[float(entropy), float(rate),
             1.0 if is_canary else 0.0,
             1.0 if has_ransom_ext else 0.0]]


def predict_proba(entropy: float, rate: int, has_ransom_ext: bool,
                  is_canary: bool = True):
    """
    Attack-probability (0..1) nikalo. Model na ho toh None.
    """
    m = _load()
    if m is None:
        return None
    try:
        X = featurize(entropy, rate, is_canary, has_ransom_ext)
        return float(m.predict_proba(X)[0][1])
    except Exception:
        return None
