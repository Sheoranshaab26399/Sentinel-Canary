# detector.py
# File events ko analyze karke EXPLAINABLE risk score (0-100) deta hai.
# Har alert ke saath REASONS list — binary nahi, samjh aata hai kyu flag hua.

import math
import os
import time
from collections import defaultdict, deque

from . import config


def shannon_entropy(data: bytes) -> float:
    """
    Shannon entropy (bits/byte). Randomness ka measure.
    Normal text ~4-5, encrypted/compressed ~7.5-8.
    """
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def file_entropy(path: str, max_bytes: int = 65536) -> float:
    """File padh ke uski entropy nikalo. Nahi milne pe 0."""
    try:
        with open(path, "rb") as f:
            return shannon_entropy(f.read(max_bytes))
    except OSError:
        return 0.0


class Detector:
    """
    Har file event pe score compute karta hai.
    State rakhta hai: per-process recent events (rate-of-change ke liye).
    """

    def __init__(self):
        # pid -> deque of timestamps (rate-of-change window ke liye)
        self._recent = defaultdict(deque)

    def _rate(self, pid: int, now: float) -> int:
        """pid ne pichle RATE_WINDOW_SEC seconds me kitne events kiye."""
        dq = self._recent[pid]
        dq.append(now)
        # window se purane events hata do
        while dq and now - dq[0] > config.RATE_WINDOW_SEC:
            dq.popleft()
        return len(dq)

    def score(self, event: dict) -> dict:
        """
        event = {
          'type': 'modified'|'created'|'moved'|'deleted',
          'path': str,
          'pid': int,           # kaun process kar raha hai
          'entropy': float|None # optional precomputed (simulator bhej sakta hai)
        }
        Return: {'score':int, 'alert':bool, 'reasons':[...], 'entropy':float}
        """
        now = time.time()
        score = 0
        reasons = []
        path = event.get("path", "")
        pid = event.get("pid", 0)
        etype = event.get("type", "modified")

        # --- entropy (ya toh event me di, ya file se compute) ---
        ent = event.get("entropy")
        if ent is None:
            ent = file_entropy(path)
        ent = float(ent)

        if ent >= config.ENTROPY_HIGH:
            score += config.W_ENTROPY_HIGH
            reasons.append(f"high entropy {ent:.2f} (encryption-like)")
        elif ent >= config.ENTROPY_SUSPICIOUS:
            score += config.W_ENTROPY_SUSP
            reasons.append(f"elevated entropy {ent:.2f}")

        # --- canary file ko touch kiya? ---
        if path and "honey" in path.replace("\\", "/"):
            score += config.W_CANARY
            reasons.append("touched a canary/honey file")

        # --- rate-of-change (mass modification) ---
        rate = self._rate(pid, now)
        if rate >= config.RATE_MANY_EVENTS:
            score += config.W_RATE
            reasons.append(f"mass modification ({rate} events/{config.RATE_WINDOW_SEC:.0f}s)")

        # --- ransomware jaisa rename/extension ---
        # Ransomware files ko rename karke weird extension deta hai (.locked/.enc/.crypt).
        # Ya toh etype 'moved' (rename) ho, ya path kisi ransomware-ext pe khatam ho,
        # ya event me explicit 'old_ext' -> new ext change diya ho.
        low = path.lower()
        old_ext = (event.get("old_ext") or "").lower()
        new_ext = os.path.splitext(low)[1]
        bad_ext = getattr(config, "RANSOM_EXTS",
                          (".enc", ".locked", ".crypt", ".crypto", ".encrypted",
                           ".ransom", ".lockbit", ".ryuk", ".crypted"))
        ext_flag = (
            new_ext in bad_ext
            or (old_ext and old_ext != new_ext and new_ext in bad_ext)
        )
        if ext_flag:
            score += config.W_RENAME_EXT
            reasons.append(f"ransom-style extension '{new_ext}'")
        elif etype == "moved":
            score += config.W_RENAME_EXT
            reasons.append("file renamed")

        # --- optional ML score (guarded) ---
        ml = None
        if getattr(config, "USE_ML", False):
            try:
                from . import ml_detector
                ml = ml_detector.predict_proba(ent, rate, ext_flag)
                if ml is not None:
                    score += int(round(ml * config.ML_WEIGHT))
                    reasons.append(f"ml-prob {ml:.2f}")
            except Exception:
                pass

        score = max(0, min(100, score))
        return {
            "score": score,
            "alert": score >= config.SCORE_ALERT,
            "reasons": reasons,
            "entropy": round(ent, 3),
            "rate": rate,
            "ml": ml,
        }
