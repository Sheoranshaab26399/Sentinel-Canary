#!/usr/bin/env python3
# roc_sweep.py — SCORE_ALERT threshold ko sweep karke precision/recall trade-off
# dekhta hai (mini ROC analysis). Report me "tuning" section ke liye useful.
#
# Har threshold pe pura simulated set dobara score hota hai, phir
# TP/FP/TN/FN + precision/recall/FPR nikalte hain.
#
# Usage: python scripts/roc_sweep.py

import os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from sentinel_canary import config, detector
from sentinel_canary.simulator import EventSimulator


def evaluate(events, truths, threshold):
    """Ek threshold pe pura set score karo -> metrics."""
    det = detector.Detector()
    tp = fp = tn = fn = 0
    for ev, t in zip(events, truths):
        res = det.score(ev)
        pred = res["score"] >= threshold
        if t and pred: tp += 1
        elif not t and pred: fp += 1
        elif not t and not pred: tn += 1
        else: fn += 1
    prec = tp/(tp+fp) if tp+fp else 0.0
    rec  = tp/(tp+fn) if tp+fn else 0.0
    f1   = 2*prec*rec/(prec+rec) if prec+rec else 0.0
    fpr  = fp/(fp+tn) if fp+tn else 0.0
    return tp, fp, tn, fn, prec, rec, f1, fpr


def main():
    events = EventSimulator().events()
    # ground truth: honey + high entropy = attack
    truths = [("honey" in e["path"] and e["entropy"] > 7) for e in events]

    print("Threshold sweep — score_threshold -> precision / recall / FPR")
    print("-" * 66)
    print(f"{'thr':>4} | {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3} | "
          f"{'prec':>5} {'rec':>5} {'F1':>5} {'FPR':>6}")
    print("-" * 66)
    for thr in range(30, 95, 5):
        tp, fp, tn, fn, p, r, f1, fpr = evaluate(events, truths, thr)
        mark = " <-- current" if thr == config.SCORE_ALERT else ""
        print(f"{thr:>4} | {tp:>3} {fp:>3} {tn:>3} {fn:>3} | "
              f"{p:>5.2f} {r:>5.2f} {f1:>5.2f} {fpr:>6.3f}{mark}")
    print("-" * 66)
    print("Low thr -> high recall but more FP. High thr -> fewer FP but more FN.")
    print("Ransomware me FN costly hai => recall-leaning threshold better.")


if __name__ == "__main__":
    main()
