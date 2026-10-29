#!/usr/bin/env python3
# benchmark.py — repeatable runs for report numbers.
# Kitne events/sec process ho sakte hain + detection accuracy (TP/FP/TN/FN).
# Usage: python scripts/benchmark.py [runs]

import os, sys, time, tempfile, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sentinel_canary import config, canary, detector, mitigation, storage, pipeline
from sentinel_canary.simulator import EventSimulator, _ATTACK


def run_once():
    tmp = tempfile.mkdtemp()
    config.HONEY_DIR = os.path.join(tmp, "honey")
    canary.ensure_honey_dirs()
    st = storage.Storage(os.path.join(tmp, "b.db"))
    pipe = pipeline.Pipeline(storage=st)

    evs = EventSimulator().events()
    # ground truth: honey path + high entropy = attack
    truth = [("honey" in e["path"] and e["entropy"] > 7) for e in evs]

    t0 = time.time()
    preds = []
    for e in evs:
        res = pipe.detector.score(e)
        preds.append(res["alert"])
        pipe.storage.log_event(e, res)
    dt = time.time() - t0

    tp = sum(1 for t, p in zip(truth, preds) if t and p)
    fp = sum(1 for t, p in zip(truth, preds) if not t and p)
    tn = sum(1 for t, p in zip(truth, preds) if not t and not p)
    fn = sum(1 for t, p in zip(truth, preds) if t and not p)

    shutil.rmtree(tmp, ignore_errors=True)
    rate = len(evs) / dt if dt else 0
    return tp, fp, tn, fn, len(evs), rate


def main():
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    print(f"benchmark: {runs} runs")
    TP = FP = TN = FN = 0
    rates = []
    for i in range(runs):
        tp, fp, tn, fn, n, rate = run_once()
        TP += tp; FP += fp; TN += tn; FN += fn; rates.append(rate)
        print(f"  run {i+1}: events={n} tp={tp} fp={fp} tn={tn} fn={fn} rate={rate:.0f} ev/s")

    prec = TP / (TP + FP) if TP + FP else 0
    rec = TP / (TP + FN) if TP + FN else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    fpr = FP / (FP + TN) if FP + TN else 0
    print("-" * 50)
    print(f"TOTAL  TP={TP} FP={FP} TN={TN} FN={FN}")
    print(f"precision={prec:.2f} recall={rec:.2f} F1={f1:.2f} FPR={fpr:.3f}")
    print(f"avg throughput={sum(rates)/len(rates):.0f} events/sec")


if __name__ == "__main__":
    main()
