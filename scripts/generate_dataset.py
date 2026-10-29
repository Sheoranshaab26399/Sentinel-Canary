#!/usr/bin/env python3
# generate_dataset.py — benign + attack file events ka CSV dataset banao.
# Report/demo ke liye labelled data (entropy + label) — ML ya plots me use kar sakte ho.
# Usage: python scripts/generate_dataset.py > events.csv

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel_canary.simulator import EventSimulator

def main():
    print("path,pid,etype,entropy,label")  # header
    for e in EventSimulator().events():
        # label: honey path + high entropy => attack(1) else benign(0)
        label = 1 if ("honey" in e["path"] and e["entropy"] > 7) else 0
        print(f"{e['path']},{e['pid']},{e['type']},{e['entropy']:.3f},{label}")

if __name__ == "__main__":
    main()
