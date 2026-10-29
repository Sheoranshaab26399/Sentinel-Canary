# Sentinel-Canary

Real-time ransomware detection & mitigation — **behaviour-based**, signature nahi.
Decoy "canary" files plant karta hai, unhe watch karta hai, aur ransomware jaisa
encryption detect hote hi offending process ko block/mitigate karta hai.

## Problem
Traditional antivirus **signatures** pe chalta hai — naya/polymorphic ransomware
miss ho jata hai. Hum **behaviour** dekhte hain: kaun canary file chhu raha hai,
kitni high-entropy se, aur kitni speed se — toh zero-day bhi pakda jata hai.

## Pipeline
```
canary files → watcher/simulator → detector(entropy+rate) → score 0-100+reasons
            → mitigation(watchlist→temp→perm) → SQLite + alert → dashboard
```

## Setup
```bash
# minimum (core — kuch install ki zaroorat nahi, stdlib only)
python -m sentinel_canary.main init
python -m sentinel_canary.main simulate

# full install (live watcher + dashboard + notifications)
pip install -r requirements.txt
```

## Commands
| Command | Kaam |
|---|---|
| `python -m sentinel_canary.main init` | canary files + snapshot banao |
| `python -m sentinel_canary.main simulate` | fixed-seed demo (repeatable, real malware nahi) |
| `python -m sentinel_canary.main real-sim` | **REAL** encryption attack — AES ransomware ko live detect karo |
| `python -m sentinel_canary.main rollback` | latest snapshot se honey dir restore (attack ke baad) |
| `python -m sentinel_canary.main live` | watchdog se real monitoring (honey dir) |
| `python -m sentinel_canary.main dashboard` | web UI @ http://127.0.0.1:8000 |
| `python scripts/selftest.py` | sab test — PASS/FAIL proof |
| `python scripts/benchmark.py 5` | TP/FP/TN/FN + precision/recall/F1 |
| `python scripts/roc_sweep.py` | threshold sweep — precision/recall trade-off |
| `python scripts/timeline.py` | forensic attack timeline (T+sec story) |
| `python scripts/show_db.py` | forensic viewer (db) |
| `python scripts/generate_dataset.py` | labelled CSV dataset |
| `python scripts/train_models.py` | optional ML classifier (sklearn) train karo |

## Honest limitations
- Live mode me exact malicious PID pakadna OS-specific hai (humne watcher pid use kiya hai; real deployment me process-attribution hook chahiye — e.g. Linux auditd/fanotify ya Windows ETW).
- Network kill-switch (`ENABLE_NET_KILLSWITCH`) root/iptables mangta hai — default OFF, app-level mitigation use hota hai.
- Simulator ek *model* hai, real ransomware ki tarah kernel-level stealth nahi karta.
- Single host pe focused — network-wide spread ke liye multi-agent chahiye.

## Viva design decisions
- **Behaviour over signature** → zero-day coverage.
- **Score 0-100 + reasons** → explainable, threshold tunable.
- **fail2ban escalation** → false-positive pe hamesha kill nahi, pehle watch phir block.
- **Redacted storage** → sirf path-tail + entropy, raw content nahi (privacy).
- **Guarded imports** → core stdlib-only, optional deps na ho toh bhi chale.

## 6-minute demo
1. `selftest.py` chalao — sab PASS dikhao (30s)
2. `init` — canary files dikhao honey dir me (30s)
3. `simulate` — attack burst pe alerts + escalation dikhao (1.5 min)
4. `real-sim` + `rollback` — REAL encryption ko live rok ke restore dikhao (1.5 min)
5. `timeline.py` / `show_db.py` — offenders + reasons + attack story (1 min)
6. `benchmark.py` + `roc_sweep.py` — precision/recall/F1 + tuning (1 min)
7. `dashboard` — browser me live feed + start/stop (30s)

## New features (v2)
- **Real ransomware simulator** (`ransomware_sim.py`) — actual AES-256-CTR
  encryption honey files pe; detector live rokta hai. Proof detection works on
  real crypto, not just canned events.
- **Forensic timeline** (`scripts/timeline.py`) — T+sec incident replay.
- **Threshold/ROC sweep** (`scripts/roc_sweep.py`) — precision/recall tuning.
- **Ransom-extension detection** — `.locked/.enc/.crypt` rename flag.
- **Optional ML classifier** (`ml_detector.py` + `train_models.py`) — sklearn
  LogisticRegression blends into rule-score (guarded, `USE_ML` flag).
