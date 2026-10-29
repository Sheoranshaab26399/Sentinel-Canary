#!/usr/bin/env python3
# selftest.py — stdlib-only. Har module + end-to-end run check karta hai.
# Output: PASS/FAIL/WARN per check. Exit 0 agar sab theek, 1 agar koi FAIL.
# Ye tumhara "proof the project works" hai.

import os, sys, time, tempfile, shutil

# package ko import karne ke liye repo root path me daalo
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

RESULTS = []

def check(name, ok, warn=False, note=""):
    status = "WARN" if warn else ("PASS" if ok else "FAIL")
    RESULTS.append((status, name, note))
    print(f"[{status}] {name}" + (f"  -- {note}" if note else ""))
    return ok


def main():
    print("=" * 55)
    print("Sentinel-Canary self-test")
    print("=" * 55)

    # ---- imports ----
    try:
        from sentinel_canary import config, canary, detector, mitigation, storage, simulator, pipeline, alerter
        check("import core modules", True)
    except Exception as e:
        check("import core modules", False, note=str(e))
        return finish()

    # ---- optional deps (warn, not fail) ----
    try:
        import watchdog; check("watchdog (live mode)", True)
    except Exception:
        check("watchdog (live mode)", True, warn=True, note="not installed — live mode off")
    try:
        import fastapi, uvicorn; check("fastapi+uvicorn (dashboard)", True)
    except Exception:
        check("fastapi+uvicorn (dashboard)", True, warn=True, note="not installed — dashboard off")
    try:
        import psutil; check("psutil (process kill)", True)
    except Exception:
        check("psutil (process kill)", True, warn=True, note="not installed — kill limited")

    # ---- entropy math ----
    ent_low = detector.shannon_entropy(b"aaaaaaaa normal english text " * 4)
    ent_high = detector.shannon_entropy(os.urandom(512))
    check("entropy: text < random", ent_low < ent_high,
          note=f"text={ent_low:.2f} rand={ent_high:.2f}")
    check("entropy range sane", 0 <= ent_low < ent_high <= 8)

    # ---- canary creation (temp dir me, real data ko na chhede) ----
    tmp = tempfile.mkdtemp()
    old_honey, old_snap = config.HONEY_DIR, config.SNAP_DIR
    config.HONEY_DIR, config.SNAP_DIR = os.path.join(tmp, "honey"), os.path.join(tmp, "snap")
    try:
        made = canary.ensure_honey_dirs()
        check("canary files created", len(made) > 0, note=f"{len(made)} files")
        check("canary file readable", all(os.path.exists(p) for p in made))
        snap = canary.snapshot_honey_dir()
        check("snapshot created", os.path.isdir(snap))
        restored = canary.restore_latest_snapshot()
        check("restore snapshot", restored != "" and os.path.isdir(config.HONEY_DIR))
    finally:
        config.HONEY_DIR, config.SNAP_DIR = old_honey, old_snap

    # ---- detector scoring ----
    d = detector.Detector()
    benign = {"type": "modified", "path": "docs/notes.txt", "pid": 100, "entropy": 4.5}
    r_benign = d.score(benign)
    check("benign not alert", not r_benign["alert"], note=f"score={r_benign['score']}")

    attack_pid = 999
    last = None
    for _ in range(12):
        last = d.score({"type": "modified", "path": "honey/x/passwords.txt",
                        "pid": attack_pid, "entropy": 7.9})
    check("attack flagged", last["alert"], note=f"score={last['score']}")
    check("reasons present", len(last["reasons"]) > 0, note="; ".join(last["reasons"]))
    check("score<=100", last["score"] <= 100)

    # ---- extension-rename detection ----
    d2 = detector.Detector()
    ren = d2.score({"type": "moved", "path": "honey/x/notes.txt.locked",
                    "old_ext": ".txt", "pid": 5, "entropy": 7.9})
    check("ransom extension flagged", any("extension" in r for r in ren["reasons"]),
          note="; ".join(ren["reasons"]))
    check("rename adds score", ren["score"] > 0)

    # ---- real ransomware simulator (actual encryption) ----
    rdir = os.path.join(tmp, "honey2")
    os.makedirs(os.path.join(rdir, "documents"), exist_ok=True)
    victims = []
    for i in range(4):
        v = os.path.join(rdir, "documents", f"passwords{i}.txt")
        with open(v, "wb") as f:
            f.write(b"service,user,pass\nmail,admin,Winter2024!\n" * 4)
        victims.append(v)
    from sentinel_canary.ransomware_sim import RansomwareSimulator
    pre_ent = detector.file_entropy(victims[0])
    hits = []
    rs = RansomwareSimulator(target_dir=rdir, delay=0)
    enc = rs.run(event_hook=lambda e: hits.append(d.score(e)))
    post_ent = detector.file_entropy(enc[0][1]) if enc else 0
    check("real-sim encrypted files", len(enc) >= 4, note=f"{len(enc)} files")
    check("encryption raised entropy", post_ent > pre_ent + 1,
          note=f"{pre_ent:.2f} -> {post_ent:.2f}")
    check("detector flagged real encryption",
          any(h.get("alert") for h in hits),
          note=f"maxscore={max((h.get('score') for h in hits), default=0)}")
    check("files got ransom ext", enc and enc[0][1].endswith(config.RANSOM_EXT))

    # ---- roc sweep + ml guards (import only, no heavy run) ----
    try:
        sys.path.insert(0, os.path.join(ROOT, "scripts"))
        import roc_sweep, timeline  # noqa
        check("roc_sweep + timeline importable", True)
    except Exception as e:
        check("roc_sweep + timeline importable", False, note=str(e))
    try:
        from sentinel_canary import ml_detector
        check("ml_detector module (guarded)", ml_detector.predict_proba is not None)
    except Exception as e:
        check("ml_detector module (guarded)", False, note=str(e))

    # ---- mitigation escalation ----
    m = mitigation.Mitigator()
    pid = 42
    r1 = m.record_alert(pid)
    r2 = m.record_alert(pid)
    r3 = m.record_alert(pid)
    check("escalation watch->perm", r3["state"] == "permanent",
          note=f"s1={r1['state']} s2={r2['state']} s3={r3['state']}")
    check("pid blocked", m.is_blocked(pid))

    # ---- end-to-end pipeline (temp db) ----
    db = os.path.join(tmp, "test.db")
    st = storage.Storage(db)
    pipe = pipeline.Pipeline(storage=st)
    from sentinel_canary.simulator import EventSimulator
    stats = pipe.run_events(EventSimulator().events())
    check("pipeline processed events", stats["events"] > 0, note=f"{stats['events']} events")
    check("pipeline raised alerts", stats["alerts"] > 0, note=f"{stats['alerts']} alerts")
    rows = st.recent_events(5)
    check("db has events", len(rows) > 0)
    off = st.list_offenders()
    check("db has offenders", len(off) > 0, note=f"{len(off)} offenders")

    shutil.rmtree(tmp, ignore_errors=True)
    return finish()


def finish():
    fails = sum(1 for s, _, _ in RESULTS if s == "FAIL")
    warns = sum(1 for s, _, _ in RESULTS if s == "WARN")
    passes = sum(1 for s, _, _ in RESULTS if s == "PASS")
    print("=" * 55)
    print(f"RESULT: {passes} PASS, {warns} WARN, {fails} FAIL")
    print("=" * 55)
    return fails


if __name__ == "__main__":
    sys.exit(0 if main() == 0 else 1)
