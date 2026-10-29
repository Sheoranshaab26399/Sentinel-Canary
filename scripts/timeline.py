#!/usr/bin/env python3
# timeline.py — forensic attack timeline viewer.
# Db me stored events ko T+seconds format me dikhata hai — incident ki "story"
# reconstruct karta hai: kab touch hua, kab entropy spike, kab block.
#
# Usage: python scripts/timeline.py [db_path] [--pid PID]

import os, sys, sqlite3, time, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from sentinel_canary import config


def _valid(p):
    if not p or not os.path.exists(p):
        return False
    try:
        c = sqlite3.connect(p); c.execute("SELECT 1 FROM events LIMIT 1"); c.close()
        return True
    except sqlite3.Error:
        return False


def pick_db(argv):
    for a in argv[1:]:
        if not a.startswith("-") and _valid(a):
            return a
    for p in [config.DB_PATH, os.path.join(tempfile.gettempdir(), "sentinel.db")]:
        if _valid(p):
            return p
    return None


def fmt_ts(t0, t):
    return f"T+{t - t0:6.3f}s"


def main():
    pid_filter = None
    if "--pid" in sys.argv:
        i = sys.argv.index("--pid")
        pid_filter = int(sys.argv[i + 1])

    db = pick_db(sys.argv)
    if not db:
        print("no populated db — pehle simulate/real-sim chalao.")
        sys.exit(1)
    conn = sqlite3.connect(db)

    q = "SELECT ts,pid,etype,path,entropy,score,is_alert,reasons FROM events"
    if pid_filter:
        q += f" WHERE pid={int(pid_filter)}"
    q += " ORDER BY ts ASC"
    rows = conn.execute(q).fetchall()
    if not rows:
        print("no events.")
        return
    t0 = rows[0][0]

    print(f"(reading {db})  — attack timeline")
    print("=" * 72)
    first_alert = None
    for ts, pid, et, path, ent, sc, al, rs in rows:
        mark = "ALERT" if al else "     "
        if al and first_alert is None:
            first_alert = ts
        print(f"{mark} {fmt_ts(t0, ts)} pid={pid:<6} {et:<8} "
              f"ent={ent:4.2f} score={sc:<3} {path}")
        if al and rs:
            print(f"        └─ {rs}")
    print("=" * 72)
    if first_alert:
        print(f"First alert at {fmt_ts(t0, first_alert)}  "
              f"(time-to-detect ≈ {first_alert - t0:.3f}s)")
    # offender states
    print("\nOffenders:")
    for pid, st, state, ts in conn.execute(
            "SELECT pid,strikes,state,last_seen FROM offenders ORDER BY strikes DESC"):
        print(f"  pid={pid} strikes={st} state={state}")
    conn.close()


if __name__ == "__main__":
    main()
