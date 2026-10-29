#!/usr/bin/env python3
# show_db.py — read-only forensic viewer. SQLite me kya store hua dekhne ke liye.
# Usage: python scripts/show_db.py [db_path]

import os, sys, sqlite3, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from sentinel_canary import config

def _valid(p):
    """db path valid hai + events table hai?"""
    if not p or not os.path.exists(p):
        return False
    try:
        c = sqlite3.connect(p)
        c.execute("SELECT 1 FROM events LIMIT 1")
        c.close()
        return True
    except sqlite3.Error:
        return False


def main():
    import tempfile
    # arg > real path > temp fallback — jo bhi pehla valid mile
    cands = ([sys.argv[1]] if len(sys.argv) > 1 else
             [config.DB_PATH, os.path.join(tempfile.gettempdir(), "sentinel.db")])
    db = next((p for p in cands if _valid(p)), None)
    if not db:
        print("no populated db found.\npehle chalao: python -m sentinel_canary.main simulate")
        sys.exit(1)
    conn = sqlite3.connect(db)
    print(f"(reading {db})")

    print("=== COUNTS ===")
    total, alerts = conn.execute("SELECT COUNT(*),COALESCE(SUM(is_alert),0) FROM events").fetchone()
    print(f"events={total}  alerts={alerts}")

    print("\n=== OFFENDERS ===")
    for pid, st, state, ts in conn.execute(
        "SELECT pid,strikes,state,last_seen FROM offenders ORDER BY strikes DESC"):
        print(f"  pid={pid} strikes={st} state={state} last={time.strftime('%H:%M:%S',time.localtime(ts))}")

    print("\n=== RECENT EVENTS (latest 15) ===")
    for ts, pid, et, path, ent, sc, al, reasons in conn.execute(
        "SELECT ts,pid,etype,path,entropy,score,is_alert,reasons FROM events ORDER BY id DESC LIMIT 15"):
        tag = "ALERT" if al else "     "
        print(f"  {tag} {time.strftime('%H:%M:%S',time.localtime(ts))} pid={pid} {et} score={sc} ent={ent:.2f} {path}")
        if reasons:
            print(f"        -> {reasons}")
    conn.close()

if __name__ == "__main__":
    main()
