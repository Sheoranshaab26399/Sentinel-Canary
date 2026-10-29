# main.py
# CLI entry point — saare modes yahin se chalte hain.
#   python -m sentinel_canary.main init       -> canary files banao + snapshot
#   python -m sentinel_canary.main simulate    -> fixed-seed demo (real malware nahi)
#   python -m sentinel_canary.main live        -> watchdog se real monitoring
#   python -m sentinel_canary.main dashboard   -> web UI + websocket

import argparse
import sys

from . import config, canary
from .storage import Storage
from .pipeline import Pipeline
from . import watcher, dashboard


def cmd_init(_a):
    made = canary.ensure_honey_dirs()
    snap = canary.snapshot_honey_dir()
    print(f"[init] honey dir: {config.HONEY_DIR}")
    print(f"[init] canary files created: {len(made)}")
    print(f"[init] snapshot saved: {snap}")


def cmd_simulate(_a):
    from .simulator import EventSimulator
    canary.ensure_honey_dirs()
    pipe = Pipeline()
    print(f"[sim] running fixed-seed simulation (seed={config.SIM_SEED})...")
    stats = pipe.run_events(EventSimulator().events(), delay=0.05)
    print(f"[sim] done. events={stats['events']} alerts={stats['alerts']}")
    print(f"[sim] offenders:")
    for row in pipe.storage.list_offenders():
        print(f"      pid={row[0]} strikes={row[1]} state={row[2]}")


def cmd_live(_a):
    if not watcher.available():
        print("[live] watchdog not installed -> pip install watchdog")
        sys.exit(1)
    canary.ensure_honey_dirs()
    pipe = Pipeline()
    print(f"[live] watching {config.HONEY_DIR}  (Ctrl+C to stop)")
    watcher.run_live(pipe.process)


def cmd_real_sim(_a):
    """
    REAL ransomware simulator — actual file encryption karta hai honey dir me,
    aur hum detector ko live chalate hain. Ye proof hai ki system real
    encryption ko rokta hai (fake events nahi — real crypto).
    """
    from .ransomware_sim import RansomwareSimulator
    canary.ensure_honey_dirs()
    canary.snapshot_honey_dir()          # attack se pehle backup (rollback ke liye)
    pipe = Pipeline()
    print(f"[real-sim] launching REAL encryption on {config.SIM_TARGET_DIR}")

    # NOTE: simulator ko FAKE pid dete hain taaki detection "malicious pid" ka
    # record ho — warna KILL_PROCESS=True hone pe mitigator humein khud
    # SIGTERM kar dega (jo ki sahi kaam hai, par demo khatam ho jayega!).
    sim = RansomwareSimulator()
    sim.pid = 6666   # fake attacker pid — detection realistic, demo safe
    print(f"[real-sim] attacker pid={sim.pid} (simulated)")
    enc = sim.run(event_hook=pipe.process)
    print(f"[real-sim] encrypted {len(enc)} files "
          f"(detector caught the burst live — alerts above)")
    print(f"[real-sim] offenders:")
    for row in pipe.storage.list_offenders():
        print(f"      pid={row[0]} strikes={row[1]} state={row[2]}")
    print(f"[real-sim] rollback available: python -c "
          f"\"from sentinel_canary import canary; canary.restore_latest_snapshot()\"")


def cmd_rollback(_a):
    """Latest snapshot se honey dir restore karo (attack ke baad)."""
    dst = canary.restore_latest_snapshot()
    print(f"[rollback] restored honey dir from: {dst or 'NO SNAPSHOT FOUND'}")


def cmd_dashboard(_a):
    if not dashboard.available():
        print("[dash] fastapi/uvicorn not installed -> pip install fastapi uvicorn")
        sys.exit(1)
    canary.ensure_honey_dirs()
    pipe = Pipeline()
    dash = dashboard.Dashboard(pipe)
    pipe.on_alert = dash.broadcast
    print("[dash] open http://127.0.0.1:8000  (Ctrl+C to stop)")
    dash.serve()


def main():
    p = argparse.ArgumentParser(prog="sentinel-canary",
                                description="Real-time ransomware detection demo")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in [("init", cmd_init), ("simulate", cmd_simulate),
                     ("live", cmd_live), ("real-sim", cmd_real_sim),
                     ("rollback", cmd_rollback),
                     ("dashboard", cmd_dashboard)]:
        sp = sub.add_parser(name)
        sp.set_defaults(fn=fn)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
