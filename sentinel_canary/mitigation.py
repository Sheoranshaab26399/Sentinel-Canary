# mitigation.py
# fail2ban-style escalation: watchlist -> temp block -> permanent block.
# App-level by default (root nahi chahiye). Optional process-kill bhi.

import time

from . import config

# Offender states
WATCH = "watch"
TEMP = "temp_blocked"
PERM = "permanent"


class Mitigator:
    """
    Har PID ka state track karta hai aur escalate karta hai.
    strikes badhte hi: watch -> temp_blocked -> permanent.
    """

    def __init__(self):
        # pid -> {'strikes':int, 'state':str, 'until':float}
        self.offenders = {}

    def _get(self, pid):
        return self.offenders.setdefault(
            pid, {"strikes": 0, "state": WATCH, "until": 0.0}
        )

    def record_alert(self, pid: int) -> dict:
        """
        Ek alert record karo aur decide karo kya action lena hai.
        Return: {'pid', 'strikes', 'state', 'action'}
        """
        o = self._get(pid)
        o["strikes"] += 1
        action = "none"

        if o["strikes"] >= config.STRIKES_FOR_PERM:
            o["state"] = PERM
            action = "permanent_block"
            if config.KILL_PROCESS:
                self._kill(pid)
        elif o["strikes"] >= config.STRIKES_FOR_TEMP:
            o["state"] = TEMP
            o["until"] = time.time() + config.TEMP_BLOCK_SECONDS
            action = f"temp_block_{config.TEMP_BLOCK_SECONDS}s"
            if config.KILL_PROCESS:
                self._kill(pid)
        else:
            o["state"] = WATCH
            action = "watchlist"

        return {"pid": pid, "strikes": o["strikes"],
                "state": o["state"], "action": action}

    def is_blocked(self, pid: int) -> bool:
        """Kya pid abhi blocked hai? temp ka time check karta hai."""
        o = self.offenders.get(pid)
        if not o:
            return False
        if o["state"] == PERM:
            return True
        if o["state"] == TEMP:
            if time.time() < o["until"]:
                return True
            # temp khatam -> wapas watch
            o["state"] = WATCH
        return False

    def _kill(self, pid: int):
        """Process terminate karo — psutil ho toh best, warna os.kill."""
        try:
            import psutil  # guarded optional dep
            try:
                psutil.Process(pid).terminate()
            except Exception:
                pass
        except Exception:
            import os, signal
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
