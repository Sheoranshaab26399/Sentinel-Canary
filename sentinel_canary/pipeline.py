# pipeline.py
# Poora detection->scoring->mitigation->storage->alert pipeline yahin chalta hai.
# Simulator aur live watcher dono isi ko feed karte hain — ek hi logic.

import time

from . import config, canary
from .detector import Detector
from .mitigation import Mitigator
from .storage import Storage
from . import alerter


class Pipeline:
    def __init__(self, storage: Storage = None, on_alert=None):
        self.detector = Detector()
        self.mitigator = Mitigator()
        self.storage = storage or Storage()
        # on_alert = optional callback (dashboard live updates ke liye)
        self.on_alert = on_alert
        self.stats = {"events": 0, "alerts": 0}

    def process(self, ev: dict) -> dict:
        """
        Ek file event poora process karo:
        score -> (alert ho toh) mitigate -> store -> notify.
        Return: result dict.
        """
        res = self.detector.score(ev)
        self.stats["events"] += 1

        mit = {"pid": ev.get("pid"), "strikes": 0, "state": "watch", "action": "none"}
        if res["alert"]:
            self.stats["alerts"] += 1
            mit = self.mitigator.record_alert(ev.get("pid", 0))
            self.storage.upsert_offender(mit["pid"], mit["strikes"], mit["state"])
            alerter.fire_alert(ev, res, mit)

        # har event store karo (forensics)
        self.storage.log_event(ev, res)

        out = {"event": ev, "result": res, "mitigation": mit}
        if self.on_alert:
            try:
                self.on_alert(out)
            except Exception:
                pass
        return out

    def run_events(self, events, delay: float = 0.0):
        """Event list ko sequentially process karo. delay har event ke beech."""
        for ev in events:
            self.process(ev)
            if delay:
                time.sleep(delay)
        return self.stats
