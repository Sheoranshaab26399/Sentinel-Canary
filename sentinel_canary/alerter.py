# alerter.py
# Alerts bhejta hai — console pe hamesha, desktop notification optional (guarded).

import logging
import os

from . import config

os.makedirs(os.path.dirname(config.LOG_PATH), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(config.LOG_PATH),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("sentinel")


def notify(title: str, msg: str):
    """
    Desktop notification — plyer ho toh. Nahi ho toh chupchaap skip.
    (guarded import — core iske bina bhi chalega)
    """
    if not config.USE_NOTIFY:
        return
    try:
        from plyer import notification  # optional dep
        notification.notify(title=title, message=msg, timeout=5)
    except Exception:
        pass  # notify na ho toh bhi theek hai


def fire_alert(ev: dict, res: dict, mit: dict):
    """
    Alert fire karo: log + console + (optional) desktop.
    """
    line = (
        f"[ALERT] pid={ev.get('pid')} score={res['score']} "
        f"path={ev.get('path')} | reasons: {', '.join(res['reasons'])} "
        f"| action={mit.get('action')}"
    )
    log.warning(line)
    notify("Sentinel-Canary ALERT",
           f"pid {ev.get('pid')} score {res['score']} — {mit.get('action')}")
