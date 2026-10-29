# watcher.py
# LIVE filesystem watcher — watchdog library (guarded import).
# Honey dir pe file events ko pipeline.process() me bhejta hai.
# watchdog na ho toh ye module gracefully disabled rehta hai.

import os

from . import config
from .detector import file_entropy

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    _HAVE_WATCHDOG = True
except Exception:
    _HAVE_WATCHDOG = False


def available() -> bool:
    return _HAVE_WATCHDOG


if _HAVE_WATCHDOG:
    class _Handler(FileSystemEventHandler):
        """watchdog events ko pipeline ke event format me convert karta hai."""

        def __init__(self, process):
            self.process = process  # pipeline.process function

        def _emit(self, etype, path):
            ev = {
                "type": etype,
                "path": path,
                "pid": os.getpid(),     # watcher ka apna pid (live me real pid alag se nikalna complex hai)
                "entropy": file_entropy(path),
            }
            self.process(ev)

        def on_modified(self, e):
            if not e.is_directory:
                self._emit("modified", e.src_path)

        def on_created(self, e):
            if not e.is_directory:
                self._emit("created", e.src_path)

        def on_moved(self, e):
            if not e.is_directory:
                self._emit("moved", e.dest_path)

        def on_deleted(self, e):
            if not e.is_directory:
                self._emit("deleted", e.src_path)


def run_live(process, stop_event=None):
    """
    Honey dir ko watch karo aur events pipeline ko feed karo.
    Ctrl+C ya stop_event tak chalta rehta hai.
    """
    if not _HAVE_WATCHDOG:
        raise RuntimeError("watchdog not installed — live mode unavailable")
    obs = Observer()
    obs.schedule(_Handler(process), config.HONEY_DIR, recursive=True)
    obs.start()
    try:
        import time
        while True:
            if stop_event and stop_event.is_set():
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        obs.stop()
        obs.join()
