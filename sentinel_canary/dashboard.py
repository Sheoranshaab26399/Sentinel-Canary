# dashboard.py
# FastAPI + self-contained index.html (koi CDN/build nahi) + WebSocket live updates.
# Browser se simulation start/stop kar sakte ho. fastapi na ho toh disabled.

import asyncio
import threading

from . import config

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse
    import uvicorn
    _HAVE = True
except Exception:
    _HAVE = False


def available() -> bool:
    return _HAVE


# Self-contained HTML — saara CSS/JS inline, light theme, no CDN.
_INDEX = """<!doctype html><html><head><meta charset=utf-8>
<title>Sentinel-Canary</title><style>
body{font-family:system-ui;margin:24px;background:#f6f8fa;color:#111}
h1{font-size:20px} .cards{display:flex;gap:12px;margin:12px 0}
.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:12px;flex:1}
.card b{font-size:26px}
button{padding:8px 14px;border-radius:6px;border:1px solid #888;background:#0b5;color:#fff;cursor:pointer}
button.stop{background:#c33}
table{width:100%;border-collapse:collapse;background:#fff;font-size:13px}
td,th{border:1px solid #e5e5e5;padding:6px;text-align:left}
tr.alert{background:#ffe9e9}
.tag{padding:2px 6px;border-radius:4px;background:#eef;font-size:11px}
</style></head><body>
<h1>&#128737; Sentinel-Canary — Live Ransomware Detection</h1>
<div class=cards>
 <div class=card>Events<br><b id=c_ev>0</b></div>
 <div class=card>Alerts<br><b id=c_al>0</b></div>
 <div class=card>Status<br><b id=c_st>idle</b></div>
</div>
<button onclick="fetch('/start',{method:'POST'})">&#9654; Start Simulation</button>
<button class=stop onclick="fetch('/stop',{method:'POST'})">&#9632; Stop</button>
<h3>Live feed</h3>
<table><thead><tr><th>time</th><th>pid</th><th>event</th><th>path</th>
<th>entropy</th><th>score</th><th>action</th><th>reasons</th></tr></thead>
<tbody id=feed></tbody></table>
<script>
let ws=new WebSocket('ws://'+location.host+'/ws');
ws.onmessage=e=>{let d=JSON.parse(e.data);
 if(d.stats){c_ev.textContent=d.stats.events;c_al.textContent=d.stats.alerts;
   c_st.textContent=d.stats.running?'running':'idle';}
 if(d.row){let t=document.createElement('tr');
  if(d.row.alert)t.className='alert';
  t.innerHTML='<td>'+d.row.time+'</td><td>'+d.row.pid+'</td><td>'+d.row.etype+
   '</td><td>'+d.row.path+'</td><td>'+d.row.entropy+'</td><td><b>'+d.row.score+
   '</b></td><td><span class=tag>'+d.row.action+'</span></td><td>'+d.row.reasons+'</td>';
  feed.prepend(t);}};
</script></body></html>"""


class Dashboard:
    def __init__(self, pipeline):
        self.pipe = pipeline
        self.clients = set()
        self.running = False
        self._thread = None
        self._loop = None
        if _HAVE:
            self.app = self._build()

    def _build(self):
        app = FastAPI(title="Sentinel-Canary")

        @app.get("/", response_class=HTMLResponse)
        def home():
            return _INDEX

        @app.post("/start")
        def start():
            self.start_sim()
            return {"ok": True}

        @app.post("/stop")
        def stop():
            self.running = False
            return {"ok": True}

        @app.websocket("/ws")
        async def ws(ws: WebSocket):
            await ws.accept()
            self.clients.add(ws)
            try:
                while True:
                    await ws.receive_text()
            except WebSocketDisconnect:
                self.clients.discard(ws)
            except Exception:
                self.clients.discard(ws)
        return app

    # pipeline se alert aaya toh sab clients ko bhejo
    def broadcast(self, out: dict):
        if not self._loop:
            return
        ev, res, mit = out["event"], out["result"], out["mitigation"]
        import time as _t
        payload = {
            "stats": {"events": self.pipe.stats["events"],
                      "alerts": self.pipe.stats["alerts"],
                      "running": self.running},
            "row": {
                "time": _t.strftime("%H:%M:%S"),
                "pid": ev.get("pid"), "etype": ev.get("type"),
                "path": ev.get("path"), "entropy": res.get("entropy"),
                "score": res.get("score"), "alert": res.get("alert"),
                "action": mit.get("action"), "reasons": "; ".join(res.get("reasons", [])),
            },
        }
        asyncio.run_coroutine_threadsafe(self._send(payload), self._loop)

    async def _send(self, payload):
        import json
        dead = []
        for ws in self.clients:
            try:
                await ws.send_text(json.dumps(payload))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)

    def start_sim(self):
        """Background thread me simulator chalao."""
        if self.running:
            return
        from .simulator import EventSimulator
        self.running = True

        def _run():
            sim = EventSimulator()
            for ev in sim.events():
                if not self.running:
                    break
                self.pipe.process(ev)
                import time; time.sleep(0.15)
            self.running = False
            self.broadcast({"event": {}, "result": {}, "mitigation": {}})

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()

    def serve(self, host="127.0.0.1", port=8000):
        self._loop = asyncio.new_event_loop()
        def _set():
            asyncio.set_event_loop(self._loop)
        cfg = uvicorn.Config(self.app, host=host, port=port, log_level="warning")
        server = uvicorn.Server(cfg)
        # loop ko server thread me capture karo taaki broadcast kaam kare
        async def _run():
            self._loop = asyncio.get_event_loop()
            await server.serve()
        asyncio.run(_run())
