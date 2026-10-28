"""Demo console for the harvested pools -- stdlib only.

  python demo/server.py            -> http://127.0.0.1:8950
  PORT=9000 python demo/server.py

Endpoints
  GET  /                      demo page
  GET  /api/status            pool summary + last scan
  POST /api/harvest           re-run INITIALIZE (fresh device id), store snapshot
  POST /api/scan              TCP reachability scan (gp:443 / gp:1080 / se:tcp)
  GET  /api/nodes?pool=gp|se  node rows
  GET  /api/export?pool=gp&fmt=plain|json|mihomo
"""
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(WORK, "tools"))
import client  # noqa: E402
import gen_mihomo  # noqa: E402
import stress  # noqa: E402

STATE = {"snapshot": None, "scan": None, "scan_ts": 0}
LOCK = threading.Lock()


def snapshot():
    if STATE["snapshot"] is None:
        if os.path.exists(client.SNAPSHOT):
            STATE["snapshot"] = json.load(open(client.SNAPSHOT, encoding="utf8"))
        else:
            STATE["snapshot"] = harvest()
    return STATE["snapshot"]


def harvest():
    u, h = client.device_ids()
    txt, gw = client.call("INITIALIZE", 1, u, h, verbose=False)
    if not txt:
        raise RuntimeError("INITIALIZE returned nothing from all gateways")
    snap = json.loads(txt)
    snap["_device"] = {"uuid": u, "hashed": h}
    snap["_gateway"] = gw
    snap["_ts"] = int(time.time())
    with open(client.SNAPSHOT, "w", encoding="utf8") as f:
        json.dump(snap, f)
    with LOCK:
        STATE["snapshot"] = snap
    return snap


def pools(snap):
    gp, se = [], []
    for line in snap.get("serversgp", "").split("\n"):
        if "•" not in line:
            continue
        f = line.split("•")
        gp.append(dict(code=f[0], port=int(f[1]), city=f[6], country=f[7], isp=f[8],
                       continent=f[9], load=f[10], dual=f[11], ip=f[13],
                       ip6=f[14] if len(f) > 14 else ""))
    for line in snap.get("serversse", "").split("\n"):
        if "•" not in line:
            continue
        f = line.split("•")
        m = re.match(r"TCP:(\d+)/UDP:(\d+)", f[4]) if len(f) > 4 else None
        se.append(dict(id=f[0], host=f[1], sessions=f[2], ping=f[3],
                       tcp=int(m.group(1)) if m else 0, udp=int(m.group(2)) if m else 0,
                       country=f[5], ip=f[6] if len(f) > 6 else ""))
    return gp, se


class Handler(BaseHTTPRequestHandler):
    server_version = "vpnus-demo/1.0"

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        data = body.encode("utf8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            p = os.path.join(HERE, "index.html")
            return self._send(200, open(p, "rb").read(), "text/html; charset=utf-8")
        snap = snapshot()
        gp, se = pools(snap)
        if u.path == "/api/status":
            return self._send(200, {
                "gateway": snap.get("_gateway"), "harvest_ts": snap.get("_ts"),
                "gp_total": len(gp), "se_total": len(se),
                "gp_unique_ip": len({n["ip"] for n in gp}),
                "se_unique_ip": len({n["ip"] for n in se}),
                "refresh_seconds": {"gp": snap.get("timegp"), "se": snap.get("timese")},
                "clientip_seen_by_upstream": snap.get("clientip"),
                "scan": STATE["scan"], "scan_ts": STATE["scan_ts"],
            })
        if u.path == "/api/nodes":
            pool = q.get("pool", ["gp"])[0]
            items = gp if pool == "gp" else se
            return self._send(200, {"pool": pool, "count": len(items), "items": items[:3000]})
        if u.path == "/api/export":
            pool = q.get("pool", ["gp"])[0]
            fmt = q.get("fmt", ["plain"])[0]
            items = gp if pool == "gp" else se
            if fmt == "json":
                return self._send(200, items)
            if fmt == "mihomo":
                cfg = gen_mihomo.build(items, gen_mihomo.reality_from(snap), snap.get("v2rayuuid1"))
                return self._send(200, json.dumps(cfg, indent=1), "text/yaml; charset=utf-8")
            lines = [f"# pool={pool} exported={time.strftime('%Y-%m-%d %H:%M:%S')}"]
            for n in items:
                if pool == "gp":
                    lines.append(f"# {n['code']} {n['ip']}:1080 {n['city']} {n['country']}")
                else:
                    lines.append(f"# {n['id']} {n['host']} {n['ip']}:{n['tcp']} {n['country'].split(' | ')[0]}")
            return self._send(200, "\n".join(lines) + "\n", "text/plain; charset=utf-8")
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/harvest":
            try:
                snap = harvest()
                gp, se = pools(snap)
                return self._send(200, {"ok": True, "gp": len(gp), "se": len(se),
                                        "gateway": snap.get("_gateway")})
            except Exception as e:
                return self._send(500, {"ok": False, "error": f"{type(e).__name__}: {e}"})
        if u.path == "/api/scan":
            snap = snapshot()
            gp, se = pools(snap)
            res = {
                "gp:443": stress.scan([dict(x, p=443) for x in gp], "p", 60, 3.0, "gp:443"),
                "gp:1080": stress.scan([dict(x, p=1080) for x in gp], "p", 60, 3.0, "gp:1080"),
                "se": stress.scan([dict(x, p=x["tcp"]) for x in se if x["tcp"]], "p", 80, 3.0, "se:tcp"),
            }
            summary = {k: {"alive": sum(1 for r in v if r["ok"]), "total": len(v)}
                       for k, v in res.items()}
            with LOCK:
                STATE["scan"] = res
                STATE["scan_ts"] = int(time.time())
            return self._send(200, {"ok": True, "summary": summary, "ts": STATE["scan_ts"]})
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8950"))
    print(f"demo console on http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
