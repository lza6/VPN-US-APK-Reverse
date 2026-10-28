"""Round-1 reachability/latency scan for both pools.

  gp : self-hosted fleet -> probe :443 (VLESS+REALITY) and :1080 (SOCKS5)
  se : VPNGate public relays -> probe the TCP port advertised in the record

Reachability is NOT usability: a TCP handshake proves nothing about the
protocol layer (see docs/REVERSE_REPORT.md section 3). This host's egress is
heavily filtered, so a timeout here must never be read as "node is dead" --
re-run behind a clean egress before publishing numbers.

usage:  python tools/stress.py [--workers 60] [--timeout 3]
"""
import argparse
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import client  # noqa: E402

BULLET = "•"


def load(path=None):
    path = path or client.SNAPSHOT
    d = json.load(open(path, encoding="utf8"))
    gp, se = [], []
    for line in d.get("serversgp", "").split("\n"):
        if BULLET not in line:
            continue
        f = line.split(BULLET)
        gp.append(dict(code=f[0], port=int(f[1]), city=f[6], country=f[7], isp=f[8],
                       continent=f[9], load=f[10], dual=f[11], ip=f[13],
                       ip6=f[14] if len(f) > 14 else ""))
    for line in d.get("serversse", "").split("\n"):
        if BULLET not in line:
            continue
        f = line.split(BULLET)
        m = re.match(r"TCP:(\d+)/UDP:(\d+)", f[4]) if len(f) > 4 else None
        se.append(dict(id=f[0], host=f[1], sessions=f[2], ping=f[3],
                       tcp=int(m.group(1)) if m else 0, udp=int(m.group(2)) if m else 0,
                       country=f[5], ip=f[6] if len(f) > 6 else ""))
    return d, gp, se


def tcp_probe(ip, port, timeout):
    t0 = time.time()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True, round((time.time() - t0) * 1000)
    except Exception:
        return False, round((time.time() - t0) * 1000)


def scan(items, port_key, workers, timeout, label):
    def job(it):
        ok, ms = tcp_probe(it["ip"], it[port_key], timeout)
        return dict(it, ok=ok, ms=ms)

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        res = list(ex.map(job, items))
    alive = [r for r in res if r["ok"]]
    lats = sorted(r["ms"] for r in alive)
    msg = f"[{label}] {len(alive)}/{len(items)} TCP-alive in {time.time()-t0:.1f}s"
    if lats:
        msg += f" | p50={lats[len(lats)//2]}ms p95={lats[int(len(lats)*0.95)]}ms"
    print(msg)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=60)
    ap.add_argument("--timeout", type=float, default=3.0)
    a = ap.parse_args()
    d, gp, se = load()
    print(f"gp={len(gp)} se={len(se)}")
    out = {
        "gp:443": scan([dict(x, p=443) for x in gp], "p", a.workers, a.timeout, "gp:443"),
        "gp:1080": scan([dict(x, p=1080) for x in gp], "p", a.workers, a.timeout, "gp:1080"),
        "se": scan([dict(x, p=x["tcp"]) for x in se if x["tcp"]], "p",
                   max(a.workers, 80), a.timeout, "se:tcp"),
    }
    path = os.path.join(client.WORK, "stress_round1.json")
    json.dump(out, open(path, "w"), indent=1)
    print("wrote", path)


if __name__ == "__main__":
    main()
