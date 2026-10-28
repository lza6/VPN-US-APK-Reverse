"""gp pool -> mihomo config (VLESS+REALITY, one socks listener per node).

usage:  python tools/gen_mihomo.py [NODE_COUNT] [--relay 127.0.0.1:10808]
        mihomo -f mihomo_gp.yaml
Then curl through 127.0.0.1:32001.. :  curl -x socks5h://127.0.0.1:32001 https://ipinfo.io

Read the node IPs from your own harvest (snapshot.json); nothing is bundled here.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import client  # noqa: E402

BULLET = "\u2022"


def reality_from(snap):
    cfg = snap.get("v2raydfcfg", "")
    pick = lambda k: (re.search(r'"%s":"([^"]*)"' % k, cfg) or [None, None])[1]
    return {"sni": pick("serverName"), "pbk": pick("publicKey"), "sid": pick("shortId"),
            "fp": pick("fingerprint"), "flow": pick("flow")}


def load_pool(path=None):
    path = path or client.SNAPSHOT
    snap = json.load(open(path, encoding="utf8"))
    nodes = []
    for line in snap.get("serversgp", "").split("\n"):
        if BULLET not in line:
            continue
        f = line.split(BULLET)
        nodes.append(dict(code=f[0], port=int(f[1]), city=f[6], country=f[7], isp=f[8],
                          continent=f[9], load=f[10], iptype=f[11], ip=f[13]))
    return snap, reality_from(snap), nodes


def build(nodes, reality, uuid, base_port=32001, relay=None):
    proxies, listeners = [], []
    if relay:
        host, port = relay.split(":")
        proxies.append({"name": "relay", "type": "socks5", "server": host, "port": int(port), "udp": True})
    for i, n in enumerate(nodes):
        name = f"{n['code']}-{i}"
        p = {"name": name, "type": "vless", "server": n["ip"], "port": 443, "uuid": uuid,
             "network": "tcp", "tls": True, "udp": True, "flow": reality["flow"],
             "servername": reality["sni"], "client-fingerprint": reality["fp"],
             "reality-opts": {"public-key": reality["pbk"], "short-id": reality["sid"]}}
        if relay:
            p["dialer-proxy"] = "relay"
        proxies.append(p)
        listeners.append({"name": f"in{i}", "type": "socks", "port": base_port + i,
                          "listen": "127.0.0.1", "proxy": name, "udp": True})
    return {"mixed-port": 0, "mode": "direct", "log-level": "warning",
            "proxies": proxies, "listeners": listeners}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("count", nargs="?", type=int, default=8)
    ap.add_argument("--relay", default=os.environ.get("VPNUS_RELAY"))
    a = ap.parse_args()
    snap, reality, nodes = load_pool()
    cfg = build(nodes[:a.count], reality, snap["v2rayuuid1"], relay=a.relay)
    out = os.path.join(client.WORK, "mihomo_gp.yaml")
    json.dump(cfg, open(out, "w", encoding="utf8"), indent=1)
    print(f"{out}: {a.count} nodes, reality sni={reality['sni']} flow={reality['flow']}")
