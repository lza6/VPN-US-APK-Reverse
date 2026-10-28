"""gp pool -> Xray-core config (VLESS+REALITY, one socks inbound per node).

Xray has no 5s dial budget (mihomo does), and `sockopt.dialerProxy` lets each
node be dialled through a local relay -- handy when your own egress cannot reach
the fleet directly.

usage:  python tools/gen_xray.py [NODE_COUNT] [--relay 127.0.0.1:10808]
        xray run -c xray_gp.json
Then:   curl -x socks5h://127.0.0.1:32201 https://ipinfo.io
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import client  # noqa: E402
import gen_mihomo as G  # noqa: E402


def build(nodes, reality, uuid, base_port=32201, relay=None):
    inbounds, outbounds = [], []
    if relay:
        host, port = relay.split(":")
        outbounds.append({"tag": "relay", "protocol": "socks",
                          "settings": {"servers": [{"address": host, "port": int(port)}]}})
    for i, n in enumerate(nodes):
        inbounds.append({"tag": f"in{i}", "port": base_port + i, "listen": "127.0.0.1",
                         "protocol": "socks", "settings": {"auth": "noauth", "udp": True}})
        stream = {"network": "tcp", "security": "reality",
                  "realitySettings": {"serverName": reality["sni"], "fingerprint": reality["fp"],
                                      "publicKey": reality["pbk"], "shortId": reality["sid"],
                                      "spiderX": ""}}
        if relay:
            stream["sockopt"] = {"dialerProxy": "relay"}
        outbounds.append({"tag": f"node{i}", "protocol": "vless",
                          "settings": {"vnext": [{"address": n["ip"], "port": 443, "users": [
                              {"id": uuid, "encryption": "none", "flow": reality["flow"]}]}]},
                          "streamSettings": stream})
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    rules = [{"type": "field", "inboundTag": [f"in{i}"], "outboundTag": f"node{i}"}
             for i in range(len(nodes))]
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds,
            "outbounds": outbounds, "routing": {"rules": rules}}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("count", nargs="?", type=int, default=8)
    ap.add_argument("--relay", default=os.environ.get("VPNUS_RELAY"))
    a = ap.parse_args()
    snap, reality, nodes = G.load_pool()
    cfg = build(nodes[:a.count], reality, snap["v2rayuuid1"], relay=a.relay)
    out = os.path.join(client.WORK, "xray_gp.json")
    json.dump(cfg, open(out, "w", encoding="utf8"), indent=1)
    print(f"{out}: {a.count} nodes, relay={a.relay or 'direct'}")
