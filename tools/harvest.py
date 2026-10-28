"""One-shot harvest: INITIALIZE -> snapshot.json + gp/se tsv.

usage:  python tools/harvest.py [NOTE] [MAGICNUM]
        python tools/harvest.py RELOADLIST 1
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import client  # noqa: E402

BULLET = "•"


def main(note="INITIALIZE", magic=1):
    u, h = client.device_ids()
    print(f"device uuid={u} hashed={h} adsids={client.ADSIDS}")
    txt, gw = client.call(note, magic, u, h, verbose=True)
    if not txt:
        print("FAILED: every gateway returned an empty body "
              "(wrong adsids / rotated key / upstream blocked)")
        return 1
    d = json.loads(txt)
    d["_device"] = {"uuid": u, "hashed": h}
    d["_gateway"] = gw
    d["_ts"] = int(time.time())
    with open(client.SNAPSHOT, "w", encoding="utf8") as f:
        json.dump(d, f)
    gp = [l.split(BULLET) for l in d.get("serversgp", "").split("\n") if l.strip()]
    se = [l.split(BULLET) for l in d.get("serversse", "").split("\n") if l.strip()]
    with open(os.path.join(client.WORK, "gp_nodes.tsv"), "w", encoding="utf8") as f:
        f.write("\n".join("\t".join(r) for r in gp))
    with open(os.path.join(client.WORK, "se_nodes.tsv"), "w", encoding="utf8") as f:
        f.write("\n".join("\t".join(r) for r in se))
    print(f"gp={len(gp)} se={len(se)} -> snapshot.json / gp_nodes.tsv / se_nodes.tsv")
    print(f"gateway={gw}")
    return 0


if __name__ == "__main__":
    note = sys.argv[1] if len(sys.argv) > 1 else "INITIALIZE"
    magic = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    raise SystemExit(main(note, magic))
