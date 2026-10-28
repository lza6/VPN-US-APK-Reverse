"""SOCKS5 handshake + exit-IP check for the gp pool's :1080 service.

The App ships `userpassgp` for the OpenVPN path; whether the same pair opens the
SOCKS5 listener is exactly what this script answers (R1 answer: it does not --
see docs/REVERSE_REPORT.md).

usage:  python tools/probe_socks.py [N] [--user U --pass P] [--relay 127.0.0.1:10808]
        --relay dials the node through a local SOCKS5 (needed on filtered egress)
"""
import argparse
import json
import os
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import client  # noqa: E402

BULLET = "•"


def parse_pool(path=None):
    snap = json.load(open(path or client.SNAPSHOT, encoding="utf8"))
    user, pwd = (snap.get("userpassgp") or "/").split("/", 1)
    out = []
    for line in snap.get("serversgp", "").split("\n"):
        if BULLET not in line:
            continue
        f = line.split(BULLET)
        out.append(dict(code=f[0], port=int(f[1]), city=f[6], country=f[7], isp=f[8],
                        load=f[10], iptype=f[11], ip=f[13]))
    return user, pwd, out


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise OSError("eof")
        buf += chunk
    return buf


def socks5_connect(host, port, dst_host, dst_port, user=None, pwd=None, timeout=12, chain=None):
    if chain:
        s = socks5_connect(chain[0], chain[1], host, port, chain[2], chain[3], timeout)
    else:
        s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x02\x00\x02")
    _ver, method = _recv_exact(s, 2)
    if method == 0x02:
        if not user:
            raise OSError("auth required but no credentials given")
        u, p = user.encode(), pwd.encode()
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        if _recv_exact(s, 2)[1] != 0:
            raise OSError("socks auth failed")
    elif method != 0x00:
        raise OSError(f"no acceptable auth method ({method})")
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(dst_host)]) + dst_host.encode()
              + struct.pack(">H", dst_port))
    head = _recv_exact(s, 4)
    if head[1] != 0:
        raise OSError(f"socks rep {head[1]}")
    if head[3] == 1:
        _recv_exact(s, 4)
    elif head[3] == 3:
        _recv_exact(s, _recv_exact(s, 1)[0])
    elif head[3] == 4:
        _recv_exact(s, 16)
    _recv_exact(s, 2)
    return s


def http_get_via(s, host, path="/json", timeout=15):
    s.settimeout(timeout)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8\r\n"
              f"Connection: close\r\n\r\n".encode())
    data = b""
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def probe(node, user, pwd, chain=None, target=("ip-api.com", 80)):
    t0 = time.time()
    try:
        s = socks5_connect(node["ip"], node["port"], target[0], target[1], user, pwd, chain=chain)
        raw = http_get_via(s, target[0])
        s.close()
        body = raw.split(b"\r\n\r\n", 1)[-1].decode("utf8", "replace")
        info = {}
        if "{" in body and "}" in body:
            info = json.loads(body[body.find("{"):body.rfind("}") + 1])
        return dict(ok=True, node=node, latency_ms=round((time.time() - t0) * 1000),
                    exit_ip=info.get("query"), country=info.get("country"), isp=info.get("isp"))
    except Exception as e:
        return dict(ok=False, node=node, error=f"{type(e).__name__}: {e}",
                    latency_ms=round((time.time() - t0) * 1000))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("n", nargs="?", type=int, default=10)
    ap.add_argument("--user")
    ap.add_argument("--pass", dest="pwd")
    ap.add_argument("--relay", default=os.environ.get("VPNUS_RELAY"))
    a = ap.parse_args()
    user, pwd, nodes = parse_pool()
    user, pwd = a.user or user, a.pwd or pwd
    chain = None
    if a.relay:
        h, p = a.relay.split(":")
        chain = (h, int(p), None, None)
    print(f"pool={len(nodes)} user={user} relay={a.relay or 'direct'}")
    with ThreadPoolExecutor(max_workers=10) as ex:
        res = list(ex.map(lambda nd: probe(nd, user, pwd, chain=chain), nodes[:a.n]))
    for r in res:
        if r["ok"]:
            print(f"OK   {r['node']['code']:8s} {r['node']['ip']:16s} {r['latency_ms']:5d}ms "
                  f"exit={r['exit_ip']} {r['country']}")
        else:
            print(f"FAIL {r['node']['code']:8s} {r['node']['ip']:16s} {r['latency_ms']:5d}ms "
                  f"{r['error'][:70]}")
    print(f"alive {sum(1 for r in res if r['ok'])}/{len(res)}")
