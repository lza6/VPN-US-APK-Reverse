"""Reference health-loop for a socks5 proxy list (the missing half of new-api).

new-api does not verify residential/static sources: `proxy_pool.go` TraceProbes()
skips every entry whose source != "free", and everything loaded from
TRYINGOPEN_PROXY_FILE gets source="residential". So a dead node in your list is
selected forever and shows up as "channel times out". This script is the thing
that rewrites the list for it.

Rules implemented (all four matter):
  1. real SOCKS5 handshake (+ optional user:pass) then a real HTTP fetch --
     TCP connect alone proves nothing;
  2. exit IP check: `--require-exit-eq-node` drops anything whose exit IP is not
     the node IP (catches an upstream silently turning your node into a relay);
  3. dual threshold: a node is dropped only after N consecutive failures
     (default 2, tolerate jitter), BUT a node that has never passed is not
     written to the pool at all on round 1;
  4. atomic rewrite (os.replace) so new-api never reads a half-written file.

usage:
  python tools/health_loop.py --in proxies.txt --out proxies_alive.txt
  python tools/health_loop.py --in proxies.txt --out proxies_alive.txt \
      --require-exit-eq-node --fail-threshold 2 --loop 300

note: new-api only reloads the list on startup / config change, so pair this with
a daily container restart (see docs/NEWAPI_INTEGRATION.md §6).
"""
import argparse
import json
import os
import re
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

STATE_VERSION = 1


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise OSError("eof")
        buf += c
    return buf


def socks5_open(host, port, dst_host, dst_port, user=None, pwd=None, timeout=10):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
    _v, method = recv_exact(s, 2)
    if method == 0x02:
        if not user:
            raise OSError("auth required")
        u, p = user.encode(), (pwd or "").encode()
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        if recv_exact(s, 2)[1] != 0:
            raise OSError("auth failed")
    elif method != 0x00:
        raise OSError(f"method {method}")
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(dst_host)]) + dst_host.encode()
              + struct.pack(">H", dst_port))
    head = recv_exact(s, 4)
    if head[1] != 0:
        raise OSError(f"rep {head[1]}")
    if head[3] == 1:
        recv_exact(s, 4)
    elif head[3] == 3:
        recv_exact(s, recv_exact(s, 1)[0])
    elif head[3] == 4:
        recv_exact(s, 16)
    recv_exact(s, 2)
    return s


def http_get(s, host, path, timeout=10):
    s.settimeout(timeout)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: health-loop\r\n"
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
    return data.split(b"\r\n\r\n", 1)[-1]


def probe(raw, target_host="ip-api.com", target_port=80, path="/json?fields=query,country,isp",
          timeout=10):
    u = urlparse(raw if "://" in raw else "socks5://" + raw)
    host, port = u.hostname, u.port or 1080
    user, pwd = (u.username, u.password) if u.username else (None, None)
    t0 = time.time()
    try:
        s = socks5_open(host, port, target_host, target_port, user, pwd, timeout)
        try:
            body = http_get(s, target_host, path, timeout).decode("utf8", "replace")
        finally:
            s.close()
    except Exception as e:
        return dict(ok=False, ms=round((time.time() - t0) * 1000), node_ip=host,
                    error=f"{type(e).__name__}: {e}")
    m = re.search(r"\{.*\}", body, re.S)
    info = json.loads(m.group()) if m else {}
    return dict(ok=True, ms=round((time.time() - t0) * 1000),
                exit_ip=info.get("query"), country=info.get("country"),
                isp=info.get("isp"), node_ip=host)


def load_state(path):
    if os.path.exists(path):
        try:
            st = json.load(open(path, encoding="utf8"))
            if st.get("version") == STATE_VERSION:
                return st
        except Exception:
            pass
    return {"version": STATE_VERSION, "nodes": {}}


def save_state(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf8") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, path)


def write_pool(path, entries):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf8") as f:
        f.write(f"# rewritten by health_loop at {time.strftime('%Y-%m-%d %H:%M:%S')} "
                f"({len(entries)} alive)\n")
        for e in entries:
            f.write(e + "\n")
    os.replace(tmp, path)


def run_once(raws, args, state):
    nodes = state["nodes"]
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda r: (r, probe(r, timeout=args.timeout)), raws))

    alive, dropped, fresh_skip = [], [], []
    for raw, res in results:
        st = nodes.setdefault(raw, {"ok_rounds": 0, "fail_streak": 0, "ever_ok": False,
                                    "last_ms": None, "exit_ip": None})
        if res["ok"] and (not args.require_exit_eq_node or res["exit_ip"] == res["node_ip"]):
            if res["exit_ip"] and res["node_ip"] == res["exit_ip"]:
                st["exit_ip_matched"] = True
            st["ok_rounds"] += 1
            st["fail_streak"] = 0
            st["ever_ok"] = True
            st["last_ms"] = res["ms"]
            st["exit_ip"] = res["exit_ip"]
            alive.append((raw, res["ms"]))
        else:
            st["fail_streak"] += 1
            st["last_error"] = res.get("error") or ("exit_mismatch"
                                                    if res["ok"] else "probe_failed")
            if not st["ever_ok"]:
                fresh_skip.append(raw)          # never passed -> never enters the pool
            elif st["fail_streak"] >= args.fail_threshold:
                dropped.append(raw)

    keep = sorted((a for a in alive), key=lambda x: x[1])
    return keep, dropped, fresh_skip, len(raws)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", required=True, help="input list, one socks5://host:port per line")
    ap.add_argument("--out", dest="dst", required=True, help="output list for TRYINGOPEN_PROXY_FILE")
    ap.add_argument("--state", default=None, help="state file (default: <out>.state.json)")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--fail-threshold", type=int, default=2)
    ap.add_argument("--require-exit-eq-node", action="store_true")
    ap.add_argument("--loop", type=int, default=0, help="seconds between rounds, 0 = run once")
    a = ap.parse_args()
    state_path = a.state or a.dst + ".state.json"
    out_dir = os.path.dirname(os.path.abspath(a.dst))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    while True:
        raws = [l.strip() for l in open(a.src, encoding="utf8")
                if l.strip() and not l.strip().startswith("#")]
        state = load_state(state_path)
        keep, dropped, fresh_skip, total = run_once(raws, a, state)
        write_pool(a.dst, [r for r, _ms in keep])
        save_state(state_path, state)
        p50 = keep[len(keep) // 2][1] if keep else None
        print(f"[{time.strftime('%H:%M:%S')}] total={total} alive={len(keep)} "
              f"dropped={len(dropped)} never-passed={len(fresh_skip)} p50={p50}ms -> {a.dst}")
        if not a.loop:
            break
        time.sleep(a.loop)


if __name__ == "__main__":
    main()
