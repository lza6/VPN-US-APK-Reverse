"""Local TCP forwarder: 127.0.0.1:<lport> -> socks5 chain (127.0.0.1:10808) -> host:port

Lets a client (mihomo/xray) dial a node as if it were local, while the actual
TCP path goes through the local proxy. Needed because this host cannot reach
most of the pool directly.
"""
import selectors
import socket
import struct
import threading


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise OSError("eof")
        buf += c
    return buf


def chain_open(relay_host, relay_port, host, port, timeout=30):
    s = socket.create_connection((relay_host, relay_port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    ver, method = _recv_exact(s, 2)
    if method != 0:
        raise OSError(f"relay method {method}")
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + struct.pack(">H", port))
    head = _recv_exact(s, 4)
    if head[1] != 0:
        raise OSError(f"relay rep {head[1]}")
    atyp = head[3]
    if atyp == 1:
        _recv_exact(s, 4)
    elif atyp == 3:
        _recv_exact(s, _recv_exact(s, 1)[0])
    elif atyp == 4:
        _recv_exact(s, 16)
    _recv_exact(s, 2)
    s.settimeout(None)
    return s


class Forwarder:
    def __init__(self, lport, host, port, relay=("127.0.0.1", 10808)):
        self.lport, self.host, self.port, self.relay = lport, host, port, relay
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", lport))
        self.srv.listen(64)
        self._stop = False
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self):
        while not self._stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        try:
            u = chain_open(*self.relay, self.host, self.port)
        except Exception:
            c.close()
            return
        sel = selectors.DefaultSelector()
        sel.register(c, selectors.EVENT_READ, u)
        sel.register(u, selectors.EVENT_READ, c)
        try:
            while True:
                for key, _ev in sel.select(timeout=120):
                    src, dst = key.fileobj, key.data
                    data = src.recv(65536)
                    if not data:
                        return
                    dst.sendall(data)
        except Exception:
            pass
        finally:
            sel.close()
            for s in (c, u):
                try:
                    s.close()
                except OSError:
                    pass

    def close(self):
        self._stop = True
        try:
            self.srv.close()
        except OSError:
            pass
