"""VPN US (com.giamping.usavpn) API client -- research / interoperability only.

Protocol (see docs/PROTOCOL.md):

    GET {gateway}?message=<M>
    M       = base64( AES-256-CBC/PKCS5( plaintext ) )  with '+' replaced by "CRYPTO"
    plain   = "magicnum=<n>&" + params + [extra] + "&note=<NOTE>"
    params  = "&unixtime=<ms>&uuid=<uuid>&hashed=<md5(uuid)>&package=<pkg>"
              "&version=<ver>&mobile=<brand model rel sdk>&adsids=<md5(ad ids)>"
    resp    = base64( AES-256-CBC( json ) )   (same key/iv)

The AES key/iv live inside lib/arm64-v8a/libsecurity.so as two .rodata tables
XORed at runtime -- run `python tools/keyderive.py <apk>` to re-derive them from
your own copy of the APK, then export VPNUS_KEY / VPNUS_IV (or leave the
defaults below, which are the values that helper prints).
"""
import base64
import gzip
import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request
import uuid as uuidlib

WORK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAPSHOT = os.path.join(WORK, "snapshot.json")

KEY = os.environ.get("VPNUS_KEY", "dK8mX2vP4wL7rT1nQ9kJ5hY3sA6fC0uB").encode()[:32]
IV = os.environ.get("VPNUS_IV", "dK8mX2vP4wL7rT1n").encode()[:16]

GATEWAYS = [
    "https://giamping.com/repository/zrequestandroid.php?message=",
    "https://divine-voice-8a97.lucky-poetry-809f.workers.dev/?message=",  # address served by a public gist
    "https://direct.giamping.com/repository/zrequestandroid.php?message=",
]
MONITOR = "https://giamping.com/repository/zmonitor.php?message="

AD_APP_ID = "ca-app-pub-6930586273737023~3521027166"
AD_UNITS = [
    "ca-app-pub-6930586273737023/1545524535",
    "ca-app-pub-6930586273737023/1698263502",
    "ca-app-pub-6930586273737023/6161747695",
    "ca-app-pub-6930586273737023/9597505640",
    "ca-app-pub-6930586273737023/2915819013",
    "ca-app-pub-6930586273737023/3662652682",
    "ca-app-pub-6930586273737023/9250945465",
    "ca-app-pub-6930586273737023/1233109471",
    "ca-app-pub-6930586273737023/5965710915",
    "156261799",
    "0ltgdq0m1dzcsf68",
    "ghoer5ixz2198vi6",
    "eeoah2wp56z0julm",
    "0iuz26u3iy26ys8q",
    "c9w1q9f9tymg81pj",
    "5vazkeq0rhjf0z59",
]
PKG = "com.giamping.usavpn"
VERSION = "20260805"
MOBILE = "Google sdk_gphone_x86_64_arm64 11 R"
ADSIDS = hashlib.md5((AD_APP_ID + "".join(AD_UNITS)).encode()).hexdigest()


def _cipher():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    return Cipher(algorithms.AES(KEY), modes.CBC(IV))


def encrypt_aes(plain: str) -> str:
    from cryptography.hazmat.primitives import padding
    padder = padding.PKCS7(128).padder()
    body = padder.update(plain.encode()) + padder.finalize()
    enc = _cipher().encryptor()
    return base64.b64encode(enc.update(body) + enc.finalize()).decode().replace("+", "CRYPTO")


def decrypt_aes(b64: str) -> str:
    from cryptography.hazmat.primitives import padding
    raw = b64.strip().replace("CRYPTO", "+")
    raw += "=" * (-len(raw) % 4)
    try:
        data = base64.b64decode(raw)
    except Exception:
        return ""
    if not data or len(data) % 16:
        return ""
    dec = _cipher().decryptor()
    out = dec.update(data) + dec.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(out) + unpadder.finalize()).decode("utf8", "replace")
    except Exception:
        return out.decode("utf8", "replace")


def device_ids(dev_uuid: str | None = None) -> tuple[str, str]:
    """The App uses the GAID when it looks like a UUID, else a random v4 UUID."""
    dev_uuid = dev_uuid or str(uuidlib.uuid4())
    return dev_uuid, hashlib.md5(dev_uuid.encode()).hexdigest()


def build_plain(note: str, magic: int, dev_uuid: str, hashed: str, extra: str = "") -> str:
    params = (
        f"&unixtime={int(time.time() * 1000)}"
        f"&uuid={dev_uuid}"
        f"&hashed={hashed}"
        f"&package={PKG}"
        f"&version={VERSION}"
        f"&mobile={MOBILE}"
        f"&adsids={ADSIDS}"
    )
    return f"magicnum={magic}&{params}{extra}&note={note}"


def http_get(url: str, timeout: float = 40.0) -> tuple[int, str]:
    """Honours HTTP(S)_PROXY from the environment -- needed behind a filtered egress."""
    opener = urllib.request.build_opener()
    req = urllib.request.Request(url, headers={"User-Agent": "okhttp/4.12.0"})
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read()
            if r.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
            return r.status, body.decode("utf8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf8", "replace")
    except Exception as e:
        return -1, repr(e)


def call(note: str, magic: int, dev_uuid: str, hashed: str, extra: str = "", verbose=True):
    """Race the three gateways; the first one that yields decryptable text wins."""
    msg = encrypt_aes(build_plain(note, magic, dev_uuid, hashed, extra))
    for gw in GATEWAYS:
        t0 = time.time()
        code, body = http_get(gw + msg)
        dt = (time.time() - t0) * 1000
        txt = decrypt_aes(body) if body else ""
        if verbose:
            print(f"[{note:11s}] {gw.split('/')[2][:38]:38s} http={code} {dt:7.0f}ms "
                  f"raw={len(body):7d}B plain={len(txt):7d}B")
        if txt:
            return txt, gw
    return None, None


if __name__ == "__main__":
    u, h = device_ids()
    print("uuid", u, "hashed", h, "adsids", ADSIDS)
    txt, gw = call("INITIALIZE", 1, u, h)
    if txt:
        d = json.loads(txt)
        print("keys:", sorted(d.keys()))
        print("serversgp", len(d.get("serversgp", "")), "serversse", len(d.get("serversse", "")))
