# PROTOCOL — 实现手册（给二次开发 / 对接方）

目标：不读逆向过程，只看这一份就能写出可用的客户端。

## 0. 一句话

```
GET https://giamping.com/repository/zrequestandroid.php?message=<MSG>
MSG = base64( AES-256-CBC/PKCS5( plaintext ) )   且把 '+' 全部换成 "CRYPTO"
plaintext = "magicnum=<n>&" + getParams() + [extra] + "&note=<NOTE>"
响应体 = base64( AES-256-CBC( JSON ) )           同一把 key/iv 解
```

## 1. 常量表

| 名称 | 值 |
|---|---|
| package | `com.giamping.usavpn` |
| version（`R.string.version`） | `20260805` |
| AES key（32B, AES-256） | `dK8mX2vP4wL7rT1nQ9kJ5hY3sA6fC0uB` |
| AES iv（16B） | `dK8mX2vP4wL7rT1n` |
| 广告位串接（`adsids` 的原料） | `ca-app-pub-6930586273737023~3521027166` + 16 个 unit id（见 `tools/client.py: AD_UNITS`） |
| `adsids` = | `md5(原料)` = `5f78c24595f9cb56e62bb6a0f680af58` |
| base64 变体 | Android `Base64.NO_WRAP`（标准字母表，带 `=` padding），再替换 `+`→`CRYPTO` |

key/iv 的出处：`lib/arm64-v8a/libsecurity.so` 中 `.rodata` 两张表 XOR 常量：

```
key = .rodata[0x112bc .. +32] XOR 0x5A
iv  = .rodata[0x112dd .. +16] XOR 0x3B
```

用 `python tools/keyderive.py "<你的 APK>"` 可以在本地复算（换版本时先跑它）。

## 2. 网关发现（三源竞速）

| 序 | URL | 备注 |
|---|---|---|
| 1 | `https://giamping.com/repository/zrequestandroid.php?message=` | PHP + Cloudflare |
| 2 | `https://divine-voice-8a97.lucky-poetry-809f.workers.dev/?message=` | Cloudflare Worker；**地址由公开 gist `mastervnc/9cee792c…/raw/kerberos?v=<rand>` 下发**，可随时更换 |
| 3 | `https://direct.giamping.com/repository/zrequestandroid.php?message=` | OVH 直连，绕 Cloudflare |

客户端是「三个并发、第一个解出明文者胜」，各自有独立超时。三个源返回的结构一致。

垂测端点：`https://giamping.com/repository/zmonitor.php?message=`，明文是 `USAVPN <BRAND MODEL REL> `。

## 3. getParams()（字段顺序固定）

```
&unixtime=<毫秒时间戳>
&uuid=<DEVICE_UUID>          # 首次启动取 GAID，非法则随机 v4 UUID
&hashed=<md5(DEVICE_UUID)>   # 小写 hex
&package=com.giamping.usavpn
&version=20260805
&mobile=<MANUFACTURER> <MODEL> <RELEASE> <VERSION_CODE_NAME>   # 空格分隔，如 "Google sdk_gphone_x86_64_arm64 11 R"
&adsids=<md5 见上>
```

> `adsids` 看着像噪声，但服务端会校验：**算错 → HTTP 200 空 body**。这是最常见的"接口挂了"误判。

## 4. note / magicnum

| note | magicnum | 说明 | 是否需额外参数 |
|---|---|---|---|
| `INITIALIZE` | 1 | 首启拉全量配置（收割入口） | 无 |
| `RELOADLIST` | 1 | 定时刷新（30 min），内容与 INITIALIZE 同构 | 无 |
| `CONNECT` | 6 | 连接上报 | `&orderid=<内购订单>` |
| `ORDERID-VERIFY-<id>` | 3 | 内购校验 | `&orderid=` |
| `REWARDED` / `PUBLISH` / `ORDERID` | 2/4/5/7 | 广告奖励、兑换码、分享 | 各自不同 |

`note` 不匹配时同样返回空体（fail-closed），**不要用"是否 200"判断成功，必须能解出明文**。

## 5. INITIALIZE 响应字段

| key | 类型/长度 | 含义 |
|---|---|---|
| `serversgp` | str 90 KB | 自营 gp 节点池，`•` 分隔，见 §6 |
| `serversse` | str 200 KB | VPNGate 公开中继镜像，见 §7 |
| `vpngpcfg` / `vpnsecfg` | str | OpenVPN 配置模板（内联 `<ca>`，ISRG Root X1），`remote default 443` / `1194`，端口运行时替换 |
| `v2raydfcfg` | str | Xray 默认配置模板（VLESS + REALITY + `xtls-rprx-vision`），占位符见 §8 |
| `v2rayifcfg` / `v2raysscfg` | str | 另两套 Xray 模板（`CONFIG` / `OUTPUT` 占位） |
| `v2rayuuid1` / `v2rayuuid2` | uuid | VLESS 用户 ID |
| `userpassgp` | `USER/PASS` | gp 池账号（OpenVPN 的 `auth-user-pass`） |
| `userpasscfx1` / `userpasscfx3` | `USER/PASS` | 占位值（`xxx`） |
| `timegp` / `timese` | 秒 | 池刷新周期 1800 / 3600 |
| `blappfilter` | str | `•` 分隔的包名黑名单（BT/下载器/翻墙类） |
| `clientip` `clientcc` `clientaso` `clientasn` | str | 服务端回显的出口信息（软地理围栏原料） |
| `webview` | str | 内置 WebView 域名 |

## 6. serversgp 节点字段（15 列，`•` 分隔，行 `\n`）

| # | 例 | 含义 |
|---|---|---|
| 1 | `AE05` | code（同时是端点名前缀） |
| 2 | `01080` | 端口，**0 填充**的 1080 |
| 3-6 | `O O O O` | 协议能力标记，全池恒为 `O` |
| 7 | `FUJAIRAH` | 城市 |
| 8 | `UNITED ARAB EMIRATES` | 国家 |
| 9 | `MELBIKOMAS \| MIDDLE EAST (…)` | 运营商/机房 + 区域标签 |
| 10 | `ASIA` | 洲 |
| 11 | `10/30` | 负载（`5/15` `25/100` `3/9`） |
| 12 | `IPv4` | 栈类型（`IPv6` 表示有 v6） |
| 13 | `00` | 常量 |
| 14 | `198.51.100.7` | IPv4 |
| 15 | `2a06:…` | IPv6，可能为空 |

**关键：真实连接端口不是第 2 列。** 客户端解析器对 GP 型节点硬编码
`tport = uport = "443"`、`type = "GP"`、`score = "999"`，endpoint 由 `<code>` + `.GIAMPING.COM` 拼成。
所以：`443` = VLESS+REALITY 入口，`1080` = 同机 SOCKS5 入口，`<code>.giamping.com` 与节点 IP 解析同址。

## 7. serversse 节点字段（7 列）

| # | 例 | 含义 |
|---|---|---|
| 1 | `0336967` | VPNGate 节点 ID |
| 2 | `VPN566130168.OPENGW.NET` | 主机名 |
| 3 | `11 SESSIONS 11 DAYS TOTAL 210,859 USERS` | 会话信息 |
| 4 | `366.24` | 延迟 |
| 5 | `TCP:995/UDP:1195` | 端口（SoftEther 常用 995/5555/1194） |
| 6 | `KR ~ SOUTH KOREA ~ CHEONGJU-SI ~ LG DACOM \| ASIA` | 位置 + 运营商 |
| 7 | `211.168.36.235` | IP |

这是 **VPNGate 志愿节点**镜像（= `vpngate.net/api/iphone/` 的公开数据），不是自有资产。

## 8. Xray 模板占位符（`v2raydfcfg`）

| 占位符 | 替换为 |
|---|---|
| `odtmnenp`（混淆前）→ `endpoint` | 节点 IP / `<code>.giamping.com` |
| `uuid` | `v2rayuuid1` 或 `v2rayuuid2` |
| `55s36` → `65535` | 本地 socks 入站端口 |
| `snifffalse` / `routefalse` | `false` / `false`（分流开关） |
| `DNSOUT` / `DNSRESOLVER` / `remotedns` | 路由规则片段 |

REALITY 参数（本案下发值）：`serverName=swdist.apple.com`、`fingerprint=chrome`、
`publicKey=FfVWfUbSPCElgulhWN0MbMuHvc3d51vvVEfF6hcv9BQ`、`shortId=95ac5b1133d094fb`、
`flow=xtls-rprx-vision`。**注意：本案这组 pbk/sid 对 gp 节点握手失败**（见 REVERSE_REPORT §3），
二次开发时务必先用真机抓包确认 pbk 是否随版本/账号变化。

## 9. 30 行最小实现

```python
import base64, hashlib, json, time, urllib.request, uuid
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY, IV = b"dK8mX2vP4wL7rT1nQ9kJ5hY3sA6fC0uB", b"dK8mX2vP4wL7rT1n"
GW = "https://giamping.com/repository/zrequestandroid.php?message="
AD = "ca-app-pub-6930586273737023~3521027166" + "".join([
    "ca-app-pub-6930586273737023/1545524535", "ca-app-pub-6930586273737023/1698263502",
    "ca-app-pub-6930586273737023/6161747695", "ca-app-pub-6930586273737023/9597505640",
    "ca-app-pub-6930586273737023/2915819013", "ca-app-pub-6930586273737023/3662652682",
    "ca-app-pub-6930586273737023/9250945465", "ca-app-pub-6930586273737023/1233109471",
    "ca-app-pub-6930586273737023/5965710915", "156261799", "0ltgdq0m1dzcsf68",
    "ghoer5ixz2198vi6", "eeoah2wp56z0julm", "0iuz26u3iy26ys8q",
    "c9w1q9f9tymg81pj", "5vazkeq0rhjf0z59"])

def aes(data, enc=True):
    c = Cipher(algorithms.AES(KEY), modes.CBC(IV)).encryptor() if enc else Cipher(algorithms.AES(KEY), modes.CBC(IV)).decryptor()
    return c.update(data) + c.finalize()

uid = str(uuid.uuid4())
plain = (f"magicnum=1&&unixtime={int(time.time()*1000)}&uuid={uid}"
         f"&hashed={hashlib.md5(uid.encode()).hexdigest()}&package=com.giamping.usavpn"
         f"&version=20260805&mobile=Google sdk_gphone_x86_64_arm64 11 R"
         f"&adsids={hashlib.md5(AD.encode()).hexdigest()}&note=INITIALIZE")
p = padding.PKCS7(128).padder()
msg = base64.b64encode(aes(p.update(plain.encode()) + p.finalize())).decode().replace("+", "CRYPTO")
body = urllib.request.urlopen(GW + msg, timeout=40).read().decode()
raw = base64.b64decode(body.replace("CRYPTO", "+"))
u = padding.PKCS7(128).unpadder()
print(json.loads((u.update(aes(raw, False)) + u.finalize()).decode())["serversgp"][:120])
```

## 10. 必避坑

1. **`+` → `CRYPTO`**：加密后不做这步，服务端解不出；解密前要先换回来。
2. **空 body ≠ 接口挂了**：所有校验失败都是 `200 + 空`。要能解出明文才算成功。
3. **`adsids` 必须精确**，少一个 unit id 就返空。
4. **端口不是记录里的 1080**（GP 型走 443），见 §6。
5. **`userpassgp` 只对 OpenVPN 有效**，拿它连 1080 的 SOCKS5 会被拒（`01 01`）。
6. `note`/`magicnum` 必须成对匹配，`CONNECT` 缺 `orderid` 一定返空。
7. OpenVPN 模板带 `register-dns` / `block-outside-dns` 等 Windows 专用 push 选项，Linux 侧要
   `--pull-filter ignore register-dns --pull-filter ignore block-outside-dns --pull-filter ignore dhcp-release --pull-filter ignore dhcp-renew --pull-filter ignore dhcp-pre-release --pull-filter ignore tap-sleep`，
   否则会以 `Options error` 中断（其实认证已过）。
