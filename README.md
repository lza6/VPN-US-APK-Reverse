# VPN US (com.giamping.usavpn) — 逆向与协议还原 R1

对一个 Xray-core + OpenVPN 双栈「VPN US」白标 App 的完整协议还原：AES-256-CBC 信封 API、
native 密钥派生、双节点池（自营 gp / VPNGate 公开 se）、本地压测、演示控制台。

**结论先说**：协议 100% 复现（本地构造的报文与真机请求字节级一致，397 KB 响应可解密）；
两个池都能收割到（gp 741 / se 1246）；但 **R1 未打通可用出口** ——
REALITY 双内核认证失败、SOCKS5 凭据不匹配。原因与下一步写在
[`docs/REVERSE_REPORT.md`](docs/REVERSE_REPORT.md) §3 / §6。

## 状态表

| 能力 | 状态 |
|---|---|
| 信封加密/解密（AES-256-CBC + `+`→`CRYPTO`） | ✅ 实测（与真机请求前 16 字节一致，整链解密成功） |
| 三网关竞速（giamping / CF Workers / direct） | ✅ 实测 |
| `INITIALIZE` / `RELOADLIST` 收割 | ✅ 实测（gp 741 / se 1236–1246，随上游浮动） |
| gp 池 `:443` VLESS+REALITY | ❌ 认证失败（mihomo + Xray-core 双内核复现） |
| gp 池 `:1080` SOCKS5 | ❌ 271/271 鉴权失败 |
| se 池 OpenVPN 拨号 | ⏳ 待验证（需 openvpn 客户端） |
| 本地 TCP 压测 | ✅ gp:443 248–265/741、gp:1080 269–271/741、se:tcp 304–306/921 |
| 演示控制台 | ✅ `:8950`（status / harvest / scan / nodes / export） |

## 快速开始

```bash
pip install cryptography            # 唯一第三方依赖
python tools/harvest.py             # 收割，产出 snapshot.json + gp_nodes.tsv + se_nodes.tsv
python tools/stress.py              # 双池 TCP 压测
python tools/probe_socks.py 20      # SOCKS5 握手 + 出口 IP（支持经本地代理链式）
python tools/gen_xray.py 8          # 生成 Xray 配置（每节点一个 socks 入站）
python demo/server.py               # 演示控制台 http://127.0.0.1:8950
```

出口受限时（本机即如此）：先起一个本地 SOCKS5/HTTP 代理，然后

```bash
export HTTPS_PROXY=http://127.0.0.1:10808      # client.py 遵循该变量
export VPNUS_RELAY=127.0.0.1:10808             # 让内核/探测脚本链式拨号
```

换 APK 版本时先重算密钥：

```bash
python tools/keyderive.py "VPN US vXXXXXXXX.apk"
```

## 目录

```
tools/client.py        协议客户端（加密/解密/三网关竞速/note 调用）
tools/harvest.py       收割一次 -> snapshot.json / *_nodes.tsv
tools/keyderive.py     从你自己的 APK 里复算 AES key/iv（不随仓库分发 APK）
tools/stress.py        双池 TCP 压测（连通性口径）
tools/probe_socks.py   SOCKS5 握手 + 出口 IP 校验
tools/tcpfwd.py        本地 TCP -> SOCKS5 转发器（给内核做 dialerProxy 用）
tools/gen_xray.py      gp 池 -> Xray-core 配置（vless+reality）
tools/gen_mihomo.py    gp 池 -> mihomo 配置
tools/dis_refs.py      原生库 rodata 引用扫描（手工分析用）
demo/server.py         演示控制台（stdlib，无依赖）
demo/index.html        控制台前端
docs/PROTOCOL.md       ★实现手册★ 常量/信封/字段/30 行最小实现/必避坑
docs/REVERSE_REPORT.md 逆向报告：样本/加固/双池/实测/合规/方法论
docs/NEWAPI_INTEGRATION.md  new-api 对接交接包（含"不要接什么"）
samples/               脱敏节点样表（IP 已换文档网段）
```

## 样本信息

| 项 | 值 |
|---|---|
| 包名 / 版本 | `com.giamping.usavpn` / `20260805` |
| 内核 | Xray-core（`libgojni.so` 35.5 MB，含 REALITY/XTLS/QUIC）+ OpenVPN |
| UI | Jetpack Compose + Kotlin |
| 加固 | Smob 字符串混淆 · AES 下沉 `libsecurity.so`（rodata 表 XOR 0x5A/0x3B）· Tink EncryptedSharedPreferences |

## 合规声明

仅用于授权范围内的安全研究与互操作性分析。`serversse` 是 VPNGate **公开志愿节点**的镜像，
可自建采集；`serversgp` 是运营方自租的基础设施，**凭证可得 ≠ 有权使用**，
把 gp 池挂进生产代理池属于盗用上游基础设施，本项目不做也不建议。
仓库内所有真实节点 IP / 账号均已脱敏为文档网段与占位符。
