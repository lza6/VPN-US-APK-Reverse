# REVERSE REPORT — VPN US v20260805 (Premium by @ElaMods)

> 本文所有节点 IP 已替换为 RFC 5737 文档网段（`198.51.100.x` / `203.0.113.x`），
> 账号口令替换为占位符。协议常量（AES key/iv、模板、域名）保留，因为它们是可复现的协议知识，
> 不涉及任何个人凭证。

## 0. 样本信息

| 项 | 值 |
|---|---|
| 包名 | `com.giamping.usavpn` |
| 版本 | `20260805` |
| 体积 | 72.4 MB（28 MB 是 `geoip.dat`+`geosite.dat`，35.5 MB 是 `libgojni.so`） |
| 内核 | **Xray-core**（`lib/arm64-v8a/libgojni.so`，含 REALITY / XTLS / QUIC 符号） |
| 附加协议 | OpenVPN（`libopenvpn.so` / `libovpnexec.so`，ics-openvpn 血统）、MS-SSTP（代码分支存在） |
| UI | Jetpack Compose + Kotlin，主业务在 `classes4.dex` |
| 签名加固 | 改包（ElaMods）；`assets/elamods.png`、`assets/Modder_Hub_*` 是其自加弹窗资源 |

三层加固：

1. **字符串表混淆**（"Smob - Mod obfuscation tool v1.4"）：每个真实 `const-string` 前跟一条同长度假串，
   例如 `const-string v24, "55s36"` 紧跟 `const-string v24, "65535"`。
2. **加密下沉 native**：AES 只在 `libsecurity.so` 里做，key/iv 是 `.rodata` 两张 XOR 表。
3. **配置持久化用 `androidx.security` EncryptedSharedPreferences**（`EncryptedSharedPreferences.xml`，Tink keyset 内嵌）。

## 1. 协议还原（结论：已完全复现）

见 `docs/PROTOCOL.md`。关键验证：本地构造的报文与真机 OkHttp 请求**前 16 字节完全一致**
（CBC 首块只依赖 key/iv+明文首块），随后整链 397 KB 响应解密成功 → key/iv 与参数拼装均正确。

## 2. 双池结构

### 2.1 gp（自营）

- 741 条（唯一 IP 741），`•` 分隔 15 列
- 国家分布 Top：PH 166 / US 66 / CN 41 / SA 41 / VN 29 / IN 22 / DE 17 / AU 15
- 机房：KAOPU CLOUD、G-CORE（CLOUD/LABS）、MELBIKOMAS 等，即**运营方自租**的基础设施
- 每条同时对应三种接入：`:443` VLESS+REALITY、`:1080` SOCKS5、`UDP/443` OpenVPN
- 刷新周期 `timegp = 1800s`

### 2.2 se（公开）

- 1246 条（唯一 IP 1246），7 列，字段与 **VPNGate 公开志愿节点**完全同构
  （`VPNxxxxx.OPENGW.NET` 主机名、`SESSIONS/USERS` 统计串、`TCP:995/UDP:1195` 端口对）
- 刷新周期 `timese = 3600s`
- 判定：等价于 `vpngate.net/api/iphone/` 的公开数据镜像 → **公开源**

### 2.3 其它下发

- `vpngpcfg` / `vpnsecfg`：OpenVPN 模板（内联 CA = ISRG Root X1），`remote default 443 / 1194`
- `v2raydfcfg`：VLESS+REALITY 模板（sni `swdist.apple.com`、flow `xtls-rprx-vision`）
- `blappfilter`：BT 下载器 / 翻墙类包名黑名单（含 `com.giamping.*` 全家桶、
  `com.utorrent.client`、`idm.*`、`com.cloudflare.onedotonedotonedone` 等）
- `clientip/clientcc/clientaso/clientasn`：服务端回显出口信息（软地理围栏）

## 3. R1 实测（2026-10-29，单机、本机出口被强过滤）

### 3.1 连通性（裸 TCP）

| 目标 | 存活 | 总 | 延迟 |
|---|---|---|---|
| gp `:443` | 248（复测 265） | 741 | P50 260 ms / P95 406 ms |
| gp `:1080` | 271（复测 269） | 741 | P50 262 ms / P95 428 ms |
| se `TCP:<记录端口>` | 306（复测 304） | 921 | P50 103 ms / P95 377 ms |

⚠️ 本机直连被大面积 RST/timeout，**超时 ≠ 节点死**。上表只能当"从本机可达"的保守下界。

### 3.2 协议层拨号（关键结论：未打通）

| 路径 | 结果 | 证据 |
|---|---|---|
| gp `:443` VLESS+REALITY，用下发 pbk/sid/sni/uuid1 | ❌ `REALITY authentication failed` | mihomo 与 Xray-core 26.10.21 **双内核**复现 |
| 同上 4 组变体（uuid1/uuid2 × sid 原值/空/全 0） | ❌ 全失败 | 参数矩阵测试 |
| gp `:443` 裸 TLS 探测（SNI=swdist.apple.com） | 服务端回落**真实 Apple 证书**（`CN=swcdn.apple.com`，verify OK） | 证明 REALITY 服务存在，但我们的 ClientHello 未被认证 → 下发 pbk 与节点实际不匹配 |
| gp `:1080` SOCKS5（`<GP_USERPASS>`、`<CFX_USERPASS>`、uuid/hashed/adsids 组合） | ❌ 271/271 `01 01` | `<GP_USERPASS>` 是 OpenVPN 的 `auth-user-pass`，不是 SOCKS5 账号 |
| se OpenVPN | 未测 | 本机无 openvpn 客户端；模板已拿到 |

**已排除的假设**：三网关差异（参数一致）、池轮换（`RELOADLIST` 返回同一组参数）、
端口（443/1080 都试）、端点（`<code>.giamping.com` 与节点 IP 解析同址）、uuid（1/2 都试）、
shortId 变体。剩余解释：REALITY 身份按节点/按会话下发，或上游已轮换而 APK 内置模板过期。

## 4. 合规判定

| 资产 | 性质 | 判定 |
|---|---|---|
| gp 池 741 节点 | 运营方自租机房 + 平台账号 | ❌ 凭证泄露 ≠ 使用权，不入生产池 |
| se 池 1246 节点 | VPNGate 公开志愿节点镜像 | ✅ 公开源，可自建采集/测活 |
| API / AES key / 模板 | APK 内可复现的协议知识 | ✅ 可写入研究文档 |

本项目**不提供**任何把 gp 池挂进生产代理池的脚本，也不建议这么做。

## 5. 方法论沉淀（可复用）

1. **jadx 卡死就换 smali**：本机对 5.4 万类 APK 的 jadx（1.5.1/1.5.6）会停在
   `Resetting disk code cache` 永不产出；`apktool d -f`（不带 `-s`）几十秒给出全量 smali，
   读 `const-string` 与 `iput` 顺序就能还原参数映射。
2. **native 加密不一定难**：只要 JNI 里用 `CallStaticObjectMethod` 回调 Java 的
   `Cipher`，key/iv 就一定是可静取的常量，capstone 扫 `adr/adrp` + XOR 立即数即可。
   注意 JNI 开头那串 `ldrb/tst/csel` 是在拼 libc++ `std::string` 的 SSO 头，别被绕晕。
3. **判断"接口挂了"之前先对齐参数**：`adsids` 这种看着像噪声的字段往往就是校验开关。
4. **"TCP 活"与"能拨通"必须分开报**：否则会把 248 个开放端口写成 248 个可用节点。
5. **端口 ≠ 记录端口**：一定要读客户端解析器（`ListServersData` 构造器实参）。
6. 抓包环境：Android 11 上把 mitmproxy CA 放到
   `/data/misc/user/0/cacerts-added/<subject_hash_old>.0`（`chown system:system 644`）即可，
   不需要 remount `/system`；应用 `network_security_config` 已 `<certificates src="user"/>`。
