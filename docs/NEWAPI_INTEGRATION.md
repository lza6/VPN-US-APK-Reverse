# NEW-API 对接指南（交接包）

写给「对接会话」：不用读逆向过程，按这份执行即可。所有结论都注明了是
**读源码确认** / **实测** / **待验证**。

## 0. 边界声明

- **不用改 new-api 一行业务代码。** 唯一改动点是环境变量 `TRYINGOPEN_PROXY_FILE` + 一个本地转换层。
- **R1 现状：本项目没有可用出口。** gp 池（自营）REALITY 认证失败、SOCKS5 凭据不匹配（详见
  `docs/REVERSE_REPORT.md` §3）。所以本文档只给**两条未来可用的路线**，其中只有 se 池（VPNGate 公开源）
  具备合规入池资格。
- 合规红线：gp 池是上游自租基础设施，**不要接进生产池**；se 池是 VPNGate 公开志愿节点，可自建采集。

## 1. 现状

| 组件 | 状态 |
|---|---|
| 协议客户端 `tools/client.py` | ✅ 实测（与真机请求字节级一致，397 KB 响应解密成功） |
| 收割 `tools/harvest.py` | ✅ 实测（741 gp / 1236–1246 se，随上游刷新浮动） |
| 压测 `tools/stress.py` | ✅ 实测（gp:443 248–265/741、gp:1080 269–271/741、se:tcp 304–306/921） |
| 配置生成 `tools/gen_xray.py` / `tools/gen_mihomo.py` | ✅ 生成成功，❌ 拨号失败（REALITY 认证） |
| SOCKS5 探测 `tools/probe_socks.py` | ✅ 实测（271/271 auth 失败，变量已收敛） |
| 演示控制台 `demo/server.py` | ✅ 实测 `:8950`（status/harvest/scan/nodes/export 全通） |
| se 池 OpenVPN 拨号 | ⏳ 待验证（本机无 openvpn 客户端） |

先跑一轮健康检查：

```bash
python tools/harvest.py            # 拉一次全量
python tools/stress.py             # 出连通性口径
python demo/server.py &            # 打开 http://127.0.0.1:8950 看池子
```

## 2. 路线 A：se 池（VPNGate）→ OpenVPN → SOCKS5 → new-api（推荐，合规）

```
VPNGate 节点 --OpenVPN(UDP/1194 或 TCP/443)--> 本地隧道
                                            └─ microsocks/3proxy 绑隧道内 IP:1080
new-api: TRYINGOPEN_PROXY_FILE=/etc/newapi/se_proxies.txt
        每行 socks5://127.0.0.1:44xxx
```

要点：

- **必须加 `--pull-filter ignore`**（`register-dns` / `block-outside-dns` / `dhcp-release` /
  `dhcp-renew` / `dhcp-pre-release` / `tap-sleep`）。这些是 Windows 专用 push，Linux 侧会以
  `Options error` 中断 —— 其实认证已经通过，不加就会把全部节点误判成"账号失效"。
- VPNGate 公开中继的 OpenVPN 账号是 `vpn` / `vpn`（公开文档口径，待实测确认）。
- 规模：单机 netns 隧道 20–50 条（每条约 1 tun + 1 veth + 1 socks 进程）。

## 3. 路线 B：gp 池（自营）——**仅研究，不入生产**

只有拿到与节点匹配的 REALITY 身份才谈得上连接。当前下发的
`publicKey/shortId` 对 gp 节点握手失败（双内核复现），需要 arm64 真机抓
ClientHello 与 `:1080` 首包来确认差异点（模拟器 x86_64 上 `libgojni.so` 走
ndk_translation 必 SIGILL，隧道跑不起来）。

## 4. 环境变量（new-api 侧，读源码确认）

| 变量 | 说明 |
|---|---|
| `TRYINGOPEN_PROXY_FILE` | 代理清单文件，**逗号分隔多文件**；每行 `socks5://host:port` 或 `http://user:pass@host:port`，`#` 开头跳过 |
| 池内行为 | `source="residential"`、`healthScore=1.0`、`origin=<文件名>`（所以多池各自成卡片） |

参考：`relay/channel/tryingopen/proxy_pool.go:348 LoadProxies()`。

## 5. 三层验收

```bash
# 隧道层：出口国是否为目标国
ip netns exec vpn0 curl -s https://ipinfo.io/country
# 池层：条目是否进池
curl -s http://<newapi>/api/twoapi/proxy_pool | head
# 业务层：发真请求并核对上游侧来源 IP
```

只看池快照有条目 ≠ 流量真走了它。

## 6. 常驻健康检查（必须有，参考实现已随仓库提供）

仓库里 `tools/health_loop.py` 就是这一层，四条规则全实现且已本地实测（活/死/exit-mismatch 三种路径）：

```bash
# 单轮
python tools/health_loop.py --in proxies.txt --out proxies_alive.txt --require-exit-eq-node
# 常驻，每 300s 一轮
python tools/health_loop.py --in proxies.txt --out proxies_alive.txt \
    --require-exit-eq-node --fail-threshold 2 --loop 300
# 输出即 new-api 的清单
export TRYINGOPEN_PROXY_FILE=/opt/newapi/proxies_alive.txt
```

实测口径（对着本机 `socks5://127.0.0.1:10808` 跑）：死节点 → `never-passed` 不入池；
活节点 → 入池并记 `exit_ip`；加 `--require-exit-eq-node` 后因出口 IP ≠ 节点 IP 被摘除 —— 三种行为都符合预期。

原理：

**new-api 不验住宅/静态源。** `TraceProbes()` 里 `if e.source != "free" { continue }`
（`proxy_pool.go:1180`），而 `TRYINGOPEN_PROXY_FILE` 加载的条目 `source` 恒为 `"residential"`
→ 死节点会被反复选中，表现为"渠道高概率超时"。

new-api 侧的那两条源码事实（读源码确认）：

- `proxy_pool.go:348 LoadProxies()`：`TRYINGOPEN_PROXY_FILE` 支持**逗号分隔多文件**，
  每行 `socks5://host:port` / `http://user:pass@host:port`，`#` 跳过；加载后
  `source="residential"`、`healthScore=1.0`、`origin=<文件名>`（所以多池各自成卡片）。
- `proxy_pool.go:1180`：`TraceProbes()` 里 `if e.source != "free" { continue }` —— **你的清单不会被验**。

所以转换层必须自带健康检查器重写清单：

1. 真实协议探测（SOCKS5 握手 + 目标站可达），不能只测 TCP；
2. **出口 IP 必须 == 节点 IP**，不等则摘除（防上游偷偷改中转）；
3. 双阈值：连续 N 轮失败才摘除；**从未通过过的新节点首轮就不入池**；
4. `os.replace` 原子重写，避免读到半个文件。

清单重写后 new-api 不会热更新（`LoadProxies()` 只在启动/配置变更时调用）→ 每天固定时段重启一次容器。

## 7. 故障排查

| 症状 | 原因 | 处理 |
|---|---|---|
| `Options error: Unrecognized option ... register-dns` | 上游 push 了 Windows 专用选项 | 全套 `--pull-filter ignore` |
| 整池突然没可用 | 同一代理连续失败 5 次进 10 分钟全局熔断 | 扩节点 / 降并发 |
| 池里有条目但请求超时 | 死节点未被探测（new-api 不验 residential） | 检查健康检查器是否真在跑 |
| 429 冷却越来越长 | 24h 窗口内使用次数递增（0/30/90/300/900s） | 加节点或控并发 |

## 8. 红线

- 不要改 `TraceProbes()` 的分支去"让池子看起来有出口 IP"。
- 不要把 gp 池（自营）写进生产清单。
- 不要在容器里用 `127.0.0.1` 指宿主转换层：容器内 loopback 是容器自己的。
  三种正确做法：`extra_hosts: host.docker.internal:host-gateway` + 端口绑 `0.0.0.0` / `network_mode: host` / 转换层进同一 compose 网络。

## 9. 验收清单

- [ ] `tools/harvest.py` 能出 snapshot（gp 700+ / se 1200+）
- [ ] `tools/stress.py` 三组数字有输出且口径写清（连通性≠可用性）
- [ ] 转换层单节点出口国正确
- [ ] `/api/twoapi/proxy_pool` 能看到条目且 `origin` 正确分卡片
- [ ] 业务层真请求成功并核对来源 IP
- [ ] 健康检查器在跑，连续两轮后清单稳定

## 10. 上游失效后怎么重来

1. `python tools/harvest.py RELOADLIST 1` —— 池子每 30 min（gp）/ 60 min（se）刷新；
2. 换网关：把 `tools/client.py: GATEWAYS` 的顺序调换（三源内容一致，只有可达性差异）；
3. 换版本：`python tools/keyderive.py "<新 APK>"` 重算 key/iv，再用
   `VPNUS_KEY` / `VPNUS_IV` 环境变量覆盖；若 `adsids` 变了，按 `docs/PROTOCOL.md` §1 重新拼接。

---

## 11. 给「对接会话」的开工提示词（直接复制粘贴）

```
项目：把一个新收割的代理池接进 new-api 的 tryingopen 渠道。
先读这两个文件，不要先动手：
  D:/apk-analysis/vpn-us-public/docs/NEWAPI_INTEGRATION.md
  D:/apk-analysis/vpn-us-public/docs/REVERSE_REPORT.md  §3（确认哪些池子不能碰）
仓库：https://github.com/lza6/VPN-US-APK-Reverse

要求：
1. new-api 侧只允许改环境变量 TRYINGOPEN_PROXY_FILE，不许改业务代码；
2. 只接 se 池（VPNGate 公开源）。gp 池是上游自租基础设施，凭证可得≠有权使用，禁止入池；
3. 转换层按 §2 路线 A：VPNGate 节点 → OpenVPN(UDP/1194 或 TCP/443) → 本地 socks5 → 清单文件；
   OpenVPN 必须加全套 --pull-filter ignore（register-dns / block-outside-dns /
   dhcp-release / dhcp-renew / dhcp-pre-release / tap-sleep），否则会以 Options error 中断；
4. 清单必须由 tools/health_loop.py 生成（真实 SOCKS5 握手 + 出口 IP 校验 + 双阈值 + 原子重写），
   不许把 harvest 结果直接喂给 new-api；
5. 验收按 §5 三层：隧道层（出口国）→ 池层（/api/twoapi/proxy_pool 有条目且 origin 正确分卡片）→
   业务层（发真请求并核对上游侧来源 IP）。只看池快照有条目不算通过；
6. 交付时报：改了什么、跑了哪些命令、每层实际输出、剩余风险。没跑过的验证明确写"未验证"。
```
