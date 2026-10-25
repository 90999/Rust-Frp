# NFrp 第十六轮 · 官方 0.71 兼容收尾与真实 e2e（2026-10-25）

本文件记录第十轮/第十五轮交接后，对 **官方 frp 0.71 剩余兼容项**、**官方 NatHole / xtcp**、
**SSH 隧道网关**、**HTTP 插件**、**pprof** 和 **Windows VirtualNet** 的收尾结果。

版本基线是工作区 `0.6.6`，未 commit / 未推送 / 未发版 / 未上传发布物。

---

## 1. 结论先说

- 官方 Windows `frpc.exe 0.71.0` 已与 NFRp 服务端完成**真实 xtcp / NatHole UDP 打洞**，
  visitor 访问成功；不是只看代码或只测登录。
- 官方 0.71 的控制连接、代理注册、`sshTunnelGateway`、`httpPlugins`、`pprof`、
  `useEncryption` / `useCompression`、`proxyURL`、`dnsServer`、`natHoleStunServer`
  均已有实现或真实测试；仍缺的是 `webServer.tls.*` 面板 HTTPS 和完整 HardNAT 分类。
- 收尾过程中真实抓到并修复 4 个问题：
  1. NatHole 把 `NatHoleSid` 直接写到控制连接 / 未先写 `StartWorkConn`；
  2. 工作连接池 `notify_waiters()` 丢失许可的竞态；
  3. SSH 网关代理指标只减不加，三条 SSH 代理断开后 `proxies_active = -3`；
  4. Linux `pprof::protos::Message` 导入路径错误（Windows 不编译该模块，差点漏到发布）。
- 本地全量 **867 passed / 0 failed**（3+5 ignored），`clippy -D warnings`、`fmt --check` 全绿。

---

## 2. 官方 NatHole / xtcp 真实 e2e

### 2.1 修复前的错误

官方 frps 的 xtcp 流程不是把 `NatHoleClient` 直接投到 provider 控制连接。实际顺序是：

1. visitor 发 `NatHoleVisitor`；
2. 服务端向 provider 申请一条**工作连接**；
3. 服务端先在这条工作连接上写 `StartWorkConn{proxy_name}`；
4. 再写 `NatHoleSid{sid}`；
5. provider 在 `InWorkConn()` 读到 Sid 后，用控制连接回 `NatHoleClient`；
6. 服务端回 `NatHoleResp`，双方 UDP 打洞。

先前实现漏了第 3 步，并且把 Sid 放到控制连接。官方 frpc 的 `handleReqWorkConn`
用 `StartWorkConn` 做类型/代理分发，收到 `NatHoleSid` 后按空代理名处理，连接被丢弃；
表现为 visitor 5 秒 `context deadline exceeded`、服务端 10 秒等 provider 超时。

### 2.2 修复

- `server/src/nathole_official.rs`：`start_session` 在独立任务里
  `acquire_work_conn_within(5s)`，成功后先写 `StartWorkConn`，再写 `NatHoleSid`；
  任一步失败就移除会话并把明确错误回给 visitor。
- `server/src/pool.rs`：`submit_work` 从 `notify_waiters()` 改 `notify_one()`。
  `notify_waiters()` 不保存许可；工作连接在等待者尚未 `await notified()` 时到达，
  通知会丢，连接留在池里，等待者超时。真实 e2e 命中了这个窗口。
- 单测同步改为先断言 `StartWorkConn.proxy_name`，再断言 `NatHoleSid.sid`。

### 2.3 真实结果

- 服务端：本地 `nfrp-server`，控制 `28100`；
- provider / visitor：官方 `frpc 0.71.0`；
- visitor 本地 `28098`，后端 HTTP `28099`。

visitor 日志：

```text
nathole prepare success, nat type: EasyNAT, behavior: BehaviorNoChange
get natHoleRespMsg, sid [...]
```

`Invoke-WebRequest http://127.0.0.1:28098/` 返回 `HTTP 200` 和真实 HTML。

证据目录：`tmp/final-handover/official_nathole_071/`
（`server.toml`、`provider.toml`、`visitor.toml`、两轮三端日志、
`visitor_http_200.txt`）。

**边界**：当前只覆盖 mode 0 / EasyNAT / 公网直连；HardNAT、端口预测、
多 STUN 地址、TTL 探测未实现，不能把“EasyNAT 通”写成“所有 NAT 都通”。

---

## 3. SSH 隧道网关

实现文件 `server/src/ssh_gateway.rs`，使用 `russh 0.54`（`ring` 后端，关闭
`aws-lc-rs`，启用 `rsa`）。

支持：

- `authorizedKeysFile` 非空时只接受文件内公钥，**公钥注释即 frp 用户名**；
  文件为空则不校验 SSH 公钥，但虚拟客户端仍必须用 `--token` 过 frps 认证；
- 命令行：`tcp` / `http` / `https` / `tcpmux` / `stcp`，参数支持 `--remote_port`、
  `--custom_domain`、`--subdomain`、`--proxy_name`、`--sk`、`--allow_users` 等；
- OpenSSH `ssh -R` 注册 `tcpip-forward`；真实用户连接通过 `forwarded-tcpip` 承载；
- 每条 SSH 连接注册为虚拟 `ClientState`，数据面复用 `spawn_bridge`；
- OpenSSH `-R` 不会消费 frp 帧，因此工作连接先用内存 duplex 模拟最小 frpc
  读掉 `StartWorkConn`，之后裸字节 relay；
- 监听在启动阶段同步绑定，端口占用会让启动失败，不在后台静默失败。

### 3.1 真实 e2e

`authorizedKeysFile` 带 options 前缀（`command="...",no-pty,...`）时：

- `tcp -R 0.0.0.0:27911:127.0.0.1:27999` 访问返回 200；
- `tcpmux --custom_domain tcp.example.com` 注册成功；
- `stcp --sk ...` 注册成功，面板 visitors 出现 `stcp`；
- 三条 SSH 全断开后：`clients_active=0`、`proxies_active=0`、`ports=[]`，
  端口 `27911` 立即 502（已释放），无幽灵客户端。

### 3.2 收尾中发现的指标 bug

首次 e2e 断开后面板显示：

```json
"proxies_total": 0, "proxies_active": -3
```

原因：普通 frpc 的 `NewProxy` 分支在 `register_proxy` 成功后自己给
`proxies_total/proxies_active` 加一；SSH 网关走同一个 `register_proxy`，却绕过了
那段分支，断开时 `Registry::remove()` 仍按代理数减一，于是负数。

修复：SSH 注册成功后补 `inc()`。修复后同场景：

```json
"proxies_total": 3, "proxies_active": 3
...
"proxies_active": 0
```

**边界**：TCP 数据面真实打通；`tcpmux` / `stcp` 只验证到注册与面板状态，
未构造 tcpmux HTTP CONNECT 访客和 stcp visitor 的完整数据面。

证据目录：`tmp/final-handover/sshgw_current/`
（配置、`authorized_keys`、`status_before/connected/after.json`、TCP 200 与服务器日志）。

---

## 4. pprof

- 实现移到 `common/src/pprof_http.rs`，Unix-only；服务端面板与客户端本地 Web
  共用；同一时刻只允许一个 CPU profile（`try_lock`）。
- 服务端路由：`/debug/pprof`、`/debug/pprof/`、
  `/debug/pprof/profile?seconds=N`；默认 10 秒、上限 60 秒、99Hz；
- 未启用 404；Windows 明确 501；其他采集错误 500。
- Linux release 真实请求：

```text
code=200 size=83
profile bytes: 0a 04 08 03 10 02 0a 04 08 01 10 04 ...
```

- 修复 Linux 编译：`use pprof::protos::Message as _;`；此前写成
  `use pprof::Message as _;`，Windows 因 `cfg(unix)` 不编译，云端 release 直接失败。
- 证据：`tmp/final-handover/pprof_linux_profile.pb`、`pprof_linux_server.log`。

Windows 只验证 404 / 501（没有 perf signal / `ucontext_t`），不能声称 Windows
能抓 profile。

---

## 5. HTTP 插件 / 数据面加密压缩 / 出站代理 / DNS / STUN

| 配置 | 实现 | 验证 |
|---|---|---|
| `httpPlugins` | `common/src/plugin.rs`，`Login` / `NewProxy` / `CloseProxy` / `Ping` / `NewWorkConn` / `NewUserConn`，URL `version=0.1.0&op=...`、`X-Frp-Reqid`、10 秒超时 | 本地插件 + 服务端 + 客户端真实 e2e；拒绝 `blocked-user` / `blocked-web`，改写 metas 被接受。证据 `tmp/final-handover/plugin_e2e/`；`CloseProxy` 本次未稳定抓到，只有代码路径覆盖 |
| `useEncryption` / `useCompression` | `ProxyStream` 包装 AES-128-CFB + snappy；服务端 `PendingUser` 携带 flags/token | 6 条单测/内存双端；未用官方 frpc 做该组合 e2e |
| `proxyURL` | `common/src/net_proxy.rs`，HTTP CONNECT + SOCKS5 | 已接入 `dial_server`；未对真实代理做 e2e |
| `dnsServer` | `common/src/dns.rs`，A/AAAA、UDP、手写 DNS 报文 | 5 条单测 |
| `natHoleStunServer` | `common/src/stun.rs`，RFC 5389 Binding Request | 6 条单测；客户端官方 xtcp 路径填 `mapped_addrs` |

官方 NatHole 分析记录：

- `natholeAnalysisDataReserveHours` 在 `serve_with` 前安装；
- 每次 NatHole 尝试/成功写记录，按保留期清理；
- `0` 小时 = 不保留；记录上限 8192；
- 补了保留期与 0 开关单测。

---

## 6. Windows VirtualNet

- `common/src/vnet/tun_windows.rs` 已有 Wintun 实现（适配器、会话、读写环形缓冲、
  IP 配置、Drop 回收），并有 `#[ignore]` 的真机网卡/数据面测试。
- 本次在非管理员会话新增可重复测试 `非管理员创建网卡要给提权提示`：
  有测试用 `wintun.dll` 时真实调用 `WintunCreateAdapter`，断言错误包含
  “拒绝访问”和“管理员”；管理员环境建完即删；无 DLL 时跳过。
- 缺失 DLL 错误仍由 `缺少_dll_时报错要可操作` 覆盖（含 `wintun.net` 与
  `NFRP_WINTUN_DLL`）。
- **未完成**：本次会话 `admin=False`，真实 Wintun 数据面（ping 双向）需提权后跑
  `cargo test -p nfrp-common -- --ignored 真机`。

---

## 7. 测试与质量门

```text
cargo test --workspace
125 + 422 + 9 + 266 + 17 + 26 + 2 = 867 passed, 0 failed
（common 3 ignored、doc-tests 5 ignored）

cargo clippy --workspace --all-targets --all-features -- -D warnings
Finished，0 warning（仅 russh future-incompat 提示）

cargo fmt --all -- --check
FMT_OK
```

证据：`tmp/final-handover/workspace-test-2.log`、`clippy3.log`。

云端 Linux release（`CARGO_BUILD_JOBS=2`）已成功编译 `nfrp-server` / `nfrp-client`；
pprof 端点真实 200。

---

## 8. 渗透复核修正

在 `tmp/pentest_round/PENTEST-REPORT.md` 第 12 节补充：

- v2 合法握手、非法 codec、65537 字节超长帧均真实执行；
- `POST /api/status` 在 0.6.3 返回 200，是真实低危问题；0.6.6 工作区已 405；
- 140 条空闲控制连接全部建立，约 11 秒回收；**控制面没有 128 上限**，
  `MAX_DASHBOARD_CONNS = 128` 是面板常量，不能混写；
- 0.6.3 仍有重复 `Authorization` first-wins、缺安全响应头、`/api/healthz`
  免鉴权；0.6.6 已补 XCTO/XFO/Referrer/CSP，HSTS 仍应由 TLS 终结层负责。

---

## 9. 仍未完成 / 不要误报

- `webServer.tls.*` 面板 HTTPS：未实现，配置会明确报错。
- 官方 NatHole 完整 NAT 分类：只做 mode 0 / EasyNAT。
- TSan、Linux TUN Miri、完整 PSF、Phaedra、真实 IdP OIDC e2e：环境/工具限制，
  不是“已通过”。
- `cargo vet` 的 184 条是 exemption，不是人工审计。
- SSH 的 tcpmux/stcp 完整数据面、官方 frpc 的加密+压缩组合、真实外部代理、
  真实 DNS 服务器未做 e2e。
- Windows Wintun 真实数据面需要管理员权限。
