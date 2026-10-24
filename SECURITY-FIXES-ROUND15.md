# NFrp 第十五轮：补齐未实现项 + 发现并修掉 OIDC 的 ES256 致命 bug

日期 2026-10-24
来源 第十四轮遗留清单
本轮性质 **特性对齐 + 缺陷修复**（不是安全审计）
质量门 **811 通过 / 0 失败** · clippy 0 告警 · audit 零漏洞

---

## 一、最重要的发现：ES256 验签用了错误的签名格式（致命）

### 现象

写"真实 IdP"端到端测试时，用**真 ECDSA P-256 密钥 + 真签名**验证，结果：

```
真实签名必须验证通过: 签名不匹配
```

### 根因

`common/src/auth/oidc.rs` 的 `pick_algorithm`：

```rust
("EC", "ES256") => &s::ECDSA_P256_SHA256_ASN1,   // ← 期望 DER
("EC", "ES384") => &s::ECDSA_P384_SHA384_ASN1,   // ← 期望 DER
```

但 **JWS 的 ES256 签名不是 DER**。RFC 7518 §3.4 原文：

> Turn R and S into octet sequences in big-endian order…
> Concatenate the two octet sequences in the order R and then S.
> **The resulting 64-octet sequence is the JWS Signature value.**

验证侧同样强制：

> The JWS Signature value **MUST be a 64-octet sequence**.
> If it is not a 64-octet sequence, the validation has failed.

也就是说 ES256 的签名是 **64 字节裸 `r‖s`**，不是 `SEQUENCE{r INTEGER, s INTEGER}`。

### 影响

**任何真实 IdP 签发的 ES256 token 都会验签失败** —— 而 ES256 恰恰是
Keycloak / Auth0 / Azure AD 的**默认算法**。

换句话说：**OIDC 认证在生产环境基本不可用**。

### 为什么之前 27 条 OIDC 单测没抓到

因为有一条**测试向量本身是错的**：

```rust
const VEC_EC_SIG: &[u8] = &[
    0x30, 0x44, 0x02, 0x20, ...   // 0x30 = DER SEQUENCE
];
```

这个向量当初是用 openssl 生成的，而**openssl 的默认输出就是 DER**。
于是「错误的实现 + 错误的向量」**一起错**，测试全绿、线上全挂。

> **教训**：自造测试向量只能证明"实现和向量一致"，证明不了"和标准一致"。
> 能抄标准（RFC 附录）就别自己编。

### 修复

```rust
("EC", "ES256") => &s::ECDSA_P256_SHA256_FIXED,   // r‖s，64 字节
("EC", "ES384") => &s::ECDSA_P384_SHA384_FIXED,   // r‖s，96 字节
```

### 测试

| 测试 | 作用 |
|---|---|
| `es256_rfc7515_官方向量必须验得过` | 用 **RFC 7515 附录 A.3** 的权威向量验签通过 |
| `es256_der_编码的签名必须验不过` | **反向门**：锁住"不再接受 DER" |
| `es384_签名长度必须是_96_字节` | 长度约束（64 字节不能当 ES384 用） |

同时**删掉**了那两个错误的 DER 向量常量，并在原处留注释说明"这里曾经有个错向量，
别再照着 openssl 默认输出造 EC 签名向量"。

### 退回验证 ✅

把 `FIXED` 改回 `ASN1` ⇒ 测试**变红**；还原 ⇒ 变绿；文件 sha256 一致。

---

## 二、真实 IdP 端到端测试（新增 9 条）

`common/tests/oidc_idp_e2e.rs` —— 在本机起一个**最小 HTTP server** 扮演 IdP，
提供 `/.well-known/openid-configuration` 与 `/jwks`，并用**真实的 ECDSA P-256
密钥**签发 JWT。整条链路（HTTP → JSON → JWKS → ring 验签）都真跑一遍。

| 测试 | 覆盖 |
|---|---|
| `真实_idp_discovery_与_jwks_与_es256_端到端` | 主干：discovery → JWKS → 真签名验签 |
| `真实_idp_密钥轮换后仍能验证` | IdP 换密钥后 `refresh()` 能拉到新的 |
| `未知_kid_必须拒绝` | 找不到 key 不能"放行" |
| `签名被篡改必须拒绝` | 改一个字符就拒 |
| `恶意_jwks_空密钥集要报错` | `{"keys":[]}` 不能当"没有密钥于是全放行" |
| `恶意_jwks_畸形_json_要报错` | 非 JSON |
| `恶意_jwks_垃圾坐标不崩溃` | `x`/`y` 是垃圾 base64 时不 panic |
| `discovery_缺_jwks_uri_要报错` | 没有 jwks_uri |
| `明文_jwks_uri_默认必须拒绝` | M9 修复的回归门（公钥走明文 = 认证可被绕过） |

---

## 三、完整的 PSF 状态机枚举（替代降级探针）

上一轮只有"降级探针"：喂 2 条跨状态消息看服务端不崩。那不算状态机覆盖。

现在做**真正的枚举**：`3 个协议阶段 × 20 条消息 = 60 个组合`，
每条都喂给真实服务端，断言三件事：

1. **不崩** —— 每次之后都能用新连接正常登录并注册代理；
2. **不挂住** —— 控制连接必须"要么还活、要么已被关闭"，**不能既不响应也不断**
   （那种会话会永久占住服务端槽位，是最难靠单测发现的问题）；
3. **不泄漏** —— 断开后该端口上的后端计数必须归零。

阶段：`PreLogin`（未登录）/ `PostLogin`（已登录未注册）/ `Registered`（已注册）。
消息：覆盖 `FrpMessage` **全部 20 个变体**，含服务端→客户端方向的那些
（客户端发它们就是协议方向违例，正是要测的输入）。

---

## 四、四个配置字段真正实现

之前它们只在 `UNSUPPORTED_*_FIELDS` 里**识别 + 告警**，现在都真正生效。

### 1. `quicBindPort`（服务端）

官方语义：**配了就开**一个独立 UDP 端口，与 `bindPort` 无关。

* 配了 ⇒ 只在那个端口开 UDP，**不再**顺带占 `bindPort/udp`
  （旧行为是隐式副作用，会让"我配了 7101，为什么 7000/udp 也被占"变成谜）；
* 没配且 `transport_protocol = "quic"` ⇒ 退回旧行为，老部署不变；
* 两种情况都保留 TCP 监听。

### 2. `includes`（客户端）

官方 `LoadAdditionalClientConfigs` 的语义：

1. 每项是路径或 **glob**；
2. 取目录、遍历普通文件、按文件名匹配；
3. 命中文件**只取 `proxies` 与 `visitors`** 追加；
4. 各文件的其它字段（`serverAddr`/`token`…）**一律忽略**。

★ 第 4 点最容易误解：`includes` 不是配置继承，而是**批量追加代理定义**。

实现细节：
* 自己写 `glob_match`，语义对齐 Go `filepath.Match`（`*`/`?`/`[a-z]`/`[^...]`）；
* 相对路径以**主配置所在目录**为基准；
* 目录内容**排序后**加载，保证确定性；
* 合并后重名 ⇒ **明确报错**（服务端按 name 定位代理，重名会让"踢一个"变成"随机踢"）；
* includes 文件通常不写 `serverAddr`，而 `parse_client` 要求必填 ⇒
  用 `parse_include_file` 补占位再解析，**不**另写一套宽松解析器
  （本项目吃过"同一语义写两遍只加固一遍"的亏）。

### 3. `tokenSource`（客户端 + 服务端）

官方 `ValueSource`：`type = "file"` 或 `"exec"`。

* `file` —— 读文件，**去首尾空白**（官方明确写过：文件末尾的换行不 trim 就对不上）；
* `exec` —— 跑子进程取 stdout，同样 trim。

优先级：**命令行 `-t` > `tokenSource` > `token`**（官方注释："mutually exclusive with Token field"）。

**安全处理（`exec`）**：
* **不经 shell**：`command` 与 `args` 分开传，不会被解释成 shell 语法；
* **10 秒超时**后强杀 —— 官方跟着 ctx 走没有上限，这里必须有，
  否则一个卡住的子进程会让客户端**永远起不来**；
* 启动日志明确打出令牌来源，便于审计；
* 取到的值只用于登录，**绝不进日志**（`Debug` 只输出路径/命令名）。

**位置（服务端）**：必须在 `check_token_strength` **之前**解析 ——
那个检查看的是实际生效的 token，先检查后解析等于检查空字符串（会误报"token 太弱"）。

### 4. `enablePrometheus`（服务端）

官方默认**不开** `/metrics`，配了才导出。我们之前**无条件开放**。

改成默认关闭，两处理由：
* 与官方默认不一致，照官方文档部署的人会以为它关着；
* 指标含业务信息（在线客户端数、代理名、流量字节），
  "只想开个面板"的部署等于**默认多暴露一份数据面**。

`/api/healthz` **不受影响** —— 健康探针永远可用，否则容器会被反复重启。

---

## 五、清单同步（防反向假警报）

实现归实现，`UNSUPPORTED_*_FIELDS` 也必须跟着改，否则会出现
**"说没实现而实际能用"** 的反向误导 —— 那比沉默更害人。

| 清单 | 本轮移除 |
|---|---|
| `UNSUPPORTED_CLIENT_FIELDS` | `includes`、`tokenSource` |
| `UNSUPPORTED_SERVER_FIELDS` | `quicBindPort`、`tokenSource`、`enablePrometheus` |

---

## 六、质量门

| 项 | 结果 |
|---|---|
| `cargo test --workspace -j 1`（串行） | ✅ **811 通过 / 0 失败**（上轮 785，+26） |
| `cargo fmt --all -- --check` | ✅ 干净 |
| `cargo clippy --workspace --all-targets -D warnings` | ✅ 0 告警 |
| `cargo audit` | ✅ exit 0 零漏洞（184 crates） |
| 退回验证（ES256） | ✅ 退回变红 / 还原变绿 / 文件干净 |

测试分布：123 + 383 + 9 + 251 + 17 + 26 + 2 = **811**

---

## 七、本轮**未完成**的（如实清单）

| 项 | 状态与原因 |
|---|---|
| **TSan** | ❌ 未完成。云端 nightly 仍在下载（网络慢，已跑 1 小时+ 未完成）。**没有结果就不报结果** |
| **Linux TUN Miri** | ❌ 未做。需要 nightly + miri 组件，与 TSan 争同一个 nightly 安装 |
| **Windows VirtualNet** | ❌ 未实现。需要 Wintun 驱动（`wintun.dll`）+ 管理员权限 + 网卡配置，**必须在真机验证**；写而不验证等于埋雷 |
| **`plugin_bridge` Linux 竞态** | ❌ 未修好。上轮两次尝试都引入忙等死循环（云端 4 进程各烧 20 分钟 CPU），已回退并记录正确方向（让"读"只有一个所有者，需重构 `HttpIO` 所有权） |
| **剩余配置字段** | ❌ 未做：`useEncryption` / `useCompression`（数据面加密压缩，协议级改动）、`udpPacketSize`、`natHoleStunServer`、`dnsServer`、`proxyURL`、`pprofEnable`、`assetsDir`、`sshTunnelGateway`、`httpPlugins`、`natholeAnalysisDataReserveHours` |

### 关于 `plugin_bridge` 竞态（已确认是真 bug）

实测证据：同一测试在 Linux 上连跑 10 次 → **5 通过 / 5 次 5 秒超时**；
真实 TCP 链路也能复现（插件收到连接但请求从未转给上游）。
根因是 `HttpIo::watch_closed()` 用 `read(&mut chunk)` 读进局部数组，
future 被 `select!` 取消时那批字节消失。

**两次修复都失败**（都引入 100% CPU 忙等），已回退。正确方向已写进代码注释。

---

## 八、改动清单

| 文件 | 改动 |
|---|---|
| `common/src/auth/oidc.rs` | **ES256/ES384 从 ASN1 改为 FIXED**（核心修复）；删除两个错误的 DER 向量常量；新增 RFC 7515 官方向量与 DER 反向门 |
| `common/tests/oidc_idp_e2e.rs` | **新增**：真实 IdP 端到端测试 9 条 |
| `server/tests/e2e.rs` | **新增**：完整 PSF 状态机枚举（3 阶段 × 20 消息） |
| `common/src/config.rs` | `ServerConfig.quic_bind_port` / `enable_prometheus`；`ClientConfig.includes` + `merge_includes()` + `glob_match` 家族 + `parse_include_file` |
| `common/src/security.rs` | `ValueSource` / `FileSource` / `ExecSource` / `ExecEnvVar` + `validate` / `resolve` / `run_exec`；两端 `token_source` 结构化 |
| `common/src/frp_config.rs` | 两份清单各移除已实现项 |
| `server/src/serve.rs` | QUIC 监听改用 `quic_bind_port` |
| `server/src/dashboard.rs` | `/metrics` 受 `enable_prometheus` 控制；新增 4 条测试 |
| `server/src/main.rs`、`client/src/main.rs` | 启动时解析 `tokenSource` |
| `assets/frps.toml`、`assets/frpc.toml` | 新配置项说明 |

---

## 九、兼容性

* **协议零变更**：与官方 frp 0.71.0 互通不受影响；
* **OIDC 修复是纯增益**：以前 ES256 完全不能用，现在能用（RS256 不受影响）；
* **两处行为变更**（都向官方对齐，已在示例配置里写明）：
  1. `/metrics` 默认关闭 —— 要采集需配 `enablePrometheus = true`；
  2. 配了 `quicBindPort` 后不再占用 `bindPort/udp`；
* 其余新配置项都是"配了才生效"，不配时行为与之前完全一致。
