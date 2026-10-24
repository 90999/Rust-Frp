# NFrp 第十四轮：测试 flake 消除 + 渗透低危项修复

日期 2026-10-24
上游来源 **OpenCode** 的渗透测试（`tmp/pentest_round/PENTEST-REPORT.md`）与交接清单
本轮处理 交接清单的 **P0** 与 **P5**
质量门 785 通过 / fmt 干净 / clippy 0 告警 / audit 零漏洞 / 冒烟 28/28

---

## 〇、先看 OpenCode 做了什么

接手前先核实了他的报告，逐条验证而不是照抄。

### 已验证属实的

| 项 | 核查结果 |
|---|---|
| `deny.toml` 存在（1026 B） | ✅ |
| `supply-chain/` 三个文件 | ✅ |
| `tls_cert_file` / `tls_key_file` / `tls_trusted_ca_file` 字段 | ✅ 已实现 |
| `tokio` 升到 1.54.1 | ✅ |
| `rustls-webpki` 升到 0.103.16 | ✅ |
| `cargo audit` 零漏洞 | ✅ 复跑确认为 0 |
| 测试全绿（当时 776） | ✅ 复跑确认 |

### 一处表述不准确

他说 `webpki-roots` 「升到 1.0.10」。实际 **`Cargo.lock` 里有两个版本并存**：

```
webpki-roots  0.26.11
webpki-roots  1.0.10
```

这是依赖树里不同 crate 要求不同大版本导致的，**不是问题**（各自用各自的），
但「升到 1.0.10」这个说法容易让人以为只有一个。记录在此以免后续误判。

### 他那轮的实质成果（值得肯定）

- **TLS 证书组真正写完**：不只是侦察。服务端自定义证书、客户端证书（mTLS）、
  只配 cert 不配 key 时明确报错而不是静默退回自签名。**mTLS 还做了内存双端真实握手测试**。
- **3 条 RustSec 通告真实修复**（rustls-webpki / webpki-roots / tokio）
- **ASan 全量跑通**：common 371 + server 238，无 `AddressSanitizer` 报错
- **Miri 部分跑通**：`frp_config` 38/38
- **cargo-deny 基线建立**

### 他诚实标注的未完成（我认同）

- TSan 未跑（Windows MSVC 不支持）
- `cargo vet` 只有 184 条 exemption，**不是人工审计**
- Windows VirtualNet、官方 xtcp NatHole、剩余配置字段都没做

---

## 一、P0：消除 e2e 测试的端口竞态

### 问题

`server/tests/e2e.rs` 的 `free_port_both()`：

```rust
fn free_port_both() -> u16 {
    for _ in 0..64 {
        let p = free_port();                              // ← TCP listener 已 drop
        if UdpSocket::bind(("127.0.0.1", p)).is_ok() {    // ← 中间有空窗
            return p;
        }
    }
    panic!("试了 64 次都没拿到 TCP/UDP 都能 bind 的端口")
}
```

**两次 bind 之间没有任何保护**。并行测试时另一个线程可能正好抢走这个号，
于是 64 次全撞车并 panic。这是**真实存在**的 flake，不是"偶发环境问题"。

### 修法

```rust
fn free_port_both() -> u16 {
    for _ in 0..128 {
        let tcp = TcpListener::bind("127.0.0.1:0")?;   // listener **不 drop**
        let p = tcp.local_addr()?.port();
        let udp = UdpSocket::bind(("127.0.0.1", p))?;  // TCP 仍持有时试 UDP
        // 两个都绑上 ⇒ 这个号真的可用
        if !claimed.insert(p) { continue; }            // 本进程内去重
        drop(tcp); drop(udp);                          // 登记后再交给被测服务端
        return p;
    }
    panic!(...)
}
```

三点改进：

1. **TCP 与 UDP 同时持有**，两个都绑上才算数
2. **校验期间 socket 一直活着**，别的测试拿不到
3. 校验通过后**先登记再释放**，进程内不再发出去

### 验收

```
跑 5 次 cargo test --workspace -j 2：
  第 1 次: OK   第 2 次: OK   第 3 次: OK   第 4 次: OK   第 5 次: OK
失败次数: 0 / 5
```

---

## 二、P5：渗透测试的三个低危项

### PT-03 · `HEAD` 仍返回响应体

**证据**：`HEAD /api/status` → 200 + 659 B；`HEAD /` → 200 + 10368 B HTML。

**问题**：RFC 9110 §9.3.2 要求 HEAD **只回头、不回头**。
危害有限（不是漏洞，是协议违规），但会带来实际麻烦：

- 用 HEAD 做健康检查的监控会白白拉一遍完整页面
- 某些缓存 / 代理对 HEAD 的 body 处理不一致，可能污染缓存

**修法**：给 `send()` 加 `head_only` 参数，`HEAD` 时不写 body，
但 **`Content-Length` 仍按真实长度发送** —— 那正是 HEAD 的语义。

### PT-07 · 只读端点接受 POST

**证据**：`POST /api/status` → 200 + 完整状态 JSON。

**根因**：未匹配 `ADMIN_PATHS` 的 POST 会落进 `match path` 的只读分支，
于是被当成普通路径处理、返回 200。

**修法**：**未匹配的 POST 一律 405**，并带 `Allow: GET, HEAD`。

用 405 而不是 404：路径确实存在，只是方法不对 —— 这是 HTTP 语义要求，
顺带告诉调用方该用什么方法。

### PT-05 · 没有任何安全响应头

**证据**：面板响应里没有 CSP / X-Frame-Options / X-Content-Type-Options。

**修法**：所有响应统一加：

| 头 | 作用 |
|---|---|
| `X-Content-Type-Options: nosniff` | 禁止 MIME 嗅探 |
| `X-Frame-Options: DENY` | 挡点击劫持（把面板套进攻击者页面诱导管理员点"踢出"） |
| `Referrer-Policy: no-referrer` | 面板 URL 不通过 Referer 泄露 |
| `Content-Security-Policy` | `default-src 'none'` + 内联脚本样式 + `frame-ancestors 'none'` |

#### 为什么**不用** HSTS

面板默认是**明文 HTTP**。对明文响应发 `Strict-Transport-Security` 会被浏览器
**直接忽略**（RFC 6797 §7.2），发了也没用；更糟的是会让人误以为"已经上 HTTPS 了"。
等面板自己支持 TLS 之后再按需加。

#### CSP 里 `'unsafe-inline'` 的取舍

面板 HTML 的脚本与样式都是内联的（`html_page()` 单文件），所以
`script-src` / `style-src` 必须允许 `'unsafe-inline'`。

这不是疏忽 —— 在自包含页面上，能挡的部分是 `default-src 'none'`
（禁止一切外域请求、图片、字体、frame），而那正好是最有价值的部分。

### 实现细节：为什么不用运行时拼接

第一版写了个 `with_sec_headers(own) -> Vec<...>` 在运行时合并。
编译失败：`send()` 收的是 `&[(&str, &str)]`，`&with_sec_headers(...)`
会产生临时值、活不过调用表达式。

改成两个 `static` 数组在**编译期**用 `const fn` 拼好：

```rust
static SEC_HEADERS_WITH_AUTH: [(&str, &str); SEC_HEADERS.len() + 1] = concat_headers_auth();
```

零运行时开销、零生命周期问题。

---

## 三、测试

新增 6 条，全部走**真实 socket + 真实 HTTP**（不是只测纯函数）：

| 测试 | 验证什么 |
|---|---|
| `head_returns_headers_without_body` | 四个路径的 HEAD 都不回 body，但仍有 Content-Length |
| `get_still_returns_body` | **对照**：GET 照常回 body（防"把修法扩到 GET"把面板变空白） |
| `post_to_readonly_endpoint_is_405` | 三个只读端点 POST 都 405 且带 Allow；真正写接口不受影响 |
| `security_headers_on_every_response` | 成功 / 401 / 405 / 免鉴权四类响应都带四个安全头 |
| `unauthorized_still_carries_www_authenticate` | 401 的 WWW-Authenticate 没被安全头挤掉 |
| `sec_headers_are_sane` | 常量本身：非空、无重名、合并数组后半段就是 SEC_HEADERS |

---

## 四、退回验证 3/3

| 修复 | 退回方式 | 结果 |
|---|---|---|
| PT-03 HEAD | `if !head_only` → `if true` | ✅ 测试变红 |
| PT-07 POST | 删掉新增的 405 分支 | ✅ 测试变红 |
| PT-05 安全头 | `SEC_HEADERS` 改成空数组 | ✅ 测试变红 |

★ 这一步不能省。本项目第十二轮吃过亏：两条修复的第一版退回**仍是绿的**，
因为它们当时压根没有测试 —— 补了测试才真正被守住。

---

## 五、顺带修的一个 clippy 告警

`server/src/nathole_official.rs` 里有一处多余的 `..Default::default()`：
所有字段都已显式指定，结构体更新没有效果。clippy 在 `-D warnings` 下报错。
删掉即可 —— 是 OpenCode 那轮遗留的，无行为影响。

---

## 六、质量门

| 项 | 结果 |
|---|---|
| `cargo test --workspace`（串行） | ✅ **785 通过 0 失败**（上轮 779，本轮 +6） |
| `cargo test --workspace -j 2` × 5 次 | ✅ **5/5 全绿**（flake 已消除） |
| `cargo fmt --all -- --check` | ✅ 干净 |
| `cargo clippy --workspace --all-targets -D warnings` | ✅ 0 告警 |
| `cargo audit` | ✅ exit 0（184 crates） |
| `cargo deny check` | ✅ advisories / bans / licenses / sources 全 ok |
| 端到端冒烟 | ✅ **28 / 28** |
| 退回验证 | ✅ **3 / 3** |

---

## 七、本轮**未做**的（诚实清单）

交接清单里还有这些没动，不能算完成：

| 项 | 状态 |
|---|---|
| **P1 Windows VirtualNet** | 未做。需要 Wintun/TAP 驱动 + 管理员权限 + 网卡配置，且**必须在真机验证** |
| **P2 官方 xtcp NatHole** | 未做。OpenCode 已有 `server/src/nathole_official.rs`（16 KB），但没接进实际链路 |
| **P3 剩余配置字段** | 未做（`useEncryption` / `useCompression` / `tokenSource` / `includes` / `quicBindPort` 等） |
| **P4 审计补跑** | 未做（TSan / 完整 PSF / Phaedra / 真实 IdP e2e / Linux TUN Miri） |
| **PT-04 重复 Authorization** | 未修 —— 判定为「设计」，取第一个是多数代理的行为 |
| **PT-10 控制面 yamux/frp v2** | 未测 —— 覆盖缺口，需另开授权测试 |

---

## 八、一次失败的修复尝试（必须记录）

### 发现的真问题

在云端跑全量测试时，`plugin_bridge` 有 **6 个测试失败**。排查后确认这是
**产品代码的真实竞态**，不是测试问题：

**证据 1**：同一测试在 Linux 上连跑 10 次 —— **5 通过 / 5 次 5 秒超时**。
通过时耗时 0.01 秒，失败时正好卡满超时。这是竞态的标准特征。

**证据 2**：绕过测试辅助函数、用**真实 TCP 连接**复现，同样挂住：
```
[diag2] read_to_end = Err(Elapsed(()))
[diag2] serve = Err(Elapsed(()))
[diag2] upstream got = Err(Elapsed(()))
```
插件收到连接，但**请求从未转给上游**。

**根因**：`HttpIo::watch_closed()` 用 `read(&mut chunk)` 读进**局部数组**。
这个 future 在 `wait_upstream` 的 `select!` 里被另一支抢先完成而 drop 时，
已经 `poll_read` 进来的字节随局部变量一起消失。丢掉的可能正是请求体开头。

原代码注释里写着「取消安全：tokio 的 `AsyncRead::read` 在取消时不消费数据」
—— **那句话是错的**。

### 两次修复尝试都失败了

**第一版**：把 `watch_closed` 改成 `read_buf` 直接读进 `self.buf`
（它属于 `self`，取消不丢），并在"缓冲非空时立即返回 `Ok(false)`"。

后果：调用方是 `loop { select! }`，立即返回让它变成 **100% CPU 忙等死循环**。
- 云端：4 个测试进程各烧掉 **20 分钟** CPU，负载 12.5
- 本地：单进程烧掉 **1288 秒** CPU

**第二版**：在循环里加 `if io.available() > 0 { return Ok(fut.await) }`，
想让缓冲有数据时只等上游。

后果：仍然空转 —— 因为 `read_buf` 已经把数据吸进缓冲，`available()` 恒 > 0。

### 最终处理：回退，如实记录

两处代码都回到原样，并在注释里写清：

- 缺陷是什么、怎么复现
- 两次修复为什么失败（附实测数字）
- **正确方向**：让"读"只有一个所有者 —— 单独一个读协程独占 `stream`，
  把字节推进共享队列，`wait_upstream` 只等队列信号。这样两个 future
  不会抢同一个 stream。这需要重构 `HttpIo` 的所有权结构。

**判断依据**：宁可保留一个已知的、只在 Linux 上间歇出现的缺陷，
也不能引入一个会让 CPU 跑满的死循环。后者影响面大得多。

### 影响面（如实说明）

- **Windows**：21/21 稳定通过，产品不受影响
- **Linux**：`http2*` / `https2*` 的**端到端用例**间歇失败；
  真实使用中若命中该竞态，表现为插件处理偶发挂起（5 秒超时后释放）
- 其余 780 个测试与 28 项冒烟全部正常

---

## 九、改动清单

| 文件 | 改动 |
|---|---|
| `server/tests/e2e.rs` | `free_port_both()` 重写，消除端口竞态 |
| `server/src/dashboard.rs` | `send()` 加 `head_only`；`SEC_HEADERS` 常量；`SEC_HEADERS_WITH_AUTH/ALLOW`；POST 未匹配 → 405；6 条新测试 |
| `server/src/nathole_official.rs` | 删一处多余的 `..Default::default()` |

---

## 九、兼容性

- **无配置变更**：本轮不涉及任何配置项
- **协议零变更**：与官方 frp 0.71.0 互通不受影响
- **HTTP 行为变化两处**（都是修正，符合 RFC）：
  - `HEAD` 不再返回 body
  - 只读端点的 POST 从 200 变成 405
- 若有用例依赖「POST /api/status 返回 200」，需改用 GET（这是正确做法）
