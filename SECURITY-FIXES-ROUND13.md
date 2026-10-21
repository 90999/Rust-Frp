# NFrp 第十三轮：负载均衡 / KCP / 健康检查与官方 frp 对齐

日期 2026-10-20
本轮性质 **特性对齐 + 缺陷修复**，不是安全审计
质量门 766 通过 / fmt 干净 / clippy 0 告警 / audit 零漏洞 / 冒烟 28/28

---

## 〇、这轮在解决什么

用户指出的问题很具体：

> 功能列表里有负载均衡和健康检查，但官方 frp 在这些特性的策略丰富度和边缘场景
> 处理上经过了更长时间的迭代。例如 group 负载均衡采用"最小连接数"分摊，
> 而官方 frp 在长连接、突发流量下的具体表现和调优参数，可能积累了更多实践细节。
> 此外，像 KCP 会话表封顶 1024 这类资源上限，在超大规模部署时可能需要拆分实例来规避。

于是这轮逐项去读官方 0.71.0 的实现，对照差异，该改的改，该保留的说明理由。

---

## 一、最重要的发现：官方用的是**轮询**，不是最少连接

### 官方怎么做的

`server/group/base.go` 的 `worker`：

```go
func (bg *baseGroup) worker(realLn net.Listener, acceptCh chan<- net.Conn) {
    for {
        c, err := realLn.Accept()
        if err != nil {
            return
        }
        err = gerr.PanicToError(func() {
            acceptCh <- c        // ← 丢进共享 channel
        })
        ...
    }
}
```

`server/group/listener.go` 里每个代理各自 `Accept()` 同一个 `acceptCh`：

```go
func (ln *Listener) Accept() (net.Conn, error) {
    select {
    case <-ln.closeCh:
        return nil, ErrListenerClosed
    case c, ok := <-ln.acceptCh:   // ← 谁先抢到谁拿到
        ...
    }
}
```

**这就是无状态轮询**：连接按到达顺序被某个代理取走，与后端当前有多忙无关。

### 我们原来怎么做的

`registry.rs` 的 `PortGroup::pick` 用的是**最少连接数**，代码注释还专门论证了
"纯轮询会把慢的后端压死"。推理没错，但它**和官方行为不一致**。

### 怎么处理的

引入 [`LbPolicy`]，两种策略都保留：

| 值 | 行为 |
|---|---|
| `roundrobin`（**新默认**） | 严格 1/N 均分，**与官方一致** |
| `leastconn` | 在途连接最少的优先，能力不均时更优 |

默认改成 `roundrobin` —— **对齐优先**。`leastconn` 作为可选的超集能力保留：
调度完全发生在服务端内部，开它不影响与官方客户端的互通。

---

## 二、顺带抓到的一个真实缺陷

改造 `pick` 时发现旧实现有**系统性偏袒**：

```rust
// 旧代码
let mut best_load = self.members[0].inflight();   // ← 固定从 0 号初始化
let start = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
for k in 1..n {
    let i = (start + k) % n;                      // ← 从 start+1 扫，跳过 start
    ...
}
let start_load = self.members[start].inflight();  // ← 事后补判 start
```

问题：`best_load` 初值是 `members[0]`，但循环从 `start+1` 开始。
当 `start != 0` 时：

* `members[0]` 的负载被当成初值参与比较，**但循环里会再访问一次其他成员**；
* `start` 那个成员要等到最后才补判，且判据是 `<=`（非严格小于）。

结果是**部分后端被系统性偏袒**，在 `n >= 3` 时表现为分配不均。

**修法**：从 `start` 起扫满一整圈，初值就取 `members[start]`：

```rust
let mut best = start;
let mut best_load = self.members[start].inflight();
for k in 1..n {
    let i = (start + k) % n;
    ...
}
```

这条修改对两种策略都正确，且不影响官方行为（轮询根本不看负载）。

---

## 三、KCP 会话上限：加了安全下限，并做成可配

### 用户提的点

> KCP 会话表封顶 1024 这类资源上限，在超大规模部署时可能需要拆分实例来规避。

### 实际情况

`max_sessions` 本来就是字段，但**默认值硬编码**，用户改不了。

### 改了什么

1. 新增配置项 `kcp_max_sessions`（0 或不填 = 用默认 1024）
2. 新增**安全下限** `MIN_KCP_SESSIONS = 64`

下限的理由：这个值直接决定内存上界（`值 × 15.3 KB`）。如果允许配 0 并照用，
表现是"第 1 条连接就被丢弃" —— **KCP 完全不可用，而进程不报错**。
那种静默失效比拒绝启动更难排查。

3. 启动日志会打出实际生效的上限，配置错时能看到

### 关于"超大规模"

正确的做法**不是无限调大**，而是：

1. 用 TCP / QUIC 承载控制连接（KCP 只在两者都走不通时才需要）
2. 或在前面挂负载均衡，把客户端拆到多个 frps 实例

这一点已经写进 `assets/frps.toml` 的注释里，避免用户以为"调大就好"。

---

## 四、健康检查：三处对齐官方

### ① HTTP 探测改成**严格 2xx**

官方 `client/health/health.go` 的 `doHTTPCheck`：

```go
if resp.StatusCode/100 != 2 {
    return fmt.Errorf("do http health check, StatusCode is [%d] not 2xx", resp.StatusCode)
}
```

我们原来是 `code < 400`，把 3xx / 404 都算健康。差别在真实场景里很明显：

* 服务配了强制 HTTPS 跳转（301/302）⇒ 探测永远拿到 301 ⇒ 旧判据认为它**一直健康**，
  但那个端口其实没在提供内容
* 反向代理返回 404 时同理

改成严格 2xx 后，这类部署需要把 `healthCheckPath` 指到真的返回 2xx 的路径 ——
这正是官方文档要求的行为。

### ② 新增 `httpHeaders` 支持

官方 `pkg/config/v1/proxy.go`：

```go
HTTPHeaders []HTTPHeader `json:"httpHeaders,omitempty"`
```

用于需要鉴权的健康检查端点（带 `Authorization`、内部 `X-Health-Token` 等）。
不支持时这类端点**一律探测失败** —— 表现为"服务明明活着，客户端却判定它不健康、
把流量摘掉"。

现在支持官方写法：

```toml
[[proxies.healthCheck.httpHeaders]]
name = "Authorization"
value = "Bearer secret-token"
```

### ③ `Host` 头语义对齐

官方在 `doHTTPCheck` 里：

```go
req.Header = monitor.header
req.Host = monitor.header.Get("Host")
```

即**配置里的 Host 覆盖默认值**。我们照做：配了 `Host` 就用它，没配才用兜底值。

### ④ 顺带做的加固：HTTP 头注入防护

官方用 Go 的 `http.Header`，库本身会拒绝非法头值。
我们是**手写 HTTP 请求**，必须自己挡 —— 否则配一个含 `\r\n` 的值就能往探测请求里
插入任意额外的头，甚至拼出第二条请求（请求走私）。

实现：头名与头值里的 CR/LF 全部剥掉。

---

## 五、测试

| 测试 | 验证什么 |
|---|---|
| `default_policy_is_round_robin_like_official` | 默认必须是轮询；负载不均时照样均分 |
| `pick_prefers_the_least_loaded_backend` | 显式设 `LeastConn` 时确实倾斜 |
| `lb_policy_parsing` | 认得 `rr` / `lc` / 大小写 / 连字符；认不出回落默认 |
| `kcp_session_cap_has_a_floor` | 配 0 抬到下限、正常值不动 |
| `kcp_会话表必须有上限` | 超额会话确实被丢弃（改用 `force_max_sessions_for_test` 绕开下限） |
| `官方的_healthcheck_httpheaders_能被解析` | 官方 `[[proxies.healthCheck.httpHeaders]]` 能读进来 |
| `没配_httpheaders_时是空表` | 不配时不报错 |
| `probe_request_includes_configured_headers` | 配置的头全部出现在请求里 |
| `probe_request_honours_configured_host` | 配了 Host 就用它，且只有一个 Host 行 |
| `probe_request_strips_crlf_from_values` | **头注入**被挡住 |
| `probe_request_strips_crlf_from_names` | 头名里的注入同样挡住 |
| `probe_request_skips_empty_names` | 空头名不产出非法行 |

★ 头注入那条测试第一版写错了判据：它断言"`X-Injected` 这个字符串不应出现在请求里"。
实际 CR/LF 剥掉后内容被压进上一个头的值，字符串仍在但**不构成独立头行** ——
那是安全的。改成验证"请求行结构"（每行必须以已知头名开头、不能拼出第二条请求、
只能有一个空行）才测到点子上。

---

## 六、质量门

| 项 | 结果 |
|---|---|
| `cargo test --workspace`（串行） | ✅ **766 通过 0 失败**（上轮 757，本轮 +9） |
| `cargo fmt --all -- --check` | ✅ 干净 |
| `cargo clippy --workspace --all-targets -D warnings` | ✅ 0 告警 |
| `cargo audit` | ✅ exit 0（184 crates） |
| 端到端冒烟 | ✅ **28 / 28** |

---

## 七、改动清单

| 文件 | 改动 |
|---|---|
| `server/src/registry.rs` | 新增 `LbPolicy`；修 `pick` 偏袒缺陷；`Registry` 加 `lb_policy` 原子字段 |
| `server/src/serve.rs` | 装载 `lb_policy`；KCP 上限接配置并打日志 |
| `common/src/config.rs` | 新增 `lb_policy` / `kcp_max_sessions` / `HttpHeader` / `health_check_http_headers` |
| `common/src/frp_config.rs` | 映射官方 `healthCheck.httpHeaders` |
| `common/src/frp/kcp.rs` | `MIN_KCP_SESSIONS`；`with_max_sessions` 加下限；新增 `max_sessions()` 与测试用 `force_max_sessions_for_test` |
| `client/src/health.rs` | HTTP 探测严格 2xx；支持自定义头；Host 语义对齐；抽 `build_probe_request` + 头注入防护 |
| `assets/frps.toml` | 补 `lb_policy` / `kcp_max_sessions` 配置说明 |

---

## 八、兼容性

* **无破坏性变更**：所有新配置项都有默认值，老配置文件一个字节不用改
* **协议零变更**：与官方 frp 0.71.0 互通不受影响
* **默认行为变化一处**：group 负载均衡从「最少连接」改为「轮询」，
  这是**向官方对齐**。依赖旧行为的部署可显式配 `lb_policy = "leastconn"`
* 租户隔离（第六轮 D-1）完整保留，不因这轮改动而放松
