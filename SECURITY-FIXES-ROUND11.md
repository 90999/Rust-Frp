# NFrp v0.6.0 修复报告（第十一轮）

日期 2026-10-18
来源 云端 Linux 测试分诊 —— 修复跨平台测试缺陷 + **照官方 frp 做法重构测试结构**
结论 **4 项修复**（1 项结构性重构 + 3 项测试 bug）；**无产品安全缺陷**；质量门全绿

---

## 〇、一句话概括

本轮的起点是"云端 Linux 上 `cargo test` 有一批失败"。逐层分诊后发现：
**它们几乎全部是测试自身的问题**，其中最有价值的一条是 ——
我们的 HTTP 测试**开了真实 socket**，而官方 frp 从不开。

修复后：`web::tests` 在云端从 **0/6 → 8/8**。

---

## 一、核心修复：`web.rs` 测试改为"纯逻辑"（照官方 frp）

### 1.1 问题

`client/src/web.rs` 的测试辅助函数 `handle_over_socket`：

```rust
let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
let srv = tokio::spawn(async move {
    let (stream, peer) = listener.accept().await.unwrap();
    let _ = handle(stream, peer, h).await;
});
let mut cli = TcpStream::connect(addr).await.unwrap();
```

**自己造了一个竞态**。云端 Linux 上的实测：

| 跑法 | 结果 |
|---|---|
| 全量串行 6 次 | **0/6 通过** |
| 4 个用它的测试单独跑 | **全部失败**，每次卡满 5.00s |
| 2 个不用它的测试 | 全绿 0.00s |

时间线插桩（毫秒级）证据：

```
TL S1 accept 等 @162µs
TL C3 write+flush 完成（45 字节）@1.08ms
（TL S2 accept 返回 —— 永不出现）
```

⇒ `listener.accept().await` **永不返回**，`handle()` 从未被调用。

而同一份代码在 **Windows 上 17/17 全绿**；**双进程**（真实的服务端进程 + 客户端进程）
在 Linux 上实测 `ok=100 fails=0`。

⇒ **产品没问题，是测试写法在 Linux 上引入了竞态。**

### 1.2 官方 frp 怎么做（关键参考）

`tmp/frp-0.71.0/server/http/controller_v2_test.go`：

```go
resp := httptest.NewRecorder()
handler.ServeHTTP(resp, req)          // 直接调 handler，内存 recorder
```

`pkg/plugin/client/http_proxy_test.go` 更彻底：

```go
clientConn, serverConn := net.Pipe()  // 纯内存管道，无 socket
```

**官方测 HTTP 处理器时从不开 socket。**

### 1.3 修法

把 `handle` 里与 socket 无关的判定逻辑抽成纯函数：

```rust
pub(crate) struct Decision {
    pub code: u16,
    pub ctype: &'static str,
    pub body: String,
}

async fn decide(hub: &Arc<Hub>, req: &http1::Request, peer: SocketAddr) -> Decision
```

`handle` 缩成三步：

```rust
async fn handle(mut stream: TcpStream, peer: SocketAddr, hub: Arc<Hub>) -> anyhow::Result<()> {
    let req = http1::read_request(&mut stream).await?;
    let d = decide(&hub, &req, peer).await;
    http1::send(&mut stream, d.code, d.ctype, d.body.as_bytes(), &[]).await?;
    Ok(())
}
```

测试改成 `decide_over_raw()` —— 解析请求 → 调 `decide()` → 拼响应文本。
**完全不碰 socket**，与官方 `ServeHTTP(resp, req)` 同构。

### 1.4 安全性（判定逻辑逐字未变）

判定顺序与内容**完全保留**：

1. `/api/healthz` 免鉴权（容器探针用，只回 `ok`）
2. Basic Auth 失败 → **401**
3. 写操作：任何一条 `Origin` 非本机 → **403**
4. 写操作：缺 `X-Nfrp-Client` 头 → **403**
5. 其余交给 `route()`

这只是**搬家**，不是改语义。

### 1.5 效果（云端 Linux）

| 指标 | 修复前 | 修复后 |
|---|---|---|
| `web::tests` 连跑 8 次 | **0/6** | ✅ **8/8** |
| 4 个关键测试单独跑 | 全红，各 5.00s | ✅ **全绿，各 0.00s** |

---

## 二、其余 3 项修复

### 2.1 `logfile` 测试用了 Windows 专有的"打不开的路径"

**根因**：测试用 `Z:/nfrp-no-such-drive/x.log` 构造错误路径。

* Windows：盘符不存在 ⇒ 打不开 ✓（所以本地一直绿）
* **Linux：`Z:/...` 是合法的相对路径**（名为 `Z:` 的目录）⇒
  `create_dir_all` 会真的建目录成功 ⇒ 断言失败

**修复**：改成「父路径是一个已存在的**文件**」—— 两个平台都必然 `ENOTDIR`。

**云端验证**：该测试不再失败。

### 2.2 `tun_linux` 测试缺 tokio runtime

**根因**：`#[test]` 下调用 `Tun::create`，在有权限环境（云端 root + `/dev/net/tun`）
会走到 `AsyncFd::new`，**没有 reactor 时 panic**（`no reactor running`）。

**修复**：`#[test]` → `#[tokio::test]`。

**云端验证**：该测试不再失败（`3 passed`）。

### 2.3 `dial_server` 测试的 accept 只等一次

**根因**：

```rust
tokio::spawn(async move { let _ = l.accept().await; });   // ← 只 accept 一次
let s  = dial_server(&cfg,  addr)...;   // 第 1 次 OK
let s2 = dial_server(&cfg0, addr)...;   // 第 2 次：listener 已 drop ⇒ ECONNREFUSED
```

Windows 上第 2 次连接恰好在 listener 回收前完成握手；Linux 上端口立即失效。

**修复**：改成常驻 accept 循环（与产品 `web::run` / `serve.rs` 一致）。

**云端验证**：**3/3 通过**。

### 2.4 附带：`handle_over_socket` 不再吞掉 panic

原先：

```rust
let _ = tokio::time::timeout(Duration::from_secs(2), srv).await;   // ← JoinError 被丢弃
```

服务端 task 若 panic，测试只表现为"响应为空"，**看不到任何线索**。

改后：区分"服务端 task 异常结束 / 超时 / 读取超时"三种情况并给出明确信息。

---

## 三、如实记录：未解决的 6 项

| 测试 | current_thread | multi_thread | 判定 |
|---|---|---|---|
| `plugin_bridge::端到端_http2http_…` | 3/5 | 2/5 | 环境敏感 |
| `plugin_bridge::端到端_http2https_…` | 1/5 | 2/5 | 环境敏感 |
| `plugin_bridge::端到端_https2https_…` | 4/5 | 4/5 | 环境敏感 |
| `plugin_bridge::上游悬挂时…` | 3/5 | 3/5 | 环境敏感 |
| `p2p::full_p2p_over_rendezvous` | 8/10 | — | 环境敏感 |
| `p2p::fake_provider_without_secret_is_rejected` | 偶发 | — | 环境敏感 |

### 为什么不再强行改

这些测试**必须依赖真实 socket**：

* `plugin_bridge`：`dial_upstream()` 硬编码 `TcpStream::connect(self.local_addr)`
  —— 上游是真实地址，无法用内存管道替换（除非改产品代码，属过度改动）
* `p2p`：QUIC/KCP 打洞本质就是 UDP socket 交互

官方 `net.Pipe()` 只适用于"处理器 + 客户端"这一类，**套不到"必须连真实上游"**。

### 尝试过并失败的方案

| 方案 | 结果 |
|---|---|
| 把 `mini_rendezvous` 改成常驻循环 | **A/B 对照：0/5 → 1/5**，无实质改善，**已回滚** |
| 全部改 `multi_thread` runtime | 无改善（见上表） |
| 加 `yield_now()` | 无改善 |
| 去掉 `cli.shutdown()` | 只修好一半 |

### 一条只记录、不改码的产品观察

p2p 打洞对 `window`（端口预测）参数敏感（云端各 10 次）：

| window | QUIC | KCP |
|---|---|---|
| 4（开端口预测） | 8/10 | **3/10** |
| 0（关端口预测） | **10/10** | **10/10** |

⇒ 端口预测显著影响打洞成功率。但**没有足够证据判定是产品缺陷**
（也可能是测试替身 `mini_rendezvous` 的行为差异），故只记录。

---

## 四、方法论收获

### 4.1「两轮对照」不足以判定确定性

`plugin_bridge` 两个测试**全量跑两轮都红**，但**单独跑变绿**
⇒ 稳定复现的**并发竞争**，不是确定性缺陷。

| 全量 | 单独 | 判定 |
|---|---|---|
| 红 | 绿 | 并发竞争 |
| 红 | 红 | 真确定性失败 |

### 4.2 测试能不用 socket 就不用

向官方 frp 学习：`httptest.NewRecorder` / `net.Pipe()`。
只有被测对象**本质需要真实网络**时才用 socket，并接受其环境敏感性。

### 4.3 `strace` 会掩盖竞态

`strace` 下同一个必失败的测试变绿（0.01s）——
因为每次系统调用都陷入内核，**改变了调度时序**。
⇒ 别用 strace 判断"是否能通过"。

### 4.4 本轮我自己的失误（8 次，全部差点误判）

1. `./$CARGO_TARGET_DIR` 路径拼错 → 程序没跑（exit 127）→ 险些读成"资源耗尽"
2. 生成的脚本没校验 → 跑的是旧版本，输出被误读
3. Python 用 `threading` 测 loopback → 51% 失败是**我代码的线程时序**
4. `tokio::join!(accept, client)` 结构 ≠ 产品
5. `stop.notify_one()` 没停干净 → 程序挂死（exit 124）→ 读成"瞬间全挂"
6. `swap` 补丁编译失败
7. 回滚 `mini_rendezvous` 时漏掉配对大括号
8. `heredoc` 里的三引号把外层字符串截断

**共同教训**：任何"实验结论"必须先验证实验本身跑通
（看 exit code、看锚点、看日志真的出现）。

---

## 五、质量门

| 项 | 结果 |
|---|---|
| `cargo test --workspace`（本地串行） | ✅ **751 通过 0 失败** |
| `cargo fmt --all -- --check` | ✅ 干净 |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ **0 告警** |
| `cargo audit` | ✅ exit 0 |
| 云端 `web::tests` × 8 | ✅ **8/8** |
| 云端 `logfile` / `tun_linux` / `dial_server` | ✅ 12 / 3 / **3-of-3** |

---

## 六、改动清单

| 文件 | 改动性质 |
|---|---|
| `client/src/web.rs` | 抽出 `Decision` + `decide()`；`handle` 精简；测试改 `decide_over_raw()` |
| `client/src/main.rs` | `dial_server_按配置开_keepalive`：accept 改常驻循环 |
| `common/src/logfile.rs` | 测试改用"父路径是文件"构造错误路径 |
| `common/src/vnet/tun_linux.rs` | `#[test]` → `#[tokio::test]` |

**产品行为无变更**（`decide` 只是把 `handle` 里的判定逻辑原样搬出）。

---

## 七、兼容性

* **无配置文件变更**
* **无协议变更**
* **无行为变更**
* `frps -v` / `frpc -v` 仍输出裸 `0.71.0`
* 与官方 frpc 0.71.0 互通不变
* **直接替换二进制即可升级**
