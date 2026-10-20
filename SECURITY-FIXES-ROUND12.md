# NFrp v0.6.1 修复报告（Shannon 渗透测试轮）

日期 2026-10-20
来源 **Shannon**（KeygraphHQ 自主 AI 渗透测试器）对本项目的源码 + 运行时审计
结论 **核对 13 条发现：10 条无需改动（已修过 / 为对齐官方故意保留），3 条是真新发现，全部修复**
质量门全绿

---

## 〇、这一轮的方法与你的要求

> **获得日志之后一定要查之前的记录，是不是有原因不修的还是为了对齐不修的**

所以每一条发现都按三类归档：

| 类别 | 含义 | 处置 |
|---|---|---|
| **A 已修过** | 历史记录里有修复 + 回归测试 | 不动 |
| **B 故意不修** | 记录里写明"为对齐官方 frp 而保留" | 不动，注明原因 |
| **C 新发现** | 两者都不是 | 修 |

---

## 一、Shannon 环境（顺带记录，方便复现）

Shannon 是 **Keygraph** 的自主 AI 渗透器，核心承诺是 **"No exploit, no report"**。

| 项 | 情况 |
|---|---|
| 平台要求 | **不支持原生 Windows**，必须在 WSL2 里跑 |
| 还要求 | **非 root 用户** + 无 sudo 可用 docker |
| 本机落地 | Docker Desktop + WSL2 内装 Docker Engine 29.9.1（阿里云源） |
| 模型 | `agnes-3.0-flash`（OpenAI 兼容端点，用 `--models-config` 描述） |
| 关键坑 | **源码放在 `/mnt/e`（Windows 挂载）会让容器内 grep 一次耗时 2 分钟**；复制到 WSL 原生盘后 **0.003s**（快 4 万倍） |
| 完整跑完 | **未成功** —— 13 阶段的连续模型调用会被限流打断（`AGENT_EXECUTION_FAILED`） |

已获得的产物：

* `pre_recon_deliverable.md`（39 KB，架构 / 信任边界 / 全部入口清单）
* `nfrp_security_report.md`（10 KB）
* 两轮 agent 日志（259 KB）

---

## 二、13 条发现逐条核对

### A 类：已修过（7 条）

| # | Shannon 的发现 | 历史依据 | 结论 |
|---|---|---|---|
| 1 | **空 token = 匿名控制面**（它判 HIGH） | v0.5.6 修（审计总报告 M6）：无认证 + 绑**对外**地址**拒绝启动**；只有"默认配置"才强告警放行 | Shannon 没看到 `validate()` 的三层判定，**误报** |
| 5 | work_conn 的"空凭据 + 源 IP 相同"回退 | v0.5.5 A-1 | 有更强防线：会话声明的 `work_conn_cred` 会让空凭据**直接被拒**，注释明说"不必依赖源 IP" |
| 6 | 未配证书时自动生成自签证书 | 设计如此 | 自签是"开箱可用"的必要条件，且客户端默认不校验（见下） |
| 7 | 面板 XSS / `esc()` | **第五轮 H4** | `table()` / `card()` 已全部转义，并有反向断言 |
| 8 | `sudp` 反射到客户端自报地址 | **L18 / E9-0** | `SeenVisitorIps` IP 级白名单 + 每包 ACL，已关闭 |
| 9 | 服务端可把客户端变成开放代理 | **H4 / F1** | `validate_remote_proxy` 拒绝任何 `plugin*` 字段，且 `local_addr` 限制回环 |
| 10 | P2P 能否被指到任意 IP | **B-1 / E9-1** | `Session.expected_ip` 绑定控制连接源 IP + 每包 ACL；候选地址**只换端口不换 IP** |

### B 类：为对齐官方而故意保留（3 条）

| # | Shannon 的发现（它判 HIGH/MEDIUM） | 为什么**不能**改 |
|---|---|---|
| 2 | 客户端 TLS **默认跳过**服务端证书校验 | **官方 frpc 就是 `InsecureSkipVerify`**（frp 的控制通道默认是明文 v1，TLS 是可选层）。改成默认校验 ⇒ **官方 frpc 全部连不上**，直接毁掉项目的存在意义。代码注释已写明这是"自有客户端 + 自有服务端"场景才开的开关 |
| 3 | v1 通道 PBKDF2-HMAC-SHA1 **只有 64 轮** | 官方 `golib v0.8.2` 的固定值。注释特别记了一笔：**golib master 分支后来把盐从 `frp` 改成了 `crypto`，照 master 写会得到一个"自洽但跟官方不通"的实现** |
| 4 | v1 的 token 证明用 **MD5** | frp 协议规定 `privilege_key = md5(token + timestamp)`。这是**线路格式**，不是设计选择 |

★ 这三条的共同点：**Shannon 看不到"必须与官方互通"这个约束**，
所以把协议兼容必需的设计当成缺陷报了出来。

### C 类：真新发现（3 条，全部已修）

#### C-1 · 面板管理操作**完全没有审计记录**（低危）

**Shannon 的原话**：
> `kick` emits only a tracing line, not an `ADMIN_ACTION` audit event.

**我核对时发现比它说的更严重**：

```bash
$ grep -rn "ADMIN_ACTION" server/src/
audit.rs:56: pub const ADMIN_ACTION: &str = "admin_action";   # ← 定义了
# 没有任何使用点
```

**`ADMIN_ACTION` 这个常量定义了，但全仓零使用** ——
也就是说面板的**增 / 删 / 踢三个操作一条审计都没记**，
而 `PROXY_ADD` / `PROXY_REMOVE` 只在 `serve.rs`（客户端自己注册那条路）记录。

审计和日志是**两条不同的链**：日志会轮转/被删，`[audit]` 的 JSONL 才是事后追责用的。
踢人是**不可回滚**的操作（客户端所有隧道立刻失效），只留日志等于查不到谁在什么时候踢了谁。

**修法**：`add_proxy` / `remove_proxy` / `kick` 三处都补 `ADMIN_ACTION`。

**回归测试**：`admin::tests::kick_必须写审计` —— 断言审计条目增加 + `target` 是 run_id + `detail` 含操作类型与理由。

★ 写测试时踩了一个坑：`AuditLog::record()` 在 `enabled == false` 时**直接 return**，
而 `Registry::unlimited()` 默认不启用审计 ⇒ 测试会因"审计没开"失败而不是"代码没写"。
已换成开启审计的安全上下文，并加了**前置自检**（先记一条 `selftest` 确认审计真的在记）。

#### C-2 · `forget_session` 写好了但**没接上**（低危）

**Shannon 的原话**：
> OIDC `subjects` map has no wired `forget_session` on teardown (per-session leak until restart).

**核对属实**：

```bash
$ grep -rn "forget_session" --include=*.rs
common/src/security.rs:505  pub fn forget_session(...)   # 定义
server/src/guard.rs:263     pub fn forget_session(...)   # 转发
common/src/auth/oidc.rs:608 pub fn forget_session(...)   # 实现
common/src/auth/oidc.rs:1260  v.forget_session("run-A"); # ← 只有单测调用
# 生产代码：零调用
```

⇒ `OidcVerifier::subjects`（`run_id -> sub` 表）**每个 OIDC 会话泄漏一条，直到进程重启**。

**修法**：在 `ClientGuard::drop` 里调用（与 `registry.remove()` 同一个位置）。
放在 `Drop` 是为了**覆盖所有退出路径**（正常断开、被踢、panic 展开），不会漏。

**回归测试**：`registry::tests::控制连接退出必须清掉_oidc_subject_绑定` ——
造真 OIDC 上下文、塞一条绑定、drop `ClientGuard`、断言表清空。

★ 没有用 `SecurityContext::from_config`：那条路径在 JWKS 未拉取时会把认证换成
`OidcUnavailable`，`forget_session` 变成空操作，**测不到修复点**。

#### C-3 · 面板 `catch` 分支的 `innerHTML` 没转义（加固）

**Shannon 的原话**：
> `innerHTML` at `dashboard.rs:779` — catch 分支写 `innerHTML = '...'+e` 没有 `esc(e)`。
> **当前安全**……**加固提示**：如果将来 fetch 错误携带了响应文本，这会变成 stored-XSS 向量。

**核对属实，且它准确指出了"今天不可利用"**：

```javascript
} catch(e) {
    document.getElementById('cards').innerHTML = '<div class="empty">读取状态失败：'+e+'</div>';
}
```

`e` 是本地 JS 的 `Error`（`fetch` 或 `JSON.parse` 失败），**不是服务端文本**，
内容由浏览器生成、攻击者控制不了。

**但这是第五轮 H4 漏掉的路径** —— 那一轮修了 `table()` / `card()`，
**唯独没覆盖这条 catch 分支**。又是"防线没铺满"那个模式。

**修法**：`esc(e)`。

**回归测试**：加进现有的 `面板表格必须转义单元格` ——
正向断言 `esc(e)` 存在 + **反向断言**不得残留裸 `'+e+'`。

---

## 三、三条修复的退回验证（3/3 有效）

| # | 修复 | 退回方式 | 结果 |
|---|---|---|---|
| C-1 | kick 审计 | 整条 `.record(...)` 语句删除 | ✅ 测试变红 |
| C-2 | `forget_session` | 整行删除 | ✅ 测试变红 |
| C-3 | `esc(e)` | 还原成裸 `e` | ✅ 测试变红 |

★ ① 的退回方式返工了 **3 次**：
v1 按分号截断 ⇒ 花括号失配；
v2 按括号配对删 `AuditEvent::new(...)` ⇒ `.record()` 少参数（E0061）；
v3 从 `registry.audit().record(` 起删到配对右括号 + 分号 ⇒ 语法合法。

★ ②③ 第一版退回时**仍是绿的** —— 因为它们**当时还没有测试**。
补了测试之后才真正被守住。这印证了一贯的标准：**没有守卫的修复不算修完**。

---

## 四、质量门

| 项 | 结果 |
|---|---|
| `cargo test --workspace`（串行） | ✅ **753 通过 0 失败**（v0.6.0 → 753，本版 +2 条测试） |
| `cargo fmt --all -- --check` | ✅ 干净 |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ **0 告警** |
| `cargo audit` | ✅ exit 0（184 crates） |
| 端到端冒烟 | ✅ **28 / 28** |
| 退回验证 | ✅ **3 / 3** |

---

## 五、改动清单

| 文件 | 改动 |
|---|---|
| `server/src/admin.rs` | `add_proxy` / `remove_proxy` / `kick` 补 `ADMIN_ACTION` 审计；新增 `kick_必须写审计` 测试 |
| `server/src/registry.rs` | `ClientGuard::drop` 调 `forget_session`；新增 `控制连接退出必须清掉_oidc_subject_绑定` 测试 |
| `server/src/dashboard.rs` | catch 分支 `esc(e)`；既有转义测试补正/反向断言 |
| `common/src/auth/oidc.rs` | 新增 `bind_subject_for_test()`（测试用后门，名字标明意图） |

**产品行为无变更**：只补了审计记录、会话清理与一处 HTML 转义。

---

## 六、兼容性

* 无配置文件变更
* 无协议变更
* 无行为变更（审计**未启用时**这些代码不产生任何输出）
* `frps -v` / `frpc -v` 仍输出裸 `0.71.0`
* 与官方 frpc 0.71.0 互通不变
* **直接替换二进制即可升级**
