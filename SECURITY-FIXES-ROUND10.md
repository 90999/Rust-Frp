# NFrp 安全审计报告 · 第十轮（SECURITY-FIXES-ROUND10.md）

本文件是第十轮审计的完整记录，含两部分：

- **第一部分** · v0.5.10 发布复扫报告（2026-10-17）—— v0.5.10 发布正文引用的那一份（内容未改）；
- **第二部分** · 新维度深挖审计（2026-10-18 起）：Miri / ASan / TSan /
  cargo-vet + cargo-deny / PSF 状态机 / Phaedra 字段 fuzz / OIDC 核查。
  **2026-10-25 状态**：已完成部分见本文件；官方 0.71 兼容、NatHole、SSH 网关、
  pprof、HTTP 插件等收尾见 [SECURITY-FIXES-ROUND16.md](SECURITY-FIXES-ROUND16.md)。
  仍未完成的 TSan / Linux TUN Miri / 真实 IdP e2e 等也在 ROUND16 末尾列明，
  不要把它们误读成“已通过”。

---

# 第一部分 · NFrp v0.5.10 安全复扫报告（2026-10-17）

日期 2026-10-17
来源 第十轮安全审计 —— 对 **v0.5.9 正式发布产物**做全量复扫（第四~九轮全部电池逐项重跑 + 质量门）
结果 **0 条新增产品漏洞**；修复 **8 个点位**的审计探针/编排器自身缺陷（修复后全部重跑变绿）
另有 12 变体体积实验与性能基准 —— 所有**有行为代价**的体积优化经裁定不采用；性能采用行为中性 `TCP_NODELAY`

---

## 〇、一句话概括

本轮任务书是对已发布的 v0.5.9 二进制做全量复扫。约 100 项电池逐项重跑、质量门全绿：
**没有打出任何新的产品漏洞**。过程中变红的 8 个点位（r6-web-b0、webauth/e1、healthssrf/e8、
rebind/c03、r6-e2e、r5-h1、r5-h3）全部分诊为**探针自身的问题**（误杀规则、判据校准、
锚点过期、编排器缺口），逐条修复后重跑全绿 —— 这些修复让以后每一轮电池的证据链更可信。

---

## 一、复扫范围与方法

- 复扫对象 = `<构建目录>\release`（与 v0.5.9 发布包逐字节一致，已另存快照防覆盖）。
- 电池分两批：主批约 100 项逐项分诊复跑 + 收尾批 40 项覆盖点验。
- 方法学：动态端口、逐项独立日志留档、只清自己的进程（精确到 PID/名）、
  失败项一律"修复 + 重跑"不豁免、Python 侧统一 UTF-8。
- 质量门：`build` / `fmt --check` / `clippy -D warnings` / `test --workspace` / `audit`（见第四节）。

## 二、探针/编排器缺陷与修复（8 个点位）

1. **`cleanup_mine.py` 宽泛子串误杀**（r6-web-b0 假红）：清理规则按命令行子串匹配，
   连同主脚本一起杀掉；根因还叠加 Windows workbuddy venv 的 `python.exe` 是
   redirector（`getppid()` 不指向直接调用者，按父进程跳过无效）。
   修：规则收窄为 `nfrp-client` / `nfrp-server` / `fake_frps.py` 三个精确目标。
2. **e1 CSRF 判据拆两组**（webauth）：「缺头 / 头名不等价」必须 403；
   「值任意 / 头名大小写等价」不得按 403 处理（与第九轮排除 #2 的"只判存在性"结论对齐）。
3. **e1 Basic 认证判据**（webauth）：RFC 7235 允许的 scheme 大小写 / 多空格形式放行（200）；
   缺头 / 空密码 / 错密码一律 401（与第九轮排除 #9 的 `constant_time_eq` 语义对齐）。
4. **e8 独立哨兵**（healthssrf）：改用专用哨兵串 `RPROBE` + C 段
   "E-1 拒绝语义"断言（对 `localhost:` / 内网地址下发断言拒绝），消除锚点词误判。
5. **c03 判据翻转**（rebind）：J4/J5 按修复后语义翻转为正向断言；
   新增 J6 会话键格式判据（`-[0-9a-f]{8,}$`）覆盖第九轮 D9 修复。
6. **r6-e2e 编排器重写**：电池原指向半成品辅助脚本（裸跑必然 `IndexError`）。
   新编排器完成**真正的 KCP 端到端**：服务端开 `kcp_bind_port`、客户端
   `[transport] protocol="kcp"`、代理 → 回显后端，判据 6/6
   （KCP 链路建立 → 登录成功 → 代理注册成功 → 经 remotePort 的 1020B 原样回显）。
   ★ 附带纠正一条**工具层面的假基线**：历轮 KCP 测试里"客户端连上"实际只建立了
   本地套接字（拨号指向 TCP 口、未完成登录）——**产品行为正确**，属测试编排问题；
   本编排器是第一份真正完成 KCP 登录的端到端证据。
7. **r5-h1 / r5-h3 元验证锚点过期**：两个"退掉修复 ⇒ 测试必须变红"脚本的锚点
   与 v0.5.6 重构后的源码文本不一致（**保护本身都在**：`dashboard_exposed_after_reload`
   仍取运行期 `live_view`；`store.rs` 两处 `validate_remote_proxy` 仍拦）。
   修：锚点更新为当前文本；并补上**严格退出码** —— 此前两脚本即使"没抓到缺陷"
   也恒返回 0（静默假绿），现在未抓到缺陷即非零退出。
   （重跑证据：h1 退掉后 2 条测试红、h3 退掉后 3 条测试红，源码随后按字节还原。）

## 三、复扫结论

- **无新增产品漏洞**；v0.5.9 的 9 条修复 + 1 条加固在复扫中全部保持生效。
- 唯一实质性"发现"在工具链层面（KCP 假基线），已在第二节第 6 条记录。

## 四、质量门（发布时最终数字）

| 项 | 结果 |
|---|---|
| `cargo test --workspace` | ✅ **732 通过 0 失败**（7 个 target；与 v0.5.9 相同 —— 本版未新增/修改测试） |
| `cargo fmt --all -- --check` | ✅ 干净 |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ **0 告警** |
| `cargo audit` | ✅ exit 0 |
| 全量复扫电池 | ✅ 约 100 项全绿（含本报告修复后的 8 个点位重跑） |
| 元验证（退回 + 还原） | ✅ h1 抓到 2 红 / h3 抓到 3 红，均按字节还原 |

## 五、体积与性能（实验记录）

- **体积**：12 变体实验（源码副本，绝不触碰本体）。最大无损候选 combo2
  （clapmin + envstub2）= **−8.62% / −8.41%**；因**有行为代价**
  （日志"模块定向语法"失效 / CLI 无颜色与拼写建议）经裁定**全部不采用**。
  其它：lld −0.12%、webpki1 ±0、noeh/lld_noeh 在 Windows 编不出、
  hot3/hotc 反而 **+8~10%**、buf512 ±0。
- **性能**：hot3 / hotc / buf512 在交错复测下无稳定收益（机器背景负载 ~35%，噪声 ±20%）⇒ 不采用。
  唯一采用：数据面 accept 入口补 `TCP_NODELAY`（行为中性，与 vhost / vnet 口径一致）。
- ⇒ **0.5.10 二进制尺寸与 v0.5.9 完全相同**（3,439,104 / 3,494,400 B）。

## 六、兼容性

- 无配置文件变更、无行为变更（除 TCP 套接字选项）。
- `frps -v` / `frpc -v` 仍输出裸 `0.71.0`；与官方 frpc 0.71.0 互通不变。

---

# 第二部分 · 新维度深挖审计（2026-10-18 起）

> 覆盖前九轮未覆盖的面：**Miri / ASan / TSan / cargo-vet + cargo-deny / PSF 状态机 /
> Phaedra 字段 fuzz / OIDC 核查**。纪律：生产代码默认只读，只有可复现证据才允许最小补丁
> （含"退掉补丁 ⇒ 测试变红"元验证）；逐 Stage 落盘；未执行项如实记录原因。

## Stage 0 · 环境、基线质量门与靶点清单

### 0.1 审计对象与身份链

- 源码 = `<工作区>\nfrp`（0.5.10）。与 v0.5.10 源码快照 `tmp\nfrp-src-0510.tar.gz`
  逐文件 SHA256 比对：**101 相同 / 0 内容不同 / 0 仅快照有 / 8 仅本体有（全部 `dist\*` 发布产物）**
  ⇒ 当前源码与发布快照逐字节一致（证据：`tmp\audit-r10\diff_snap.py`）。
- 发布件链（发布日已逐字节核验）：`release\nfrp-server.exe`（`BF9C7D99DA7DF82B…`）、
  `release\nfrp-client.exe`（`1126777622078928…`）= dist zip 内容 = GitHub 发布资产。
  尺寸 3,439,104 / 3,494,400 B。今日复核：该批 release 产物未被触碰（mtime 仍 2026-10-17 23:01）。

### 0.2 环境

| 项 | 值 |
|---|---|
| OS | Windows 11 10.0.26200，12 逻辑核 |
| rustc / cargo | 1.98.1（x86_64-pc-windows-msvc，default；另装 gnu） |
| 已装 target | linux-gnu / linux-musl / aarch64-linux-musl / android ×2 / windows-gnu |
| Python | 3.13.15 |
| CARGO_HOME / CARGO_TARGET_DIR | `<CARGO_HOME>` / `<构建目录>` |

日志：`tmp\audit-r10\gates\environment.txt`。

### 0.3 基线质量门（当前源码全量重建后 —— 全绿）

| 门 | 命令 | rc |
|---|---|---|
| build | `cargo build --release -p nfrp-server -p nfrp-client` | 0 |
| fmt | `cargo fmt --all --check` | 0 |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | 0（0 告警） |
| test | `cargo test --workspace` | 0 —— **732 通过 / 0 失败**（7 个 target，与发布时一致） |
| audit | `cargo audit` | 0 |

日志目录：`tmp\audit-r10\gates\`。

### 0.4 ⚠ 环境事件：共享 target 目录里其他 Agent 的陈旧产物（假红，已排除）

- 首跑 `cargo test` rc=101：3 个 client `store` 安全测试红
  （`merge_initial_也要挡住危险条目` / `store_里四种本机资源字段都要拦` /
  `store_里的危险字段必须在恢复时被拦下`），且 cargo 认为"无需重编"。
- 定位证据：该测试二进制 `debug\deps\nfrp_client-e51a…exe` mtime = **2026-10-17 23:37**
  （另一 Agent 时段）；panic 行号 496/538/585 对当前源码 516/558/603（差 20/20/18 行）；
  server 侧 replay 出 `live_view` never used 伪警（当前源码 `reload.rs:309` 正在使用它）
  ⇒ **二进制来自另一棵源码树**，与当前源码无关。
- 处置：备份该产物与哈希（`tmp\audit-r10\backup-20261018\`）→ `cargo clean -p`（dev 档）
  → 当前源码全量重建 → 732/0 全绿，3 个原红测试全部 ok、伪警消失
  （测试二进制 mtime 更新为 2026-10-18 11:02）。
- 结论：**产品源码基线干净**。运维注：共享 `CARGO_TARGET_DIR` 的多人/多 Agent 场景，
  跑门前先 `cargo clean -p`。

### 0.5 靶点清单（后续 Stage 的目标面）

- **unsafe**：命中 10 行，其中 9 处真实 `unsafe` 全部在 `common\src\vnet\tun_linux.rs`
  （close/open/ioctl ×5、read/write ×2、fcntl ×2；非 Linux 编译不到），
  另 1 行为 `client\src\store.rs` 注释提及。⇒ Miri 的 unsafe 可达面小。
- **并发原语**（`tmp\audit-r10\inventory.out.txt`，35 个文件）：spawn 93 / Mutex 69 / mpsc 48 /
  Atomic 43 / RwLock 36 / OnceLock 15 / watch 14 / Semaphore 11 / static 7 / Notify 4。
  高密度点：`server\src\serve.rs`（spawn 16、Semaphore 6）、`client\src\plugin_bridge.rs`
  （spawn 10）、`server\src\registry.rs`（Mutex 14）、`server\src\reload.rs`（RwLock 15）、
  `server\src\pool.rs`（Mutex 5 + Notify 2）、`common\src\frp\mux.rs`、`common\src\frp\kcp.rs`。
- **既有缺口（沿基线口径）**：OIDC 无 e2e；官方抓包向量不可复现。

### 0.6 Stage 计划与状态

| Stage | 内容 | 状态 |
|---|---|---|
| 1 | Miri（nightly；可编译测试子集；并发项 many-seeds） | **部分完成**：编译 362 测试；`frp_config` 38/38 + WS 纯函数 1/1 通过；tokio/mio Windows IOCP 不可执行；Linux TUN 未覆盖（详见文末 Stage 1 节） |
| 2 | ASan / TSan（Windows MSVC 先试；TSan 走云端 Linux 或如实记未执行） | **部分完成**：ASan 下 `nfrp-common` 371/371、`nfrp-server` 238/238 通过；TSan 在 Windows MSVC 不可用，未执行 |
| 3 | cargo-vet + cargo-deny（供应链） | **部分完成**：`cargo deny check` 四项全绿；`cargo audit` 修复 3 条通告后清零；`cargo vet` 仅初始化 184 条 exemption，**不等于已审计** |
| 4 | PSF 状态机（不可得则降级手工状态探针） | **降级完成**：新增真实 e2e 乱序消息探针，服务端不崩且后续合法注册成功 |
| 5 | Phaedra 字段 fuzz（不可得则降级定向变异） | **降级完成**：1200 次确定性 TOML 变异，解析器未 panic |
| 6 | OIDC 核查（代码路径实测） | **部分完成**：27 个 OIDC 单测全过（JWT/JWKS/claims/subject 绑定）；无真实 IdP 端到端 |

（本报告为**进行中**状态，后续 Stage 逐段补充。）

---

## 附记 · 发布通道维护（2026-10-18，非审计 Stage）

- **源码同步**：GitHub `main` 由 `26a7cea`（0.5.9 源码）推进到 `c72d61d` —— 提交
  `sync v0.5.10 source (TCP_NODELAY + version bump)`，5 文件（Cargo.toml / Cargo.lock / README.md /
  server/src/serve.rs / SECURITY-FIXES-ROUND10.md）。其中 ROUND10.md 采用**发布日快照版**
  （`080D93855C3B661E…`），使该提交树与 v0.5.10 源码快照逐字节一致；本地续写版（本文件当前内容）
  待本轮结束后再推送。tag `v0.5.10` 强移至 `c72d61d`（原先误指 0.5.9 源码）；tag `v0.5.9` 不动。
  推送后独立核验 7/7 通过（`tmp\audit-r10\ghsync\verify_sync_0510.py`）。
- **发布正文占位符回填**：Release v0.5.10 正文与 `dist\RELEASE_v0.5.10.md` 中残留的
  `BENCH_LINE_PLACEHOLDER` 已补为终版同机对照实测：中位吞吐 **453（0.5.9）vs 482（0.5.10）MB/s**、
  16B 往返 p50 均 0.13~0.22 ms（交错 4 轮 × 4 迭代；原始数据 `tmp\audit10\bench-final-*.json`、
  统计脚本 `tmp\audit-r10\ghsync\bench_stats.py`）——差异处于本机噪声带（±20~40%）内，**无可靠差异**。
  GitHub 正文 PATCH 后与本地文件逐字节一致（2689 字符）。
- **发布后全量复核**（c 版脚本，抗网络抖动）：7 个资产全部重新下载成功；SHA256 与
  `SHA256SUMS.txt` 一致；与本地原件逐字节一致；Ed25519 验签双路通过（release.py rc=0；OpenSSL
  「Signature Verified Successfully」；公钥指纹 `763896b5d759c6cbe1f208c3c35c9f71`）。
- **CI 现状（既有，非本次引入）**：GitHub Actions 自引入（2026-09-25）至今共 239 个 run，
  仅 1 次全绿（9/25 `b68f48c`，当日修 musl 后）；10 月起全部失败，形状稳定 ——
  `unit tests (ubuntu/macOS)` 与 `fmt / clippy` 红，**Windows 单测 / e2e 冒烟 / 两条 musl 交叉编译绿**。
  本机质量门（fmt / clippy 0 告警 / 732 通过）不受影响；Linux/macOS 单测通道与 clippy 通道
  当前不可用，记为**待专项**。

---

# 第二部分 · Stage 1「Miri」实跑记录（2026-10-24）

> 本节只记录**实际执行**的内容与硬限制；没有跑到的部分明确写“未执行”，不把
> “Miri 能编译”当成“内存安全已证明”。

## 1.1 环境

| 项 | 值 |
|---|---|
| 主机 | Windows 11 10.0.26200（本地） |
| rustc | `1.101.0-nightly (8006091eb 2026-10-17)` |
| cargo-miri | `miri 0.1.0 (8006091eb7 2026-10-17)` |
| target | `x86_64-pc-windows-msvc`（nightly 仅装此 target） |
| Miri flags | `-Zmiri-disable-isolation -Zmiri-strict-provenance` |
| CARGO_TARGET_DIR | `D:\cargo-target-miri`（与正常构建隔离） |

## 1.2 编译门

命令：

```text
cargo +nightly miri test -p nfrp-common --lib --no-run
```

结果：**成功**。`nfrp-common` 及其依赖（tokio、rustls、ring 相关构建脚本等）在
Miri sysroot 下编译通过；证据 `tmp\miri_common_compile.txt`。
测试清单共 **362** 个（`tmp\miri_common_list.txt`，`-- --list`）。

## 1.3 已实际跑通的子集

### A. 配置解析/兼容层（38/38 通过）

```text
cargo +nightly miri test -p nfrp-common --lib frp_config:: -- --test-threads=1
```

结果：

```text
running 38 tests
...
test result: ok. 38 passed; 0 failed; 0 ignored; 0 measured;
324 filtered out; finished in 423.70s
```

证据：`tmp\miri_frp_config.txt`。

覆盖点包括：TOML/INI 的未实现字段识别与大小写折叠、`auth`/`transport` 子表、
`visitors`、`allow_ports`、`subdomain_host`、`healthcheck.httpHeaders`、
`metadatas`、示例配置加载、字段优先级等。**未发现 Miri UB/越界/未初始化读。**

### B. WebSocket 纯函数（1/1 通过）

```text
cargo +nightly miri test -p nfrp-common --lib ws::tests::accept_key_matches_rfc_vector -- --test-threads=1
```

结果：`1 passed; 0 failed; ... finished in 0.46s`；证据 `tmp\miri_ws_one.txt`。

## 1.4 未能执行的子集（硬限制）

对 `ws::` 整个模块执行时，第 2 个测试
`ws::tests::binary_payload_survives_including_invalid_utf8` 在 Miri 下直接报：

```text
error: unsupported operation: can't call foreign function `CreateIoCompletionPort`
on OS `windows`
  --> mio-1.2.3/src/sys/windows/iocp.rs:57:28
```

根因：该测试用 `#[tokio::test]`，tokio 的 Windows IO driver 初始化 `mio` 的
IOCP；Miri 不支持这个 Windows FFI。**不是 nfrp 的 UB**，是 Miri/Windows 运行时限制。
证据：`tmp\miri_ws.txt`（16 个 ws 测试，第 1 个通过后中止）。

尝试补 `x86_64-unknown-linux-gnu` nightly target（让 mio 走 epoll）时，
`rustup +nightly target add` 在 300 秒内未完成，target 仍未安装；为避免把
网络等待写成“已执行”，本节不声称 Linux target 已跑。

另外：本仓库唯一的真实 `unsafe`（TUN 设备）在 `#[cfg(target_os = "linux")]`
下编译，Windows 的 Miri 根本不会实例化它；因此 **Stage 1 没有覆盖 Linux TUN 的
unsafe 路径**。要完整覆盖，需在 Linux 主机装 nightly + miri + rust-src 后重跑
（云端旧机内存/时间未在本轮尝试）。

## 1.5 Stage 1 结论

- 可编译性：**通过**（362 个测试的 Miri 构建）。
- 纯 Rust 配置解析子集：**38/38 通过**，无 Miri 报错。
- WebSocket 纯函数：**1/1 通过**。
- tokio/mio 网络测试：**Windows Miri 不可执行**（IOCP FFI），未用“跳过”伪装成全绿。
- Linux TUN unsafe：**未覆盖**。
- 因此 Stage 1 状态记为 **部分完成（partial）**，不能写成“Miri 全量通过”。

后续补齐命令（Linux）：

```bash
rustup toolchain install nightly --component miri rust-src
rustup +nightly target add x86_64-unknown-linux-gnu
MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance" \
  cargo +nightly miri test -p nfrp-common --lib -- --test-threads=1
```

（在 Linux 上还要单独对 `common/src/vnet/tun_linux.rs` 的 unsafe 路径做定向测试。）

---

# 第三部分 · Stage 2–6 实跑记录（2026-10-24，OpenCode）

> 本节只写**实际执行**的命令与结果；不可用的工具/平台明确写“未执行”，
> 不把“能编译”“初始化了配置文件”当成“已证明安全”。

## 2.1 Stage 2：ASan / TSan

### ASan（实际通过）

环境：Windows 11，`rustc 1.101.0-nightly`，target `x86_64-pc-windows-msvc`，
`rust-src` 已安装，`RUSTFLAGS=-Zsanitizer=address`，`-Zbuild-std`。

```text
cargo +nightly test -p nfrp-common --lib -Zbuild-std \
  --target x86_64-pc-windows-msvc -- --test-threads=1
# test result: ok. 371 passed; 0 failed; ... finished in 17.15s

cargo +nightly test -p nfrp-server -p nfrp-client --lib -Zbuild-std \
  --target x86_64-pc-windows-msvc -- --test-threads=1
# test result: ok. 238 passed; 0 failed; ... finished in 14.43s
```

另外对 `frp_config::` 38 个测试单独跑过 ASan，全部通过。
没有出现 `ERROR: AddressSanitizer` / `SUMMARY: AddressSanitizer`。
证据：`tmp\asan_common_final2.txt`、`tmp\asan_server_client.txt`、`tmp\asan_common_frp_config.txt`。

### TSan（未执行）

Windows MSVC 的 Rust TSan 不受支持；本轮没有 Linux 构建机可用，
因此**没有**运行 TSan，也没有用 ASan 的结果替代 TSan 结论。
遗留并发风险仍需 Linux + nightly TSan 定向跑 `server\src\serve.rs`、
`server\src\pool.rs`、`common\src\frp\mux.rs`。

## 2.2 Stage 3：供应链

### 实际发现并修复（有通告 ID）

`cargo audit` 首次运行命中：

| 组件 | 版本 | 通告 | 处理 |
|---|---|---|---|
| `rustls-webpki` | 0.103.15 | RUSTSEC-2026-0382（证书链可能接受不受信中间 CA） | 升到 0.103.16 |
| `webpki-roots` | 1.0.9 | RUSTSEC-2026-0381（内置根含不受信 emSign 中间 CA） | 升到 1.0.10 |
| `tokio` | 1.53.1 | RUSTSEC-2026-0386（`AsyncFd` I/O safety，unsound） | 升到 1.54.1 |

升级后 `cargo audit` 输出为空（0 vulnerabilities / 0 warnings）。
证据：`tmp\cargo_audit.txt`（修复前）、`tmp\cargo_audit_final.txt`（修复后）。

### cargo-deny

新增 `nfrp\deny.toml`（许可证白名单、禁用 wildcard、未知 registry/git 源、
RustSec advisory 数据库）。最终：

```text
advisories ok, bans ok, licenses ok, sources ok
```

证据：`tmp\cargo_deny_final.txt`。许可证为常见宽松/弱 copyleft 组合，
`webpki-roots` 的 `CDLA-Permissive-2.0` 已显式列入。

### cargo-vet（仅基线，不是审计）

`cargo vet init` 生成 `nfrp\supply-chain\{config.toml,audits.toml,imports.lock}`，
`cargo vet` 输出：

```text
Vetting Succeeded (184 exempted)
```

**184 条全部是 exemption，不是人工审计结论。** 这一步只证明工具链能跑、
依赖树能锁定；后续要么补真实 audit，要么引入可信 imports 后删除 exemption。
证据：`tmp\cargo_vet.txt`、`tmp\cargo_vet_final.txt`。

## 2.3 Stage 4：PSF 降级（手工状态探针）

PSF 工具本轮不可得，降级为真实服务端 e2e 探针：
登录后把 `NewWorkConn` / `NewVisitorConn` 误发到**控制连接**，随后做一次
合法 `NewProxy` 注册。结果：服务端不崩、不断线，合法注册成功。

```text
cargo test -p nfrp-server --test e2e \
  out_of_state_messages_do_not_kill_control_session -- --nocapture
# 1 passed
```

证据：`tmp\stage4_state_test.txt`；代码在 `server\tests\e2e.rs`。

**未覆盖**：完整状态机枚举（登录前/后、代理注册中、关闭中、心跳超时交叉）、
并发多连接状态竞争；这些仍需 PSF 或自建状态模型。

## 2.4 Stage 5：Phaedra 降级（定向变异）

Phaedra 不可得，降级为确定性 TOML 定向变异：3 个种子 × 400 次
（替换/删除/插入），共 1200 次，分别喂给客户端和服务端解析器；
`Ok`/`Err` 都接受，**panic 即失败**。

```text
cargo test -p nfrp-common --lib \
  frp_config::tests::定向变异配置不应_panic
# 1 passed
```

证据：`tmp\fuzz_mutation_test.txt`；代码在 `common\src\frp_config.rs`。
这不是覆盖率 fuzz，没有发现新漏洞；只证明这 1200 个变异没有把解析器带崩。

## 2.5 Stage 6：OIDC 核查

实际执行：

```text
cargo test -p nfrp-common --lib auth::oidc:: -- --test-threads=1
# test result: ok. 27 passed; 0 failed
```

覆盖：JWT 分段解析、base64url、`exp`/`nbf`/`iss`/`aud`、`alg=none` 拒绝、
RSA/ES256/ES384 验签、JWKS key 解析、`skip` 语义、subject 与会话 `run_id` 绑定。

**未覆盖**：真实 IdP 的 discovery + JWKS 拉取 e2e、密钥轮换、网络错误/超时、
恶意 JWKS（超大 key、重复 kid、非预期 alg）。代码路径只做了单元级验证。

## 2.6 Stage 2–6 结论

- 真实执行：ASan、cargo-deny、cargo-audit、cargo-vet（基线）、e2e 状态探针、
  定向变异、OIDC 单测。
- 明确未执行：TSan、完整 PSF、Phaedra、真实 IdP e2e、Linux TUN Miri。
- 真实修复：3 条 RustSec 依赖通告；没有把它们写成“0day 已修”。
- 新增质量门：`deny.toml`、ASan 可重复命令、1200 次变异测试、乱序状态 e2e。

---

# 第四部分 · README 限制①批次3：TLS 证书组（2026-10-24）

实现范围：官方 0.71 的 `[transport.tls]` 证书组。

- 服务端：`certFile` / `keyFile` 自定义证书；`trustedCaFile` 启用 mTLS。
- 客户端：`certFile` / `keyFile` 在 TLS 握手时出示客户端证书。
- 三者为空时保持官方默认（自签名、不校验客户端）。
- 只配 cert 或只配 key：启动与 `--check` 都明确报错，不静默退回自签名。

关键代码：

| 文件 | 内容 |
|---|---|
| `common\src\config.rs` | 5 个字段 + 默认值 |
| `common\src\frp_config.rs` | `[transport.tls]` hoist；从 unsupported 清单移除；`webServer.tls.*` 按路径补扫，避免同名误洗白 |
| `common\src\frp\tls.rs` | PEM helper、`server_config_from_pem_with_ca`、`configure_server_tls`、`validate_server_tls_files`、客户端身份、`ClientTlsOptions` |
| `client\src\main.rs` | 传入客户端证书/私钥 |
| `server\src\serve.rs` | accept 前安装证书；预检校验 |
| `common\src\config.rs` 测试 | 官方段写法的解析断言 |

验证：

```text
cargo test -p nfrp-common --lib
# 371 passed（新增 TLS 配置/装载/半配置报错/变异测试）

cargo test --workspace -j 2 -- --test-threads=1
# 123 + 371 + 238 + 17 + 25 + 2 passed；0 failed；5 ignored

cargo clippy --workspace --all-targets
# 0 warning
```

证据：`tmp\test_final5.txt`、`tmp\clippy_final5.txt`、`tmp\webserver_tls_test.txt`。

mTLS 已做内存双端真实握手：合法客户端证书通过；不带证书拒绝；错误 CA 签发拒绝。
证据：`tmp\mtls_handshake_test2.txt`。同一份 TLS 配置重复安装是幂等的；换另一组文件
会明确报错（`configure_tls_is_idempotent_for_same_files`）。

仍未实现：`webServer.tls.*`（面板 HTTPS）、Windows VirtualNet、官方 xtcp NatHole，
以及 README 限制③列出的其余字段。




