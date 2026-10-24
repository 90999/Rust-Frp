//! 官方 frp ≥0.52 的 xtcp `NatHole` 控制器（服务端侧）。
//!
//! 这里不是 NFRp 自己那套“UDP HELLO + 服务端回 PEER”的牵线协议，而是
//! 官方 frpc 使用的控制连接消息流：
//!
//! ```text
//! visitor --NatHoleVisitor--> frps --NatHoleClient{sid}--> provider
//! visitor <--NatHoleResp----- frps <--NatHoleClient------ provider
//! ```
//!
//! 双方拿到 `NatHoleResp` 后，各自在本地 UDP socket 上按
//! `detect_behavior` 发/收探测包，真正的打洞数据不经过 frps。
//!
//! # 当前覆盖范围
//!
//! 先实现官方 `mode 0 / index 0`：双方都能直连或都是 EasyNAT 时，
//! provider（官方叫 client）做 sender，visitor 做 receiver，TTL 7。
//! 这对应 `pkg/nathole/analysis.go` 的 `mode0Behaviors[0]`。
//!
//! 尚未实现完整的 NAT 分类（`ClassifyNATFeature` / 历史成功率分析），
//! 因此 HardNAT、端口预测、mode 1~4 仍会走 mode 0；失败时官方客户端
//! 会自行回退到 stcp 中继，不会假装“打洞成功”。

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use nfrp_common::frp::msg::{
    FrpMessage, NatHoleClient, NatHoleDetectBehavior, NatHoleResp, NatHoleVisitor,
};
use tracing::{debug, info, warn};

use crate::{pool::ClientState, visitor::VisitorEntry};

/// 等 provider 回 `NatHoleClient` 的时间，对齐官方 `NatHoleTimeout`（10 秒）。
const WAIT_CLIENT: Duration = Duration::from_secs(10);

/// 最多同时保留多少条未配对会话。每条只存几个地址字符串，但仍要防
/// 已认证客户端无限建会话；超过就把新的挡回去，让它回退中继。
const MAX_SESSIONS: usize = 2048;

/// 官方 mode0 index0 的读超时：`max(send_delay) + 5000ms`。
const MODE0_READ_TIMEOUT_MS: i64 = 5_000;

struct Session {
    sid: String,
    proxy_name: String,
    visitor_client: Arc<ClientState>,
    provider_client: Arc<ClientState>,
    visitor_txn: String,
    visitor_protocol: String,
    visitor_mapped: Vec<String>,
    visitor_assisted: Vec<String>,
    created: Instant,
}

fn sessions() -> &'static Mutex<HashMap<String, Session>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, Session>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_sessions() -> std::sync::MutexGuard<'static, HashMap<String, Session>> {
    sessions().lock().unwrap_or_else(|e| e.into_inner())
}

/// visitor 的第一条消息只是 `pre_check`：官方 frpc 用它确认
/// “provider 在不在、我这个 user 能不能访问”，此时还没有 NAT 地址。
///
/// 成功后必须回 `error` 为空的响应；失败要回明确的错误，官方客户端
/// 才会按 `fallbackTo = "stcp"` 回退。
pub fn precheck(entry: &VisitorEntry, visitor_user: &str) -> Result<(), String> {
    if !entry.check_user(visitor_user) {
        return Err(format!(
            "xtcp visitor user [{}] not allowed for [{}]",
            visitor_user, entry.proxy_name
        ));
    }
    Ok(())
}

/// 收到带 `mapped_addrs` 的官方 `NatHoleVisitor` 后开一条会话。
///
/// 调用方（[`crate::p2p::handle_nat_hole_visitor`]）已完成 provider 存在性、
/// 签名、用户白名单校验；这里只负责配对和超时。
pub fn start_session(
    visitor_client: &Arc<ClientState>,
    entry: &Arc<VisitorEntry>,
    m: &NatHoleVisitor,
) -> Result<(), String> {
    if m.mapped_addrs.is_empty() {
        return Err("nat hole visitor has no mapped_addrs".to_string());
    }

    let sid = format!(
        "{}{}",
        nfrp_common::util::now_unix_secs(),
        nfrp_common::util::new_run_id()
    );
    let provider_client = entry.client.clone();
    let session = Session {
        sid: sid.clone(),
        proxy_name: entry.proxy_name.clone(),
        visitor_client: visitor_client.clone(),
        provider_client: provider_client.clone(),
        visitor_txn: m.transaction_id.clone(),
        visitor_protocol: m.protocol.clone(),
        visitor_mapped: m.mapped_addrs.clone(),
        visitor_assisted: m.assisted_addrs.clone(),
        created: Instant::now(),
    };

    {
        let mut g = lock_sessions();
        g.retain(|_, s| s.created.elapsed() < WAIT_CLIENT);
        if g.len() >= MAX_SESSIONS {
            return Err("too many pending nat hole sessions".to_string());
        }
        g.insert(sid.clone(), session);
    }

    // 通知 provider 去和 visitor 交换地址。官方 frpc 收到后会立即回一条
    // `NatHoleClient{sid, mapped_addrs, assisted_addrs}`。
    provider_client.forward_to_client(FrpMessage::NatHoleClient(NatHoleClient {
        transaction_id: m.transaction_id.clone(),
        proxy_name: entry.proxy_name.clone(),
        sid: sid.clone(),
        ..Default::default()
    }));

    // 不能在这里 await：本函数跑在 visitor 的控制连接循环里，阻塞会让
    // 后面 `forward_to_client` 投递的响应永远发不出去。用独立任务做超时，
    // 只把错误投递回同一个控制通道（循环恢复后会执行）。
    let sid_for_timeout = sid.clone();
    let txn = m.transaction_id.clone();
    tokio::spawn(async move {
        tokio::time::sleep(WAIT_CLIENT).await;
        let removed = lock_sessions().remove(&sid_for_timeout);
        if let Some(s) = removed {
            warn!(
                sid = %sid_for_timeout,
                proxy = %s.proxy_name,
                "等待 provider 的 NatHoleClient 超时"
            );
            s.visitor_client
                .forward_to_client(FrpMessage::NatHoleResp(NatHoleResp {
                    transaction_id: txn,
                    error: "wait for provider NatHoleClient timeout".to_string(),
                    ..Default::default()
                }));
        }
    });

    debug!(
        %sid, proxy = %entry.proxy_name, txn = %m.transaction_id,
        "已创建官方 NatHole 会话，等待 provider 回 NatHoleClient"
    );
    Ok(())
}

/// 处理 provider 回来的 `NatHoleClient`：配对成功后分别给双方回
/// `NatHoleResp`。返回 `true` 表示确实消费了一条已知会话。
pub fn handle_client(provider_client: &Arc<ClientState>, m: &NatHoleClient) -> bool {
    if m.sid.is_empty() {
        return false;
    }

    // 先确认 sid 存在且确实是这个 provider 的会话，再摘除；否则一个
    // 认证过的其他客户端只要猜到 sid 就能把别人的会话顶掉。
    let session = {
        let mut g = lock_sessions();
        match g.get(&m.sid) {
            Some(s) if Arc::ptr_eq(&s.provider_client, provider_client) => g.remove(&m.sid),
            _ => None,
        }
    };
    let Some(s) = session else {
        return false;
    };

    if s.proxy_name != m.proxy_name {
        warn!(
            sid = %m.sid,
            expected = %s.proxy_name,
            got = %m.proxy_name,
            "NatHoleClient 的代理名不匹配，丢弃"
        );
        send_error(
            &s.visitor_client,
            &s.visitor_txn,
            "NatHoleClient proxy_name mismatch",
        );
        return true;
    }

    if m.mapped_addrs.is_empty() {
        send_error(
            &s.visitor_client,
            &s.visitor_txn,
            "provider NatHoleClient has no mapped_addrs",
        );
        send_error(
            provider_client,
            &m.transaction_id,
            "provider NatHoleClient has no mapped_addrs",
        );
        return true;
    }

    let protocol = if s.visitor_protocol.is_empty() {
        // 官方 0.71 的 visitor 会带 `quic`；没带时按官方默认走 quic。
        "quic"
    } else {
        &s.visitor_protocol
    };

    // provider（官方叫 client）是 sender；visitor 是 receiver。
    let visitor_resp = build_response(
        &s.visitor_txn,
        &s.sid,
        protocol,
        &m.mapped_addrs,
        &m.assisted_addrs,
        NatHoleDetectBehavior {
            role: "receiver".to_string(),
            mode: 0,
            ttl: 7,
            read_timeout_ms: MODE0_READ_TIMEOUT_MS,
            ..Default::default()
        },
    );
    let provider_resp = build_response(
        &m.transaction_id,
        &s.sid,
        protocol,
        &s.visitor_mapped,
        &s.visitor_assisted,
        NatHoleDetectBehavior {
            role: "sender".to_string(),
            mode: 0,
            read_timeout_ms: MODE0_READ_TIMEOUT_MS,
            ..Default::default()
        },
    );

    info!(
        sid = %s.sid,
        proxy = %s.proxy_name,
        visitor_candidates = ?m.mapped_addrs,
        provider_candidates = ?s.visitor_mapped,
        "官方 NatHole 配对成功，已向双方下发候选地址"
    );
    s.visitor_client
        .forward_to_client(FrpMessage::NatHoleResp(visitor_resp));
    provider_client.forward_to_client(FrpMessage::NatHoleResp(provider_resp));
    true
}

fn build_response(
    transaction_id: &str,
    sid: &str,
    protocol: &str,
    candidate_addrs: &[String],
    assisted_addrs: &[String],
    detect_behavior: NatHoleDetectBehavior,
) -> NatHoleResp {
    NatHoleResp {
        transaction_id: transaction_id.to_string(),
        sid: sid.to_string(),
        protocol: protocol.to_string(),
        candidate_addrs: candidate_addrs.to_vec(),
        assisted_addrs: assisted_addrs.to_vec(),
        detect_behavior,
        ..Default::default()
    }
}

fn send_error(client: &ClientState, txn: &str, err: impl Into<String>) {
    client.forward_to_client(FrpMessage::NatHoleResp(NatHoleResp {
        transaction_id: txn.to_string(),
        error: err.into(),
        ..Default::default()
    }));
}

/// 清理会话表（测试与进程退出前用；正常超时由 spawn 的任务负责）。
#[cfg(test)]
pub(crate) fn clear_sessions() {
    lock_sessions().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pool::CtrlCmd, registry::ServerLimits};
    use nfrp_common::frp::WireVersion;
    use tokio::sync::mpsc;

    fn client(user: &str, ip: &str) -> (Arc<ClientState>, mpsc::UnboundedReceiver<CtrlCmd>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let (conn, backlog, proxy) = ServerLimits::default().per_client();
        let c = Arc::new(ClientState::new(
            "run".into(),
            "id".into(),
            user.to_string(),
            tx,
            Duration::from_secs(60),
            Duration::from_secs(10),
            Default::default(),
            false,
            WireVersion::V1,
            conn,
            backlog,
            0,
            proxy,
            ip.parse().unwrap(),
        ));
        (c, rx)
    }

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn take_nat_hole_resp(rx: &mut mpsc::UnboundedReceiver<CtrlCmd>) -> NatHoleResp {
        match rx.try_recv().expect("expected queued message") {
            CtrlCmd::Send(msg) => match *msg {
                FrpMessage::NatHoleResp(resp) => resp,
                other => panic!("unexpected message: {}", other.name()),
            },
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn precheck_uses_provider_user_and_allowlist() {
        let (provider, _prx) = client("provider", "5.6.7.8");
        let entry = VisitorEntry {
            proxy_name: "xtcp-test".into(),
            secret_key: "sk".into(),
            allow_users: vec![],
            provider_user: "provider".into(),
            client: provider,
            proxy_type: "xtcp".into(),
        };
        assert!(precheck(&entry, "provider").is_ok());
        assert!(precheck(&entry, "visitor").is_err());

        let entry2 = VisitorEntry {
            allow_users: vec!["*".into()],
            ..entry
        };
        assert!(precheck(&entry2, "visitor").is_ok());
        assert!(precheck(&entry2, "").is_err());
    }

    #[tokio::test]
    async fn mode0_swaps_candidate_addresses_and_roles() {
        let _guard = test_lock();
        clear_sessions();
        let (visitor, mut vrx) = client("visitor", "1.2.3.4");
        let (provider, mut prx) = client("provider", "5.6.7.8");
        let entry = Arc::new(VisitorEntry {
            proxy_name: "xtcp-test".into(),
            secret_key: "sk".into(),
            allow_users: vec![],
            provider_user: "provider".into(),
            client: provider.clone(),
            proxy_type: "xtcp".into(),
        });
        let m = NatHoleVisitor {
            transaction_id: "v-txn".into(),
            proxy_name: "xtcp-test".into(),
            protocol: "quic".into(),
            mapped_addrs: vec!["1.2.3.4:1000".into()],
            assisted_addrs: vec!["1.2.3.4:1001".into()],
            ..Default::default()
        };
        start_session(&visitor, &entry, &m).unwrap();

        let sid = {
            let g = lock_sessions();
            g.keys().next().cloned().unwrap()
        };
        // provider 先收到“去交换地址”的通知。
        match prx.try_recv().expect("provider notification") {
            CtrlCmd::Send(msg) => match *msg {
                FrpMessage::NatHoleClient(c) => {
                    assert_eq!(c.sid, sid);
                    assert_eq!(c.proxy_name, "xtcp-test");
                }
                other => panic!("unexpected provider message: {}", other.name()),
            },
            other => panic!("unexpected provider command: {:?}", other),
        }

        let cm = NatHoleClient {
            transaction_id: "c-txn".into(),
            proxy_name: "xtcp-test".into(),
            sid,
            mapped_addrs: vec!["5.6.7.8:2000".into()],
            assisted_addrs: vec!["5.6.7.8:2001".into()],
        };
        assert!(handle_client(&provider, &cm));

        let vresp = take_nat_hole_resp(&mut vrx);
        assert_eq!(vresp.transaction_id, "v-txn");
        assert_eq!(vresp.protocol, "quic");
        assert_eq!(vresp.candidate_addrs, vec!["5.6.7.8:2000"]);
        assert_eq!(vresp.assisted_addrs, vec!["5.6.7.8:2001"]);
        assert_eq!(vresp.detect_behavior.role, "receiver");
        assert_eq!(vresp.detect_behavior.mode, 0);
        assert_eq!(vresp.detect_behavior.ttl, 7);

        let presp = take_nat_hole_resp(&mut prx);
        assert_eq!(presp.transaction_id, "c-txn");
        assert_eq!(presp.candidate_addrs, vec!["1.2.3.4:1000"]);
        assert_eq!(presp.assisted_addrs, vec!["1.2.3.4:1001"]);
        assert_eq!(presp.detect_behavior.role, "sender");

        assert!(lock_sessions().is_empty());
    }

    #[tokio::test]
    async fn wrong_provider_cannot_steal_session() {
        let _guard = test_lock();
        clear_sessions();
        let (visitor, _vrx) = client("visitor", "1.2.3.4");
        let (provider, _prx) = client("provider", "5.6.7.8");
        let (attacker, _arx) = client("attacker", "9.9.9.9");
        let entry = Arc::new(VisitorEntry {
            proxy_name: "xtcp-test".into(),
            secret_key: "sk".into(),
            allow_users: vec![],
            provider_user: "provider".into(),
            client: provider,
            proxy_type: "xtcp".into(),
        });
        let m = NatHoleVisitor {
            transaction_id: "v-txn".into(),
            proxy_name: "xtcp-test".into(),
            mapped_addrs: vec!["1.2.3.4:1000".into()],
            ..Default::default()
        };
        start_session(&visitor, &entry, &m).unwrap();
        let sid = lock_sessions().keys().next().cloned().unwrap();
        let cm = NatHoleClient {
            transaction_id: "a-txn".into(),
            proxy_name: "xtcp-test".into(),
            sid: sid.clone(),
            mapped_addrs: vec!["9.9.9.9:3000".into()],
            ..Default::default()
        };
        assert!(!handle_client(&attacker, &cm));
        assert!(lock_sessions().contains_key(&sid));
    }
}
