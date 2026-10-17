//! yamux 多路复用，对应 frp 的 `transport.tcpMux`。
//!
//! 层次：`TCP -> [TLS] -> yamux 会话 -> 每条 stream 上跑一次 frp v2 握手`。
//! 控制连接与所有工作连接复用同一条 TCP，每条连接占一个 yamux stream。
//!
//! 实现要点：rust-yamux 的 `Connection` 必须由外部持续 poll 来驱动，
//! 子流 `Stream` 只是从共享缓冲里取数据。因此这里把 `Connection` 放进后台任务。

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use futures::future::poll_fn;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config, Connection, Mode};

use super::stream::BoxStream;

/// 开流请求的应答通道。
type OpenReq = oneshot::Sender<std::result::Result<yamux::Stream, yamux::ConnectionError>>;

fn mux_config() -> Config {
    // 默认 `split_send_size` 只有 16 KiB：单流打满时每 16 KiB 就要走一遍
    // "分配缓冲 + 加锁 + 写 frame 头 + 唤醒驱动任务"的流程，
    // 本机回环实测单流只有 ~530 Mbps（官方 frp 用 Go yamux 能到 ~2 Gbps）。
    // 提高到 128 KiB 后单流吞吐明显改善；多流场景本来就够快。
    let mut cfg = Config::default();
    cfg.set_split_send_size(128 * 1024);
    cfg
}

/// 服务端：接收对端打开的 yamux stream。
pub struct MuxAcceptor {
    rx: mpsc::Receiver<BoxStream>,
}

impl MuxAcceptor {
    /// 等待下一条 stream；会话关闭时返回 `None`。
    pub async fn accept(&mut self) -> Option<BoxStream> {
        self.rx.recv().await
    }
}

/// 会话健康检查的心跳。
const SESSION_TICK: Duration = Duration::from_secs(2);

/// **没有任何活跃流**的会话在此期限后被关闭（第九轮 C9-4/C9-3 修复）。
///
/// # 为什么需要
///
/// yamux 会话本身没有任何时间上界：crate 不设 keepalive，frp 侧原先也没设。
/// 攻击者只发一个 `0x00`（让服务端建立会话）后静默，或只开一条注定
/// 握手超时的流（12 字节），会话就能被**无限期**挂住 —— 第九轮实测量化：
/// ① 只发 0x00 的连接 50s 后仍存活，500 条可线性囤积（+515 句柄 / +6.4MB）；
/// ② 未认证开流 ≈9.5 KiB/条、单会话上限 512 条、跨会话无全局上限，
///    攻击者 129 KB 流量 + 22 个 fd 就能把服务端内存抬 +100 MB。
///
/// # 为什么 30s 是安全的
///
/// 合法 frpc 的 mux 会话里**控制流在客户端存活期间一直开着** ——
/// "活跃流为 0 持续 30s"只可能是：① 未认证占位；② 已经死掉的僵尸会话。
/// 两种都应该断开。（控制流出问题但 TCP 还在时，断会话会让客户端按既有
/// 重连逻辑重建整条连接，不会造成不可用。）
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// 会话活跃度：驱动器与交出去的流共享。
struct SessionState {
    /// 已交出且尚未 drop 的流数量。
    active: AtomicUsize,
    /// 最近一次交出流的时刻。
    last_open: Mutex<tokio::time::Instant>,
}

/// 包一层计数：被 drop 时告诉会话"这条流结束了"。
struct CountedStream<S> {
    inner: S,
    state: Arc<SessionState>,
}

impl<S: AsyncRead + Unpin> AsyncRead for CountedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> Drop for CountedStream<S> {
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 在已有流上建立 yamux 服务端会话。
pub fn serve(stream: BoxStream) -> MuxAcceptor {
    serve_with_timeouts(stream, SESSION_TICK, SESSION_IDLE_TIMEOUT)
}

/// [`serve`] 的实现本体；时限参数化是为了让测试能低成本验证看门狗逻辑
/// （生产调用永远走 `serve` 的常数）。
fn serve_with_timeouts(
    stream: BoxStream,
    idle_tick: Duration,
    idle_timeout: Duration,
) -> MuxAcceptor {
    // 通道容量 = "已创建但还没被 accept 走"的流的上限。yamux 驱动任务在
    // `send` 上被挂住后不会再从 TCP 读新帧（内核缓冲形成反压）——服务端
    // accept 循环在**未认证会话**上等预认证名额时正是停在这里。容量 64 时
    // 每条停滞会话仍会囤 64 条流对象（C9-3 复验实测）；压到 8 后，
    // "已创建但未认证"的流数量 ≈ 闸门上限 + 会话数 × ~9，与攻击流多少无关。
    // 正常会话 accept 是毫秒级，容量 8 对合法客户端无任何可感知影响。
    let (tx, rx) = mpsc::channel::<BoxStream>(8);
    let state = Arc::new(SessionState {
        active: AtomicUsize::new(0),
        last_open: Mutex::new(tokio::time::Instant::now()),
    });
    let mut conn = Connection::new(stream.compat(), mux_config(), Mode::Server);
    let share = state.clone();
    tokio::spawn(async move {
        loop {
            let tick = tokio::time::sleep(idle_tick);
            tokio::pin!(tick);
            let item = tokio::select! {
                item = poll_fn(|cx| conn.poll_next_inbound(cx)) => item,
                _ = &mut tick => {
                    let idle = share.active.load(Ordering::Relaxed) == 0;
                    let since = share
                        .last_open
                        .lock()
                        .map(|t| t.elapsed())
                        .unwrap_or_default();
                    if idle && since >= idle_timeout {
                        tracing::debug!(
                            "yamux 会话空闲超时（{:?} 内没有任何活跃流），断开",
                            idle_timeout
                        );
                        break;
                    }
                    continue;
                }
            };
            match item {
                Some(Ok(s)) => {
                    if let Ok(mut t) = share.last_open.lock() {
                        *t = tokio::time::Instant::now();
                    }
                    share.active.fetch_add(1, Ordering::Relaxed);
                    let counted = CountedStream {
                        inner: s.compat(),
                        state: share.clone(),
                    };
                    if tx.send(Box::pin(counted)).await.is_err() {
                        break;
                    }
                }
                Some(Err(e)) => {
                    tracing::debug!("yamux 会话错误：{e}");
                    break;
                }
                None => break,
            }
        }
    });
    MuxAcceptor { rx }
}

/// 客户端：在一条底层流上按需开新的 yamux stream。
///
/// 会话本身跑在后台任务里，通过 channel 请求开流。
#[derive(Clone)]
pub struct MuxSession {
    req_tx: mpsc::Sender<OpenReq>,
}

impl MuxSession {
    pub fn new(stream: BoxStream) -> Self {
        let (req_tx, req_rx) = mpsc::channel(64);
        let conn = Connection::new(stream.compat(), mux_config(), Mode::Client);
        tokio::spawn(drive_client(conn, req_rx));
        Self { req_tx }
    }

    /// 打开一条新的 stream（控制连接、工作连接都走这里）。
    pub async fn open_stream(&self) -> Result<BoxStream> {
        let (tx, rx) = oneshot::channel();
        self.req_tx
            .send(tx)
            .await
            .map_err(|_| anyhow!("yamux 会话已关闭，无法开流"))?;
        match rx.await.map_err(|_| anyhow!("yamux 会话已关闭"))? {
            Ok(s) => Ok(Box::pin(s.compat())),
            Err(e) => bail!("yamux 打开 stream 失败：{e}"),
        }
    }
}

/// 后台驱动任务：既要持续 poll 连接推进数据，又要响应开流请求。
///
/// 两者都要独占 `&mut Connection`，所以放在同一个 `poll_fn` 里顺序处理，
/// 用 `pending` 暂存"已经取出但还没就绪"的开流请求。
async fn drive_client<S>(mut conn: Connection<S>, mut req_rx: mpsc::Receiver<OpenReq>)
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    let mut pending: Option<OpenReq> = None;

    enum Ev {
        /// 收到入站 stream。frp 服务端不会主动向客户端开流，直接丢弃即可。
        Inbound,
        InboundErr(String),
        Outbound(
            OpenReq,
            std::result::Result<yamux::Stream, yamux::ConnectionError>,
        ),
        Closed,
    }

    loop {
        let ev = poll_fn(|cx| {
            // 1) 驱动会话，顺带取入站 stream（客户端模式下通常没有）
            match conn.poll_next_inbound(cx) {
                std::task::Poll::Ready(Some(Ok(_))) => return std::task::Poll::Ready(Ev::Inbound),
                std::task::Poll::Ready(Some(Err(e))) => {
                    return std::task::Poll::Ready(Ev::InboundErr(e.to_string()))
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ev::Closed),
                std::task::Poll::Pending => {}
            }

            // 2) 处理开流请求（每条分支都会返回，所以不需要循环）
            if pending.is_none() {
                match req_rx.poll_recv(cx) {
                    std::task::Poll::Ready(Some(tx)) => pending = Some(tx),
                    std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ev::Closed),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }
            let Some(tx) = pending.take() else {
                return std::task::Poll::Pending;
            };
            match conn.poll_new_outbound(cx) {
                std::task::Poll::Ready(r) => std::task::Poll::Ready(Ev::Outbound(tx, r)),
                std::task::Poll::Pending => {
                    pending = Some(tx);
                    std::task::Poll::Pending
                }
            }
        })
        .await;

        match ev {
            Ev::Inbound => {
                // frp 服务端不会主动向客户端开流，收到就丢弃
                tracing::debug!("yamux 收到意外的入站 stream，忽略");
            }
            Ev::InboundErr(e) => {
                tracing::debug!("yamux 会话结束：{e}");
                break;
            }
            Ev::Outbound(tx, r) => {
                let _ = tx.send(r);
            }
            Ev::Closed => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 空转会话（一条流都没有）应被看门狗关闭 —— C9-4 修复的回归锁。
    #[tokio::test]
    async fn 空转会话被空闲看门狗关闭() {
        let (srv, _cli) = tokio::io::duplex(4096);
        let mut acc = serve_with_timeouts(
            Box::pin(srv),
            Duration::from_millis(20),
            Duration::from_millis(200),
        );
        let got = acc.accept().await;
        assert!(got.is_none(), "没有任何流的会话必须被关闭");
    }

    /// 有活跃流时不得误杀；流结束后应由看门狗回收 —— C9-3 的残留路线。
    ///
    /// ★ 关键事实：rust-yamux 的 SYN 帧是**懒发送**的 —— 流对象创建后，
    /// 要等它第一次被 poll（读/写都算）才把 SYN 推给连接。所以这里必须
    /// 真的对 `held` 写一个字节，服务端才会"看见"这条流。
    /// （C9-3 的攻击探针手搓 SYN 帧，模拟的正是"有人强行把流塞过来"。）
    #[tokio::test]
    async fn 活跃流结束后会话被回收() {
        use tokio::io::AsyncWriteExt as _;

        let (srv, cli) = tokio::io::duplex(64 * 1024);
        let mut acc = serve_with_timeouts(
            Box::pin(srv),
            Duration::from_millis(20),
            Duration::from_millis(200),
        );
        let session = MuxSession::new(Box::pin(cli));
        let mut held = session.open_stream().await.expect("开流");
        held.write_all(b"x").await.expect("写出首字节（触发 SYN）");
        let got = acc.accept().await.expect("服务端应收到流");

        // 持有流 500ms：远超 200ms 空闲线，不得被误杀
        tokio::time::sleep(Duration::from_millis(500)).await;
        let r = tokio::time::timeout(Duration::from_millis(100), acc.accept()).await;
        assert!(r.is_err(), "有活跃流时会话被误杀");

        // 丢掉流 ⇒ 空闲超时后应被看门狗关闭（accept 返回 None）
        drop(got);
        let r2 = tokio::time::timeout(Duration::from_secs(2), acc.accept()).await;
        assert!(matches!(r2, Ok(None)), "流结束后的会话应被回收");
        drop(held);
    }
}
