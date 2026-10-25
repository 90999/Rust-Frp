//! 官方 frps 的 `[[httpPlugins]]` 兼容层。
//!
//! # 协议
//!
//! 对每个 `op`，向 `addr + path?version=0.1.0&op=...` 发一条 JSON POST：
//!
//! ```json
//! {"version":"0.1.0","op":"Login","content":{...}}
//! ```
//!
//! 插件返回：
//!
//! ```json
//! {"reject":false,"reject_reason":"","unchange":true,"content":null}
//! ```
//!
//! * `reject = true`：拒绝本次操作，`reject_reason` 原样回给客户端；
//! * `unchange = true`：忽略 `content`，保持服务端当前内容；
//! * `unchange = false` 且 `content` 非空：用插件返回的内容替换。
//!
//! 这里的请求 / 响应结构与官方 `pkg/plugin/server/types.go` 一致，
//! 因此现成的 frp 插件（用户管理、端口管理、认证等）不用改就能接。
//!
//! # 与官方的一处务实差异
//!
//! 官方用的是无超时的 `http.Client`。插件进程一旦卡住，frps 的登录 /
//! 心跳会**永久挂起**。这里给每次请求 10 秒上限：超时按"插件失败"处理，
//! 登录直接拒绝、心跳断开重连，至少不会把整个服务端拖死。

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, warn};

use crate::{config::HttpPluginConfig, httpc};

/// 官方插件 API 版本。
pub const API_VERSION: &str = "0.1.0";

pub const OP_LOGIN: &str = "Login";
pub const OP_NEW_PROXY: &str = "NewProxy";
pub const OP_CLOSE_PROXY: &str = "CloseProxy";
pub const OP_PING: &str = "Ping";
pub const OP_NEW_WORK_CONN: &str = "NewWorkConn";
pub const OP_NEW_USER_CONN: &str = "NewUserConn";

/// 单个插件的不可变运行时配置。
#[derive(Debug, Clone)]
struct Endpoint {
    name: String,
    url: String,
    ops: Vec<String>,
    opts: httpc::Options,
}

/// 一组 HTTP 插件。
#[derive(Debug, Default)]
pub struct PluginManager {
    endpoints: Vec<Endpoint>,
}

#[derive(Debug, Serialize)]
struct PluginRequest<'a> {
    version: &'a str,
    op: &'a str,
    content: Value,
}

#[derive(Debug, Deserialize, Default)]
struct PluginResponse {
    #[serde(default)]
    reject: bool,
    #[serde(default)]
    reject_reason: String,
    #[serde(default)]
    unchange: bool,
    #[serde(default)]
    content: Option<Value>,
}

impl PluginManager {
    /// 从配置构建。任何一项地址非法都直接失败 —— 启动时就暴露，
    /// 比运行到第一次登录才发现"插件根本连不上"要好。
    pub fn from_config(configs: &[HttpPluginConfig]) -> Result<Self> {
        let mut endpoints = Vec::with_capacity(configs.len());
        for cfg in configs {
            let addr = cfg.addr.trim();
            if addr.is_empty() {
                bail!("httpPlugins 的 addr 不能为空");
            }
            let base = if addr.contains("://") {
                addr.trim_end_matches('/').to_string()
            } else {
                format!("http://{}", addr.trim_end_matches('/'))
            };
            let path = cfg.path.trim();
            let path = if path.is_empty() {
                String::new()
            } else if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{path}")
            };
            endpoints.push(Endpoint {
                name: if cfg.name.trim().is_empty() {
                    base.clone()
                } else {
                    cfg.name.clone()
                },
                url: format!("{base}{path}"),
                ops: cfg.ops.clone(),
                opts: httpc::Options {
                    // 官方 `TLSVerify` 默认 false ⇒ InsecureSkipVerify = true。
                    insecure_skip_verify: !cfg.tls_verify,
                    timeout_secs: 10,
                    ..Default::default()
                },
            });
        }
        Ok(Self { endpoints })
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    fn supports(&self, ep: &Endpoint, op: &str) -> bool {
        ep.ops.iter().any(|o| o == op)
    }

    /// 可修改内容的 op：按配置顺序链式执行，后一个插件看到前一个的结果。
    ///
    /// 与官方 `handleMutableContent` 完全同构；`content` 必须是 JSON 对象
    /// （各 Content 结构都是对象）。
    pub async fn handle_mutable(&self, op: &str, content: Value) -> Result<Value> {
        let mut content = content;
        for ep in self.endpoints.iter().filter(|e| self.supports(e, op)) {
            match self.call(ep, op, content.clone()).await {
                Ok(res) => {
                    if res.reject {
                        let reason = if res.reject_reason.trim().is_empty() {
                            format!("{op} rejected by plugin {}", ep.name)
                        } else {
                            res.reject_reason
                        };
                        return Err(anyhow!("{reason}"));
                    }
                    if !res.unchange {
                        if let Some(new_content) = res.content {
                            content = new_content;
                        }
                    }
                }
                Err(e) => {
                    warn!(plugin = %ep.name, %op, "HTTP 插件调用失败：{e:#}");
                    return Err(anyhow!("send {op} request to plugin error: {e}"));
                }
            }
        }
        Ok(content)
    }

    /// 通知型 op（`CloseProxy`）：失败只记日志，不阻断关闭流程。
    pub async fn notify(&self, op: &str, content: Value) {
        for ep in self.endpoints.iter().filter(|e| self.supports(e, op)) {
            match self.call(ep, op, content.clone()).await {
                Ok(res) if res.reject => {
                    warn!(
                        plugin = %ep.name,
                        %op,
                        reason = %res.reject_reason,
                        "插件拒绝了通知型 op（按官方语义忽略）"
                    );
                }
                Ok(_) => {}
                Err(e) => warn!(plugin = %ep.name, %op, "HTTP 插件通知失败：{e:#}"),
            }
        }
    }

    async fn call(&self, ep: &Endpoint, op: &str, content: Value) -> Result<PluginResponse> {
        let sep = if ep.url.contains('?') { '&' } else { '?' };
        let url = format!("{}{sep}version={API_VERSION}&op={op}", ep.url);
        let reqid = format!("{:016x}", rand::random::<u64>());
        let headers = [("X-Frp-Reqid", reqid.as_str())];
        let body = PluginRequest {
            version: API_VERSION,
            op,
            content,
        };
        let resp = httpc::post_json(&url, &serde_json::to_value(&body)?, &headers, &ep.opts)
            .await
            .with_context(|| format!("POST {url}"))?;
        if !(200..300).contains(&resp.status) {
            bail!(
                "插件返回 HTTP {}：{}",
                resp.status,
                String::from_utf8_lossy(&resp.body[..resp.body.len().min(300)])
            );
        }
        let parsed: PluginResponse = serde_json::from_slice(&resp.body).with_context(|| {
            format!(
                "插件响应不是合法 JSON：{}",
                String::from_utf8_lossy(&resp.body[..resp.body.len().min(300)])
            )
        })?;
        debug!(plugin = %ep.name, %op, reject = parsed.reject, unchange = parsed.unchange, "HTTP 插件已响应");
        Ok(parsed)
    }
}

/// 给 `Login` 附加官方要求的 `client_address` 字段。
pub fn login_content(login: &crate::frp::msg::Login, client_address: &str) -> Result<Value> {
    let mut v = serde_json::to_value(login)?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| anyhow!("Login 序列化结果不是对象"))?;
    obj.insert(
        "client_address".into(),
        Value::String(client_address.to_string()),
    );
    Ok(v)
}

/// 把插件改写后的 Login 内容解析回来；`client_address` 会被 serde 忽略。
pub fn apply_login_content(login: &mut crate::frp::msg::Login, content: Value) -> Result<()> {
    *login = serde_json::from_value(content).context("插件返回的 Login 内容无法解析")?;
    Ok(())
}

/// 官方 `UserInfo`：**只含** user / metas / run_id。
///
/// 注意不要直接序列化整个 `Login` —— 那会把 `privilege_key`（token/OIDC
/// 凭据）送给插件。官方 `UserInfo` 没有凭据字段，这里保持一致。
pub fn user_info(login: &crate::frp::msg::Login, run_id: &str) -> Value {
    serde_json::json!({
        "user": login.user,
        "metas": login.metas,
        "run_id": run_id,
    })
}

/// 官方各 op 的外层 `content` 形状都是 `{..., "user": UserInfo}`。
pub fn content_with_user<T: Serialize>(value: &T, user: Value) -> Result<Value> {
    let mut v = serde_json::to_value(value)?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| anyhow!("内容序列化结果不是对象"))?;
    obj.insert("user".into(), user);
    Ok(v)
}

/// 给测试和调试用的短超时构造：不暴露 `Endpoint`。
#[cfg(test)]
fn test_endpoint(url: &str, ops: &[&str]) -> Endpoint {
    Endpoint {
        name: "test".into(),
        url: url.into(),
        ops: ops.iter().map(|s| s.to_string()).collect(),
        opts: httpc::Options {
            insecure_skip_verify: true,
            timeout_secs: 2,
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    const OK: &str = r#"{"reject":false,"reject_reason":"","unchange":true,"content":null}"#;

    /// 起一个只回固定 JSON 的 HTTP 服务，并返回收到的请求体。
    async fn one_shot_server(
        response: &'static str,
        hits: Arc<AtomicUsize>,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let mut all = Vec::new();
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                all.extend_from_slice(&buf[..n]);
                if all.windows(4).any(|w| w == b"\r\n\r\n") {
                    // 有 Content-Length 时继续读到完整体
                    let text = String::from_utf8_lossy(&all).to_string();
                    let want = text
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("Content-Length: ")
                                .or_else(|| l.strip_prefix("content-length: "))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if let Some(pos) = all.windows(4).position(|w| w == b"\r\n\r\n") {
                        if all.len() >= pos + 4 + want {
                            break;
                        }
                    }
                }
            }
            hits.fetch_add(1, Ordering::SeqCst);
            let body = response.as_bytes();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(resp.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            String::from_utf8_lossy(&all).to_string()
        });
        (format!("http://{addr}/handler"), handle)
    }

    #[tokio::test]
    async fn 未命中_op_的插件不会被调用() {
        let hits = Arc::new(AtomicUsize::new(0));
        let (url, server) = one_shot_server(OK, hits.clone()).await;
        let mgr = PluginManager {
            endpoints: vec![test_endpoint(&url, &[OP_NEW_PROXY])],
        };
        let out = mgr
            .handle_mutable(OP_LOGIN, serde_json::json!({"user":"a"}))
            .await
            .unwrap();
        assert_eq!(out["user"], "a");
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn 请求带官方版本_op_与_reqid() {
        let hits = Arc::new(AtomicUsize::new(0));
        let (url, server) = one_shot_server(OK, hits).await;
        let mgr = PluginManager {
            endpoints: vec![test_endpoint(&url, &[OP_LOGIN])],
        };
        mgr.handle_mutable(OP_LOGIN, serde_json::json!({"user":"alice"}))
            .await
            .unwrap();
        let raw = server.await.unwrap();
        assert!(
            raw.starts_with("POST /handler?version=0.1.0&op=Login HTTP/1.1"),
            "{raw}"
        );
        assert!(raw.to_ascii_lowercase().contains("x-frp-reqid:"), "{raw}");
        assert!(raw.contains(r#""op":"Login""#), "{raw}");
        assert!(raw.contains(r#""user":"alice""#), "{raw}");
    }

    #[tokio::test]
    async fn reject_把原因返回给调用方() {
        let body = r#"{"reject":true,"reject_reason":"bad user","unchange":true}"#;
        let (url, _server) = one_shot_server(body, Arc::new(AtomicUsize::new(0))).await;
        let mgr = PluginManager {
            endpoints: vec![test_endpoint(&url, &[OP_LOGIN])],
        };
        let e = mgr
            .handle_mutable(OP_LOGIN, serde_json::json!({"user":"x"}))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("bad user"));
    }

    #[tokio::test]
    async fn unchange_false_时用插件内容替换() {
        let body = r#"{"reject":false,"unchange":false,"content":{"user":"rewritten"}}"#;
        let (url, _server) = one_shot_server(body, Arc::new(AtomicUsize::new(0))).await;
        let mgr = PluginManager {
            endpoints: vec![test_endpoint(&url, &[OP_LOGIN])],
        };
        let out = mgr
            .handle_mutable(OP_LOGIN, serde_json::json!({"user":"original"}))
            .await
            .unwrap();
        assert_eq!(out["user"], "rewritten");
    }

    #[test]
    fn 地址没写_scheme_时补_http() {
        let cfg = HttpPluginConfig {
            name: "p".into(),
            addr: "127.0.0.1:9000".into(),
            path: "handler".into(),
            ops: vec![OP_LOGIN.into()],
            tls_verify: false,
        };
        let mgr = PluginManager::from_config(&[cfg]).unwrap();
        assert_eq!(mgr.endpoints[0].url, "http://127.0.0.1:9000/handler");
        assert!(mgr.endpoints[0].opts.insecure_skip_verify);
    }

    #[test]
    fn 空地址直接报配置错误() {
        let cfg = HttpPluginConfig {
            name: "p".into(),
            addr: "".into(),
            path: "/handler".into(),
            ops: vec![OP_LOGIN.into()],
            tls_verify: false,
        };
        assert!(PluginManager::from_config(&[cfg]).is_err());
    }

    #[test]
    fn login_client_address_可附加且回解析() {
        let login = crate::frp::msg::Login {
            user: "u".into(),
            ..Default::default()
        };
        let v = login_content(&login, "1.2.3.4:5").unwrap();
        assert_eq!(v["client_address"], "1.2.3.4:5");
        let mut got = crate::frp::msg::Login::default();
        apply_login_content(&mut got, v).unwrap();
        assert_eq!(got.user, "u");
    }
}
