//! 出站代理：通过 HTTP CONNECT 或 SOCKS5 连到对端（官方 frp 的 `transport.proxyURL`）。
//!
//! # 官方语义
//!
//! `proxyURL` 支持三种 scheme（`libnet.ParseProxyURL`）：
//! * `http://[user:pass@]host:port` —— HTTP CONNECT 隧道；
//! * `https://...` —— 先与代理做 TLS，再 CONNECT；
//! * `socks5://[user:pass@]host:port` —— SOCKS5（用户名/密码认证）。
//!
//! 它作用于**客户端连服务端**的方向（控制连接与工作连接都走它），
//! 也作用于 OIDC 拉 JWKS（那边 `httpc` 已实现）。
//!
//! # 为什么不复用 `httpc`
//!
//! `httpc::connect_via_proxy` 是私有的、且只为 HTTP(S) 服务；而这里需要
//! 一个**通用的"给我一条到 host:port 的字节流"**入口，还要支持 SOCKS5。
//! 两者关注点不同（一个是"发 HTTP 请求"，一个是"建立裸隧道"），
//! 混在一起会让 `httpc` 越来越难读。所以单独一个模块。
//!
//! # 安全约束
//!
//! * 只接受 `http` / `https` / `socks5` / `socks5h` 四种 scheme，
//!   其它一律报错（不"猜"）；
//! * `https` 代理走 rustls，**校验证书**（代理是用户自己的基础设施，
//!   没有"自签"的普遍需求；要自签请用 http 代理或换证书）；
//! * 认证信息只从 URL 的 userinfo 读，**不进日志**（日志里只打 host:port）。

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::frp::stream::BoxStream;

/// 通过 `proxy_url` 建立一条到 `host:port` 的隧道。
///
/// `proxy_url` 为空时**直连**（不经过任何代理），行为与之前完全一致。
pub async fn connect(
    proxy_url: &str,
    host: &str,
    port: u16,
    _tls_to_target: Option<&str>,
) -> Result<BoxStream> {
    if proxy_url.trim().is_empty() {
        return Ok(Box::pin(
            TcpStream::connect((host, port))
                .await
                .with_context(|| format!("连接 {host}:{port} 失败"))?,
        ));
    }

    let (scheme, rest) = proxy_url
        .split_once("://")
        .ok_or_else(|| anyhow!("proxyURL 缺少 scheme（应形如 http://host:port）：{proxy_url}"))?;
    let scheme = scheme.to_ascii_lowercase();

    // 拆 userinfo 与 host:port
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };
    let hostport = hostport.trim_end_matches('/');
    let (phost, pport) = split_host_port(hostport, &scheme)?;

    match scheme.as_str() {
        "http" | "https" => {
            let mut stream: BoxStream = Box::pin(
                TcpStream::connect((phost.as_str(), pport))
                    .await
                    .with_context(|| format!("连接代理 {phost}:{pport} 失败"))?,
            );
            if scheme == "https" {
                let name = rustls::pki_types::ServerName::try_from(phost.clone())
                    .map_err(|e| anyhow!("无效的代理主机名 {phost}：{e:?}"))?;
                let cfg = crate::frp::tls::client_config()
                    .context("构造 TLS 配置失败（https 代理）")?;
                stream = Box::pin(
                    tokio_rustls::TlsConnector::from(cfg)
                        .connect(name, stream)
                        .await
                        .context("与 https 代理的 TLS 握手失败")?,
                );
            }
            http_connect(stream, &phost, pport, userinfo, host, port).await
        }
        "socks5" | "socks5h" => {
            let stream = TcpStream::connect((phost.as_str(), pport))
                .await
                .with_context(|| format!("连接 SOCKS5 代理 {phost}:{pport} 失败"))?;
            let boxed: BoxStream = Box::pin(stream);
            socks5_connect(boxed, userinfo, host, port).await
        }
        other => bail!(
            "proxyURL 的 scheme [{other}] 不支持；支持 http / https / socks5 / socks5h（{proxy_url}）"
        ),
    }
}

/// 拆 `host:port`，缺 port 时按 scheme 给默认值。
fn split_host_port(hostport: &str, scheme: &str) -> Result<(String, u16)> {
    // IPv6 字面量：[::1]:8080
    if let Some(rest) = hostport.strip_prefix('[') {
        if let Some((h, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').filter(|p| !p.is_empty());
            let p = match port {
                Some(p) => p.parse().context("代理端口不是数字")?,
                None => default_port(scheme),
            };
            return Ok((h.to_string(), p));
        }
        bail!("代理地址的 IPv6 字面量没有闭合的 `]`：{hostport}");
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() => {
            Ok((h.to_string(), p.parse().context("代理端口不是数字")?))
        }
        Some((h, _)) => Ok((h.to_string(), default_port(scheme))),
        None => Ok((hostport.to_string(), default_port(scheme))),
    }
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        "socks5" | "socks5h" => 1080,
        _ => 8080,
    }
}

/// 在已连上代理的流上发 `CONNECT`，把隧道交给调用方。
async fn http_connect(
    mut stream: BoxStream,
    phost: &str,
    pport: u16,
    userinfo: Option<&str>,
    host: &str,
    port: u16,
) -> Result<BoxStream> {
    let target = format!("{host}:{port}");
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(u) = userinfo {
        // Basic 认证：base64(user:pass)。这里只编码、不校验 —— 校验是代理的事。
        use base64::Engine as _;
        let cred = base64::engine::general_purpose::STANDARD.encode(u.as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {cred}\r\n"));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .with_context(|| format!("向代理 {phost}:{pport} 发送 CONNECT 失败"))?;
    stream.flush().await.ok();

    // 读到头结束
    let mut buf = Vec::new();
    let mut one = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut one)
            .await
            .context("读代理 CONNECT 响应失败")?;
        if n == 0 {
            bail!("代理 {phost}:{pport} 在返回 CONNECT 响应前就关闭了连接");
        }
        buf.extend_from_slice(&one[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_string();
            let status = head
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|c| c.parse::<u16>().ok())
                .unwrap_or(0);
            if !(200..300).contains(&status) {
                bail!(
                    "代理 {phost}:{pport} 拒绝 CONNECT {target}（HTTP {status}）：{}",
                    head.lines().next().unwrap_or("")
                );
            }
            // CONNECT 之后是裸字节；头之后可能已经带了隧道数据，塞回去
            let leftover = buf[pos + 4..].to_vec();
            if leftover.is_empty() {
                return Ok(stream);
            }
            return Ok(Box::pin(crate::frp::stream::PrefixedStream::new(
                leftover, stream,
            )));
        }
        if buf.len() > 64 * 1024 {
            bail!("代理 {phost}:{pport} 的 CONNECT 响应头超过 64 KiB");
        }
    }
}

/// SOCKS5（RFC 1928 + RFC 1929 用户名/密码认证）。
async fn socks5_connect(
    mut stream: BoxStream,
    userinfo: Option<&str>,
    host: &str,
    port: u16,
) -> Result<BoxStream> {
    let (user, pass) = match userinfo {
        Some(u) => match u.split_once(':') {
            Some((a, b)) => (Some(a.to_string()), Some(b.to_string())),
            None => (Some(u.to_string()), Some(String::new())),
        },
        None => (None, None),
    };

    // ① 打招呼：支持 无认证(0x00) 与 用户名密码(0x02)
    let methods: &[u8] = if user.is_some() {
        &[0x00, 0x02]
    } else {
        &[0x00]
    };
    let mut hello = vec![0x05u8, methods.len() as u8];
    hello.extend_from_slice(methods);
    stream.write_all(&hello).await.context("SOCKS5 问候失败")?;

    let mut rep = [0u8; 2];
    stream
        .read_exact(&mut rep)
        .await
        .context("读 SOCKS5 问候响应失败")?;
    if rep[0] != 0x05 {
        bail!("对端不是 SOCKS5（版本字节 {:#x}）", rep[0]);
    }
    match rep[1] {
        0x00 => {} // 无需认证
        0x02 => {
            let u = user.ok_or_else(|| anyhow!("SOCKS5 代理要求用户名密码，但 proxyURL 里没写"))?;
            let p = pass.unwrap_or_default();
            let mut auth = vec![0x01u8, u.len() as u8];
            auth.extend_from_slice(u.as_bytes());
            auth.push(p.len() as u8);
            auth.extend_from_slice(p.as_bytes());
            stream
                .write_all(&auth)
                .await
                .context("SOCKS5 认证发送失败")?;
            let mut ar = [0u8; 2];
            stream
                .read_exact(&mut ar)
                .await
                .context("读 SOCKS5 认证响应失败")?;
            if ar[1] != 0x00 {
                bail!("SOCKS5 用户名密码认证被拒绝");
            }
        }
        0xFF => bail!("SOCKS5 代理不接受我们的任何认证方式"),
        m => bail!("SOCKS5 代理选了未支持的方法 {m:#x}"),
    }

    // ② CONNECT 请求
    let mut req = vec![0x05u8, 0x01, 0x00];
    let ip: Option<std::net::IpAddr> = host.parse().ok();
    match ip {
        Some(std::net::IpAddr::V4(v4)) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        Some(std::net::IpAddr::V6(v6)) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
        None => {
            // 域名交给代理解析（socks5h 语义；socks5 下 Go 也是这么做的）
            if host.len() > 255 {
                bail!("SOCKS5 目标主机名过长（{} 字节）", host.len());
            }
            req.push(0x03);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&req)
        .await
        .context("SOCKS5 CONNECT 发送失败")?;

    // ③ 读回复：VER REP RSV ATYP + 地址 + 端口
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .context("读 SOCKS5 CONNECT 响应失败")?;
    if head[0] != 0x05 {
        bail!("SOCKS5 响应版本不对（{:#x}）", head[0]);
    }
    if head[1] != 0x00 {
        bail!("SOCKS5 CONNECT 被拒绝：{}", socks5_err(head[1]));
    }
    // 按 ATYP 长度把剩余地址读掉
    let rest_len = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            stream
                .read_exact(&mut l)
                .await
                .context("读 SOCKS5 域名长度失败")?;
            l[0] as usize + 2
        }
        a => bail!("SOCKS5 返回了未知地址类型 {a:#x}"),
    };
    let mut rest = vec![0u8; rest_len];
    stream
        .read_exact(&mut rest)
        .await
        .context("读 SOCKS5 绑定地址失败")?;

    Ok(stream)
}

fn socks5_err(code: u8) -> &'static str {
    match code {
        0x01 => "通用失败",
        0x02 => "规则不允许（代理不放行该目标）",
        0x03 => "网络不可达",
        0x04 => "主机不可达",
        0x05 => "连接被拒绝",
        0x06 => "TTL 过期",
        0x07 => "不支持的命令",
        0x08 => "不支持的地址类型",
        _ => "未知错误",
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 拆_host_port_各种写法() {
        assert_eq!(
            split_host_port("1.2.3.4:8080", "http").unwrap(),
            ("1.2.3.4".into(), 8080)
        );
        assert_eq!(
            split_host_port("proxy.lan", "http").unwrap(),
            ("proxy.lan".into(), 8080)
        );
        assert_eq!(
            split_host_port("proxy.lan", "https").unwrap(),
            ("proxy.lan".into(), 443)
        );
        assert_eq!(
            split_host_port("proxy.lan", "socks5").unwrap(),
            ("proxy.lan".into(), 1080)
        );
        assert_eq!(
            split_host_port("[::1]:9050", "socks5").unwrap(),
            ("::1".into(), 9050)
        );
        assert_eq!(
            split_host_port("1.2.3.4:", "http").unwrap(),
            ("1.2.3.4".into(), 8080)
        );
        assert!(split_host_port("proxy:abc", "http").is_err());
    }

    /// 空 proxy_url ⇒ 直连（不走代理）。用本机一个必然拒绝的端口验证
    /// "确实尝试了直连"，而不是悄悄走了别的路径。
    #[tokio::test]
    async fn 空代理地址是直连() {
        // 连一个几乎不可能有人监听的端口：期望拿到连接错误，
        // 而不是"proxyURL 解析失败"之类的错误。
        let msg = match connect("", "127.0.0.1", 1, None).await {
            Ok(_) => panic!("连 127.0.0.1:1 不该成功"),
            Err(e) => format!("{e:#}"),
        };
        assert!(!msg.contains("scheme"), "空地址不该走到代理解析分支：{msg}");
    }

    /// 不支持的 scheme 必须明确报错，不能猜。
    #[tokio::test]
    async fn 不支持的_scheme_报错() {
        let msg = match connect("ftp://1.2.3.4:21", "example.com", 80, None).await {
            Ok(_) => panic!("不支持的 scheme 不该成功"),
            Err(e) => format!("{e:#}"),
        };
        assert!(msg.contains("不支持"), "要说清不支持：{msg}");
        assert!(msg.contains("ftp"), "要回显用户写的 scheme：{msg}");
    }

    /// SOCKS5 错误码要翻成人话。
    #[test]
    fn socks5_错误码可读() {
        assert_eq!(socks5_err(0x05), "连接被拒绝");
        assert_eq!(socks5_err(0x03), "网络不可达");
    }
}
