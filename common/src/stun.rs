//! 最小 STUN 客户端（RFC 5389 Binding Request），用于 xtcp 的 NAT 映射探测。
//!
//! # 用途
//!
//! 官方 frpc 在 xtcp 里先做 `nathole.Prepare([]string{natHoleStunServer}, opts)`：
//! 向 STUN 服务器发 Binding Request，拿到**自己的公网映射地址**
//! （`XOR-MAPPED-ADDRESS`），再把这个地址填进 `NatHoleVisitor.mapped_addrs`
//! 交给服务端做撮合。
//!
//! 没有它，客户端只能靠"服务端看到的源地址"猜映射 —— 在锥形 NAT 下够用，
//! 但在对称 NAT / 多出口时会给出错误地址，打洞必然失败。
//!
//! # 只做最小实现
//!
//! * 只支持 **UDP** 上的 Binding Request（RFC 5389）；
//! * 只解析 `XOR-MAPPED-ADDRESS`（0x0020）与 `MAPPED-ADDRESS`（0x0001，老 RFC 3489）；
//! * 不处理认证（`MESSAGE-INTEGRITY`）—— 公网 STUN 服务都不需要；
//! * 有超时与重试，不会卡住启动。
//!
//! 这样约 150 行、全部可单测，不引第三方 STUN 库。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::net::UdpSocket;

/// STUN magic cookie（RFC 5389 §6）。
const MAGIC_COOKIE: u32 = 0x2112_A442;
/// Binding Request 的 message type。
const BINDING_REQUEST: u16 = 0x0001;
/// Binding Response 的 message type。
const BINDING_RESPONSE: u16 = 0x0101;
/// XOR-MAPPED-ADDRESS 属性。
const ATTR_XOR_MAPPED: u16 = 0x0020;
/// 老式 MAPPED-ADDRESS 属性（RFC 3489）。
const ATTR_MAPPED: u16 = 0x0001;

/// 单次探测的默认超时。
const TIMEOUT: Duration = Duration::from_secs(3);

/// 向 STUN 服务器探测本机的公网映射地址。
///
/// `server` 形如 `stun.example.com:3478` / `1.2.3.4:3478`。
/// 返回 `(映射到的地址, 该 STUN 服务器看到的本地出口地址)`。
///
/// 多个服务器时用 `,` 分隔，**逐个尝试**，第一个成功的就用它
/// （官方 `nathole.Prepare` 也是传一个列表逐个试）。
pub async fn probe(servers: &str) -> Result<SocketAddr> {
    let list: Vec<&str> = servers
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if list.is_empty() {
        bail!("没有配置 STUN 服务器");
    }

    let mut last_err = None;
    for s in list {
        match probe_one(s).await {
            Ok(addr) => return Ok(addr),
            Err(e) => last_err = Some(format!("{s}: {e:#}")),
        }
    }
    Err(anyhow!(
        "所有 STUN 服务器都探测失败：{}",
        last_err.unwrap_or_else(|| "（无）".into())
    ))
}

async fn probe_one(server: &str) -> Result<SocketAddr> {
    let dst = crate::util::resolve_addr(server)
        .await
        .with_context(|| format!("解析 STUN 服务器地址 {server} 失败"))?;
    let sock = UdpSocket::bind(if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .await
        .context("绑定本地 UDP 端口失败（STUN）")?;

    // 事务 ID 必须是随机的（RFC 5389 §6：96 位随机）
    let mut txn = [0u8; 12];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut txn)
        .expect("系统随机数不可用");

    let req = build_binding_request(&txn);
    sock.send_to(&req, dst)
        .await
        .with_context(|| format!("向 STUN {server} 发送 Binding Request 失败"))?;

    let mut buf = vec![0u8; 1500];
    let (n, _from) = tokio::time::timeout(TIMEOUT, sock.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow!("等 STUN {server} 应答超时（{}s）", TIMEOUT.as_secs()))?
        .with_context(|| format!("从 STUN {server} 收应答失败"))?;

    parse_binding_response(&buf[..n], &txn)
}

/// 拼一个 Binding Request。
fn build_binding_request(txn: &[u8; 12]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    buf.extend_from_slice(&BINDING_REQUEST.to_be_bytes()); // type
    buf.extend_from_slice(&0u16.to_be_bytes()); // length（无属性）
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(txn);
    buf
}

/// 解析 Binding Response，取出映射地址。
fn parse_binding_response(buf: &[u8], txn: &[u8; 12]) -> Result<SocketAddr> {
    if buf.len() < 20 {
        bail!("STUN 应答太短（{} 字节）", buf.len());
    }
    let mtype = u16::from_be_bytes([buf[0], buf[1]]);
    if mtype != BINDING_RESPONSE {
        bail!("不是 Binding Response（type {mtype:#06x}）");
    }
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE {
        bail!("STUN magic cookie 不对（{cookie:#010x}）—— 对端不是 RFC 5389 服务器");
    }
    if &buf[8..20] != txn {
        bail!("STUN 事务 ID 不匹配");
    }
    if 20 + len > buf.len() {
        bail!("STUN 应答长度字段（{len}）超过实际数据");
    }

    let end = 20 + len;
    let mut pos = 20;
    let mut fallback: Option<SocketAddr> = None;
    while pos + 4 <= end {
        let atype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let alen = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + alen > end {
            bail!("STUN 属性长度越界");
        }
        let data = &buf[pos..pos + alen];
        // 属性按 4 字节对齐
        pos += (alen + 3) & !3;

        if atype == ATTR_XOR_MAPPED {
            if let Some(a) = parse_addr_attr(data, Some(txn)) {
                return Ok(a);
            }
        } else if atype == ATTR_MAPPED && fallback.is_none() {
            fallback = parse_addr_attr(data, None);
        }
    }

    fallback.ok_or_else(|| anyhow!("STUN 应答里没有 MAPPED-ADDRESS 属性"))
}

/// 解析地址属性：`0x00 | family | port | addr`。
///
/// `xor` 为 `Some(txn)` 时按 RFC 5389 解 XOR（端口与 cookie 高 16 位异或，
/// IPv4 与 cookie 异或、IPv6 与 cookie‖txn 异或）。
fn parse_addr_attr(data: &[u8], xor: Option<&[u8; 12]>) -> Option<SocketAddr> {
    if data.len() < 4 {
        return None;
    }
    let family = data[1];
    let mut port = u16::from_be_bytes([data[2], data[3]]);

    if xor.is_some() {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }

    match family {
        0x01 => {
            if data.len() < 8 {
                return None;
            }
            let mut oct = [data[4], data[5], data[6], data[7]];
            if let Some(_t) = xor {
                let c = MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    oct[i] ^= c[i];
                }
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(oct)), port))
        }
        0x02 => {
            if data.len() < 20 {
                return None;
            }
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&data[4..20]);
            if let Some(txn) = xor {
                let c = MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    oct[i] ^= c[i];
                }
                for i in 0..12 {
                    oct[4 + i] ^= txn[i];
                }
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(oct)), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 请求报文格式正确() {
        let txn = [1u8; 12];
        let r = build_binding_request(&txn);
        assert_eq!(r.len(), 20);
        assert_eq!(&r[0..2], &[0x00, 0x01], "Binding Request");
        assert_eq!(&r[2..4], &[0, 0], "无属性");
        assert_eq!(&r[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&r[8..20], &txn);
    }

    /// 手工造一份带 XOR-MAPPED-ADDRESS 的应答，验证解析。
    #[test]
    fn 解析_xor_mapped_ipv4() {
        let txn = [0xABu8; 12];
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let port = 54321u16;

        // 按 RFC 5389 做 XOR 编码
        let c = MAGIC_COOKIE.to_be_bytes();
        let mut enc_ip = ip.octets();
        for i in 0..4 {
            enc_ip[i] ^= c[i];
        }
        let enc_port = port ^ ((MAGIC_COOKIE >> 16) as u16);

        let mut attr = vec![0x00u8, 0x01]; // reserved + family IPv4
        attr.extend_from_slice(&enc_port.to_be_bytes());
        attr.extend_from_slice(&enc_ip);

        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&((attr.len() + 4) as u16).to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txn);
        resp.extend_from_slice(&ATTR_XOR_MAPPED.to_be_bytes());
        resp.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        resp.extend_from_slice(&attr);

        let got = parse_binding_response(&resp, &txn).unwrap();
        assert_eq!(got, SocketAddr::new(IpAddr::V4(ip), port));
    }

    /// 事务 ID 不匹配必须拒（否则会被无关应答污染）。
    #[test]
    fn 事务_id_不匹配要拒() {
        let txn = [0xABu8; 12];
        let mut resp = vec![0x01, 0x01, 0x00, 0x00];
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&[0xCD; 12]);
        assert!(parse_binding_response(&resp, &txn).is_err());
    }

    /// 不是 RFC 5389（没有 magic cookie）也要明确报错。
    #[test]
    fn 没有_magic_cookie_要报错() {
        let txn = [1u8; 12];
        let mut resp = vec![0x01, 0x01, 0x00, 0x00, 0, 0, 0, 0];
        resp.extend_from_slice(&txn);
        let e = parse_binding_response(&resp, &txn).unwrap_err();
        assert!(format!("{e:#}").contains("magic cookie"), "{e:#}");
    }

    /// 老式（RFC 3489）MAPPED-ADDRESS 也要认，作为兜底。
    #[test]
    fn 兼容老式_mapped_address() {
        let txn = [2u8; 12];
        let mut attr = vec![0x00u8, 0x01];
        attr.extend_from_slice(&8080u16.to_be_bytes());
        attr.extend_from_slice(&[10, 1, 2, 3]);

        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&((attr.len() + 4) as u16).to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txn);
        resp.extend_from_slice(&ATTR_MAPPED.to_be_bytes());
        resp.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        resp.extend_from_slice(&attr);

        let got = parse_binding_response(&resp, &txn).unwrap();
        assert_eq!(got.port(), 8080);
    }

    #[tokio::test]
    async fn 空服务器列表要报错() {
        let e = probe("  ,  ").await.unwrap_err();
        assert!(format!("{e:#}").contains("STUN"), "{e:#}");
    }
}
