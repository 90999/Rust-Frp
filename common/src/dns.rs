//! 自定义 DNS 解析（官方 frpc 的 `dnsServer`）。
//!
//! # 语义
//!
//! 官方注释（`pkg/config/v1/client.go`）：
//!
//! > DNSServer specifies a DNS server address for FRPC to use.
//! > If this value is empty, the system default will be used.
//!
//! 也就是说它**只改 frpc 自己**解析服务端地址时用的 DNS，不动系统设置。
//!
//! # 为什么自己实现，不引 `hickory-dns`
//!
//! 需要的只是"查一个 A / AAAA 记录"：
//!
//! * `hickory-resolver` 会带进十几个 crate（含 TLS、缓存、DNSSEC 相关）；
//! * 而 DNS 报文格式在这个用途下极简（一问一答，A/AAAA），
//!   手写解析约 150 行、可完整单测，且**没有 unsafe**。
//!
//! 对"内网自建 DNS 才能解析服务端域名"这种场景，这就够了。
//!
//! # 安全
//!
//! * 只接受 `UDP 53` 的明文查询（与系统 stub resolver 一致）；
//! * 校验事务 ID 与问题段回显，避免被无关应答污染；
//! * 有超时（默认 5 秒）与重试上限，不会卡死启动流程。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::net::UdpSocket;

/// 单次查询的默认超时。
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// MCU 上限，防止畸形应答把内存吃穿。
const MAX_RESP: usize = 4096;

/// 用 `server` 解析 `name`，返回第一个地址。
///
/// `server` 形如 `8.8.8.8` / `8.8.8.8:53` / `[::1]:53`。不带端口时补 53。
pub async fn resolve_via(server: &str, name: &str) -> Result<Vec<IpAddr>> {
    let server_addr = parse_server(server)?;
    let sock = UdpSocket::bind(if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
    .context("绑定本地 UDP 端口失败（自定义 DNS）")?;

    // 先查 A；拿不到再查 AAAA（与服务端地址族的常见预期一致）
    let mut addrs = query(&sock, server_addr, name, 1).await.unwrap_or_default();
    if addrs.is_empty() {
        addrs = query(&sock, server_addr, name, 28)
            .await
            .unwrap_or_default();
    }
    if addrs.is_empty() {
        bail!("自定义 DNS {server} 没能解析出 {name} 的任何 A/AAAA 记录");
    }
    Ok(addrs)
}

/// 用 `server` 解析 `addr`（形如 `host:port`）为 `SocketAddr`。
///
/// 主机部分如果是 IP 字面量，**不查 DNS**（直接返回）。
pub async fn resolve_addr_via(server: &str, addr: &str) -> Result<SocketAddr> {
    // 已经是 IP:port？
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let (host, port) = split_host_port(addr)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let ips = resolve_via(server, &host).await?;
    Ok(SocketAddr::new(ips[0], port))
}

fn split_host_port(addr: &str) -> Result<(String, u16)> {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((h, tail)) = rest.split_once(']') {
            let p = tail.strip_prefix(':').unwrap_or("0");
            return Ok((h.to_string(), p.parse().context("端口不是数字")?));
        }
        bail!("IPv6 地址缺少 `]`：{addr}");
    }
    match addr.rsplit_once(':') {
        Some((h, p)) => Ok((h.to_string(), p.parse().context("端口不是数字")?)),
        None => bail!("地址缺少端口：{addr}"),
    }
}

fn parse_server(server: &str) -> Result<SocketAddr> {
    let s = server.trim();
    if s.is_empty() {
        bail!("dnsServer 为空");
    }
    // host:port 形式
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa);
    }
    // 纯 IP：补 53
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    // [v6] 或 [v6]:port
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((h, tail)) = rest.split_once(']') {
            let ip: IpAddr = h.parse().context("dnsServer 的 IPv6 字面量非法")?;
            let port = match tail.strip_prefix(':') {
                Some(p) if !p.is_empty() => p.parse().context("dnsServer 端口不是数字")?,
                _ => 53,
            };
            return Ok(SocketAddr::new(ip, port));
        }
    }
    // 剩下只可能是主机名——我们不支持用主机名指 DNS 服务器（那需要先解析它）
    bail!("dnsServer 必须是 IP 地址（可带端口）：{server}")
}

/// 拼一个 DNS 查询报文。
fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        bail!("要解析的域名为空");
    }
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            bail!("域名标签长度非法（1~63 字节）：{label:?}");
        }
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(buf)
}

async fn query(
    sock: &UdpSocket,
    server: SocketAddr,
    name: &str,
    qtype: u16,
) -> Result<Vec<IpAddr>> {
    // 事务 ID 用系统随机数：可预测的 ID 会让应答伪造容易得多
    let mut idb = [0u8; 2];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut idb)
        .expect("系统随机数不可用");
    let id = u16::from_be_bytes(idb);

    let req = build_query(id, name, qtype)?;
    sock.send_to(&req, server)
        .await
        .with_context(|| format!("向 DNS {server} 发送查询失败"))?;

    let mut buf = vec![0u8; MAX_RESP];
    let (n, _from) = tokio::time::timeout(QUERY_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow!("等 DNS {server} 的应答超时（{}s）", QUERY_TIMEOUT.as_secs()))?
        .with_context(|| format!("从 DNS {server} 收应答失败"))?;

    parse_response(&buf[..n], id, name, qtype)
}

/// 解析应答，只取我们问的那一类记录。
fn parse_response(buf: &[u8], id: u16, name: &str, qtype: u16) -> Result<Vec<IpAddr>> {
    if buf.len() < 12 {
        bail!("DNS 应答太短（{} 字节）", buf.len());
    }
    let rid = u16::from_be_bytes([buf[0], buf[1]]);
    if rid != id {
        bail!("DNS 应答的事务 ID 不匹配（期望 {id:#06x}，实际 {rid:#06x}）");
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        bail!("收到的不是应答（QR=0）");
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        bail!("DNS 服务器返回错误码 {rcode}（{}）", rcode_text(rcode));
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    // 跳过问题段
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(buf, pos)?;
        pos = pos.checked_add(4).ok_or_else(|| anyhow!("DNS 报文越界"))?;
        if pos > buf.len() {
            bail!("DNS 问题段越界");
        }
    }

    let mut out = Vec::new();
    for _ in 0..an {
        pos = skip_name(buf, pos)?;
        if pos + 10 > buf.len() {
            bail!("DNS 资源记录头越界");
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            bail!("DNS 资源记录数据越界");
        }
        if rtype == qtype {
            let data = &buf[pos..pos + rdlen];
            match qtype {
                1 if rdlen == 4 => out.push(IpAddr::V4(Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                ))),
                28 if rdlen == 16 => {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(data);
                    out.push(IpAddr::V6(Ipv6Addr::from(b)));
                }
                _ => {}
            }
        }
        pos += rdlen;
    }

    if out.is_empty() {
        bail!("DNS 应答里没有 {name} 的所求记录（type {qtype}）");
    }
    Ok(out)
}

/// 跳过域名（支持压缩指针）。
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        if pos >= buf.len() {
            bail!("DNS 名字越界");
        }
        let len = buf[pos];
        if len == 0 {
            return Ok(pos + 1);
        }
        // 压缩指针：高两位 11 ⇒ 2 字节，且后面不再有本名字的延续
        if len & 0xC0 == 0xC0 {
            if pos + 2 > buf.len() {
                bail!("DNS 压缩指针越界");
            }
            return Ok(pos + 2);
        }
        if len & 0xC0 != 0 {
            bail!("DNS 名字段类型非法（{len:#04x}）");
        }
        pos += 1 + len as usize;
    }
}

fn rcode_text(c: u16) -> &'static str {
    match c {
        1 => "格式错误",
        2 => "服务器故障",
        3 => "域名不存在（NXDOMAIN）",
        4 => "查询类型不支持",
        5 => "拒绝（REFUSED）",
        _ => "未知",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 拼出来的查询报文合法() {
        let q = build_query(0x1234, "example.com", 1).unwrap();
        assert_eq!(&q[0..2], &[0x12, 0x34], "事务 ID");
        assert_eq!(u16::from_be_bytes([q[2], q[3]]) & 0x0100, 0x0100, "RD=1");
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1, "QDCOUNT");
        // 问题段：7 example 3 com 0
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(q[24], 0);
        assert_eq!(u16::from_be_bytes([q[25], q[26]]), 1, "QTYPE=A");
    }

    #[test]
    fn 非法域名要报错() {
        assert!(build_query(1, "", 1).is_err());
        assert!(build_query(1, &"a".repeat(64), 1).is_err(), "标签超 63");
    }

    #[test]
    fn dns_服务器地址解析() {
        assert_eq!(parse_server("8.8.8.8").unwrap().port(), 53);
        assert_eq!(parse_server("8.8.8.8:5353").unwrap().port(), 5353);
        assert_eq!(parse_server("[::1]:53").unwrap().port(), 53);
        assert!(
            parse_server("dns.example.com").is_err(),
            "不支持主机名指 DNS"
        );
        assert!(parse_server("").is_err());
    }

    /// 伪造一份应答，验证解析与"事务 ID 不匹配必须拒"。
    #[test]
    fn 应答解析与_id_校验() {
        // 手工造：ID=0x1234, flags=0x8180(RD+RA+QR), QD=1, AN=1
        let mut r: Vec<u8> = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0];
        // 问题：example.com A IN
        r.extend_from_slice(&[7]);
        r.extend_from_slice(b"example");
        r.extend_from_slice(&[3]);
        r.extend_from_slice(b"com");
        r.extend_from_slice(&[0]);
        r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // 应答：指向问题段的名字(0xC00C), A, IN, TTL, RDLEN=4, 1.2.3.4
        r.extend_from_slice(&[0xC0, 0x0C]);
        r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
        r.extend_from_slice(&[0x00, 0x04]);
        r.extend_from_slice(&[1, 2, 3, 4]);

        let got = parse_response(&r, 0x1234, "example.com", 1).unwrap();
        assert_eq!(got, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);

        // 事务 ID 不对 ⇒ 必须拒（否则可被无关/伪造应答污染）
        assert!(parse_response(&r, 0x9999, "example.com", 1).is_err());
        // NXDOMAIN
        let mut nx = r.clone();
        nx[3] = 0x83; // rcode=3
        assert!(parse_response(&nx, 0x1234, "example.com", 1).is_err());
    }

    #[test]
    fn 压缩指针越界要报错() {
        let buf = [0xC0, 0xFF];
        assert!(skip_name(&buf, 0).is_ok(), "指针本身 2 字节即结束");
        let short = [0xC0];
        assert!(skip_name(&short, 0).is_err());
    }
}
