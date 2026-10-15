//! frp 的 `transport.tls` 实现。
//!
//! 注意：frp 说的"自定义 TLS"其实是**标准 TLS**（Go `crypto/tls`），
//! "自定义"只体现在两点：
//!
//! 1. 服务端自动生成一张自签名证书（默认 RSA-2048，我们这里用 ECDSA-P256）；
//! 2. 客户端默认 `InsecureSkipVerify = true`，不校验服务端证书。
//!
//! 另外 frp 客户端在 TLS 握手前会先发一个 `0x17`（TLS Application Data 记录类型）
//! 用于伪装，服务端据此判断这是 TLS 连接。可通过
//! `transport.tls.disableCustomTLSFirstByte = true` 关掉。

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::stream::{BoxStream, PrefixedStream};

/// frp 自定义首字节：`0x17` = TLS Application Data，用于把 frp 流量伪装成 TLS。
pub const FRP_TLS_HEAD_BYTE: u8 = 0x17;
/// 标准 TLS 握手的第一个字节（Handshake）。
const TLS_HANDSHAKE_BYTE: u8 = 0x16;

/// 探测首字节的等待时间，与 frp 的 `connReadTimeout` 对应。
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// 服务端证书只生成一次：RSA/ECDSA 密钥生成有几十毫秒开销，
/// 每个连接都生成会明显拖慢握手。
static SERVER_TLS_CONFIG: OnceLock<Arc<rustls::ServerConfig>> = OnceLock::new();

/// 进程共用的 rustls 加密后端（QUIC 直连也要用同一个 provider）。
pub fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// 生成自签名证书并构造服务端 TLS 配置。
pub fn server_config() -> Result<Arc<rustls::ServerConfig>> {
    if let Some(c) = SERVER_TLS_CONFIG.get() {
        return Ok(c.clone());
    }
    let key = rcgen::generate_simple_self_signed(vec!["frp".to_string()])
        .context("生成自签名证书失败")?;
    let cert_der: CertificateDer<'static> = key.cert.der().clone();
    let key_der = PrivateKeyDer::try_from(key.key_pair.serialize_der())
        .map_err(|e| anyhow!("转换私钥失败：{e}"))?;

    let cfg = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| anyhow!("TLS 协议版本配置失败：{e}"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("装载服务端证书失败")?;

    let cfg = Arc::new(cfg);
    let _ = SERVER_TLS_CONFIG.set(cfg.clone());
    Ok(cfg)
}

/// 客户端 TLS 配置：与 frp 默认行为一致，不校验服务端证书。
///
/// ★★ v0.5.6（审计总报告 L16，低危）：保留这个默认，但**新增**
/// [`client_config_verifying`] 提供"真正校验"的可选路径。
///
/// # 为什么默认不改
///
/// 官方 frp 的 `transport.tls.enable = true` **默认不校验对端证书**
/// （`InsecureSkipVerify = true`）。改了默认会让"官方 frpc ↔ NFrp frps"
/// 这条零配置互通链路直接断掉 —— 而 README 明确承诺了它。
/// 这是**设计取舍**，不是遗漏（报告也这么定位）。
///
/// # 但必须给用户一条更安全的路
///
/// 现状的问题是"用户**没有选择**"：想校验也做不到。
/// 同项目的 `httpc`（OIDC 那边）默认是**校验**的 —— 同一个仓库两套默认，
/// 而其中一套无法切换。本函数补上那个开关。
pub fn client_config() -> Result<Arc<rustls::ClientConfig>> {
    let cfg = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| anyhow!("TLS 协议版本配置失败：{e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// 客户端 TLS 配置：**校验服务端证书**（v0.5.6，L16）。
///
/// 用系统根证书 + 可选的额外信任 CA（`trustedCaFile`）。
/// 与 [`client_config`] 的区别只有"验不验证书"。
///
/// # 什么时候用
///
/// * 服务端用的是**受信任 CA 签发的证书**（Let's Encrypt 等）⇒ 直接可用；
/// * 服务端用**自签证书** ⇒ 把该证书填进 `transport.tls.trustedCaFile`，
///   同时 `tlsServerName` 要能对上证书里的名字。
///
/// ★ 注意：开了校验之后，**官方 frpc 默认连不上**（它不校验，但也不提供
///   证书给你）—— 所以这个开关是给"自有客户端 + 自有服务端"的部署用的。
///   双方都配好 CA 即可。
pub fn client_config_verifying(
    trusted_ca_file: &str,
    server_name: &str,
) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();

    // 内置的公开根证书（与 `httpc` 用同一份 `webpki-roots`，
    // 避免"同一个仓库两套根证书来源"）。
    //
    // ★ 不引 `rustls-native-certs`：它会读系统信任库（Windows 证书store /
    //   Linux ca-certificates），覆盖面更广，但**多一个依赖 + 平台差异**；
    //   而本项目已有的 `httpc` 走的就是 `webpki-roots`。保持一致更重要 ——
    //   自签场景本来就必须配 `trustedCaFile`，那时系统根证书帮不上忙。
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    tracing::debug!(
        count = roots.len(),
        "已装载内置公开根证书（自签服务端请配 transport.tls.trustedCaFile）"
    );

    // 用户额外指定的 CA（自签服务端必填）
    if !trusted_ca_file.trim().is_empty() {
        let blocks = read_pem_blocks(trusted_ca_file)?;
        let mut n = 0usize;
        for (_label, der) in blocks.iter().filter(|(l, _)| l == "CERTIFICATE") {
            roots
                .add(rustls::pki_types::CertificateDer::from(der.clone()))
                .with_context(|| format!("{trusted_ca_file} 里的第 {} 个证书无法解析", n + 1))?;
            n += 1;
        }
        if n == 0 {
            bail!("{trusted_ca_file} 里没有 CERTIFICATE 块（可能只给了私钥？）");
        }
        tracing::debug!(count = n, path = %trusted_ca_file, "已装载额外信任 CA");
    }

    if roots.is_empty() {
        bail!(
            "要校验对端证书，但一个可信 CA 都没有：\
             内置根证书为空，且没配 transport.tls.trustedCaFile。\
             自签服务端请把其证书填进 trustedCaFile"
        );
    }

    let cfg = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| anyhow!("TLS 协议版本配置失败：{e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();

    if !server_name.trim().is_empty() {
        tracing::debug!(server_name, "TLS 将校验该名字");
    }
    Ok(Arc::new(cfg))
}

/// 读 PEM 文件，返回 `(块标签, DER 字节)` 的列表，顺序保留。
///
/// 标签是 `CERTIFICATE` / `PRIVATE KEY` / `RSA PRIVATE KEY` / `EC PRIVATE KEY` 这类
/// BEGIN 行里的那个词。**按标签区分私钥格式是必须的** —— 三种格式的 DER 结构不同，
/// 猜错会在握手时才报一个和文件内容完全无关的错。
///
/// 这里是**唯一**一处解析 PEM 的地方：客户端插件的 `crtPath` / `keyPath`
/// 和 OIDC 的 `trustedCaFile` 都走它，省得两处对"什么算合法 PEM"理解不一致。
pub fn read_pem_blocks(path: &str) -> Result<Vec<(String, Vec<u8>)>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let text =
        std::fs::read_to_string(path).with_context(|| format!("读取 PEM 文件 {path} 失败"))?;
    let mut out = Vec::new();
    let mut label: Option<String> = None;
    let mut b64 = String::new();
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("-----BEGIN ") {
            let name = rest.trim_end_matches('-').trim().to_string();
            label = Some(name);
            b64.clear();
            continue;
        }
        if l.starts_with("-----END ") {
            if let Some(name) = label.take() {
                let der = STANDARD
                    .decode(b64.as_bytes())
                    .map_err(|e| anyhow!("PEM 文件 {path} 的 {name} 块不是合法 base64：{e}"))?;
                out.push((name, der));
            }
            continue;
        }
        if label.is_some() {
            b64.push_str(l);
        }
    }
    if out.is_empty() {
        bail!("PEM 文件 {path} 里没有找到任何 -----BEGIN ...----- 块");
    }
    Ok(out)
}

/// 从 PEM 文件构造服务端 TLS 配置（对应官方 frp 的 `transport.NewServerTLSConfig`）。
///
/// 用于客户端的 `https2http` / `https2https` / `tls2raw` 三个插件 —— 它们在
/// frpc 这一侧**终止** TLS，所以要拿用户给的证书自己当 TLS 服务端
/// （frp 的 https 代理与之相反：服务端只嗅探 SNI，不终止 TLS）。
pub fn server_config_from_pem(crt_path: &str, key_path: &str) -> Result<Arc<rustls::ServerConfig>> {
    let certs: Vec<CertificateDer<'static>> = read_pem_blocks(crt_path)?
        .into_iter()
        .filter(|(label, _)| label.eq_ignore_ascii_case("CERTIFICATE"))
        .map(|(_, der)| CertificateDer::from(der))
        .collect();
    if certs.is_empty() {
        bail!("证书文件 {crt_path} 里没有 CERTIFICATE 块");
    }

    let (label, der) = read_pem_blocks(key_path)?
        .into_iter()
        .find(|(label, _)| label.to_ascii_uppercase().contains("PRIVATE KEY"))
        .ok_or_else(|| anyhow!("私钥文件 {key_path} 里没有 PRIVATE KEY 块"))?;
    let key = match label.to_ascii_uppercase().as_str() {
        "PRIVATE KEY" => PrivateKeyDer::Pkcs8(der.into()),
        "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(der.into()),
        "EC PRIVATE KEY" => PrivateKeyDer::Sec1(der.into()),
        other => bail!("私钥文件 {key_path} 的块类型 {other} 不认识"),
    };

    let cfg = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| anyhow!("TLS 协议版本配置失败：{e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| format!("装载证书 {crt_path} + 私钥 {key_path} 失败"))?;
    Ok(Arc::new(cfg))
}

/// 把主机名转成 rustls 的 ServerName（IP 和域名是两种不同的变体）。
fn to_server_name(host: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::from(ip));
    }
    ServerName::try_from(host.to_string()).map_err(|e| anyhow!("无效的 SNI 名称 {host}：{e:?}"))
}

/// 服务端：探测首字节，按需升级到 TLS。
///
/// - `0x17`：frp 自定义首字节，该字节被消费掉，随后是真正的 TLS 握手；
/// - `0x16`：标准 TLS 握手，首字节要还回流里；
/// - 其他：明文连接，首字节要还回流里。
///
/// 泛型化是为了让调用方在 TLS 之前先做一层探测（WebSocket 嗅探就是），
/// 探测读掉的字节可以用 [`PrefixedStream`] 还回来，不影响这里的首字节判断。
pub async fn accept_server<S>(mut stream: S, enable: bool, force: bool) -> Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !enable && !force {
        return Ok(Box::pin(stream));
    }

    let mut first = [0u8; 1];
    let n = tokio::time::timeout(PROBE_TIMEOUT, stream.read_exact(&mut first))
        .await
        .context("等待首字节超时")?
        .context("读取首字节失败")?;
    if n == 0 {
        bail!("连接在对端发送首字节前就关闭了");
    }

    match first[0] {
        FRP_TLS_HEAD_BYTE => {
            let acceptor = TlsAcceptor::from(server_config()?);
            let tls = acceptor
                .accept(stream)
                .await
                .context("TLS 服务端握手失败")?;
            Ok(Box::pin(tls))
        }
        TLS_HANDSHAKE_BYTE => {
            let acceptor = TlsAcceptor::from(server_config()?);
            let tls = acceptor
                .accept(PrefixedStream::new(vec![first[0]], stream))
                .await
                .context("TLS 服务端握手失败")?;
            Ok(Box::pin(tls))
        }
        other => {
            if force {
                bail!("服务端强制 TLS，但收到非 TLS 首字节 0x{other:02x}");
            }
            Ok(Box::pin(PrefixedStream::new(vec![other], stream)))
        }
    }
}

/// 客户端：按需发送 frp 自定义首字节并发起 TLS 握手。
///
/// ★ v0.5.6（L16）：新增 `verify` 参数 —— `false` 走与官方一致的"不校验"
/// （保互通），`true` 走真正校验（需要 `trustedCaFile` 配合自签场景）。
pub async fn connect_client(
    mut stream: TcpStream,
    enable: bool,
    server_name: &str,
    disable_custom_first_byte: bool,
    verify: bool,
    trusted_ca_file: &str,
) -> Result<BoxStream> {
    if !enable {
        return Ok(Box::pin(stream));
    }
    if !disable_custom_first_byte {
        tokio::io::AsyncWriteExt::write_all(&mut stream, &[FRP_TLS_HEAD_BYTE])
            .await
            .context("发送 frp 自定义首字节失败")?;
    }
    let name = to_server_name(server_name)?;
    let cfg = if verify {
        client_config_verifying(trusted_ca_file, server_name)?
    } else {
        client_config()?
    };
    let connector = TlsConnector::from(cfg);
    let tls = connector.connect(name, stream).await.context(if verify {
        "TLS 客户端握手失败（已开启证书校验 —— 若是自签服务端，\
             请把其证书填进 transport.tls.trustedCaFile，\
             并确认 tlsServerName 与证书里的名字一致）"
    } else {
        "TLS 客户端握手失败"
    })?;
    Ok(Box::pin(tls))
}

/// 不校验服务端证书（等价于 frp 的 `InsecureSkipVerify = true`）。
///
/// `pub` 是为了让 OIDC 那边（[`crate::httpc`]）在配了 `insecureSkipVerify`
/// 时复用同一份实现 —— 两边对"不校验"的理解必须完全一致。
#[derive(Debug)]
pub struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }

    fn requires_raw_public_keys(&self) -> bool {
        false
    }
}
