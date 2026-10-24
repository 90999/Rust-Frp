//! ★ v0.6.5：真实 IdP 的端到端 OIDC 测试。
//!
//! # 为什么需要它
//!
//! 之前的 27 条 OIDC 测试全是**纯函数级**：DER 编码、base64url、JWT 分段解析。
//! 它们证明不了"这套代码能和**真的 IdP** 说上话"—— 缺少的正是最容易出问题的部分：
//!
//! * discovery 文档的实际字段名与 URL 拼接；
//! * JWKS 里 EC 公钥的 `x`/`y` 编码与 ring 期望的格式是否对得上；
//! * ES256 签名验证的**端到端**链路（header.alg → kid → JWK → ring）；
//! * 密钥轮换后能否重新拉到新密钥；
//! * 恶意 JWKS（畸形 / 空 / 假密钥）会不会被静默接受。
//!
//! # 做法
//!
//! 在本机起一个**最小 HTTP server** 扮演 IdP：提供
//! `/.well-known/openid-configuration` 与 `/jwks`，并用真实的 ECDSA P-256
//! 密钥对签发 JWT。这样整条链路（HTTP 拉取 → JSON 解析 → JWKS → 签名验证）
//! 都被真实地跑一遍。
//!
//! 走的是 `http://127.0.0.1`，因此配置里必须开 `allowInsecureIssuer`——
//! 那正是它存在的理由（生产默认要求 https，见 `discover()` 里的 M9 修复）。

use std::sync::Arc;

use nfrp_common::auth::oidc::{OidcVerifier, ServerOidcConfig};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// 最小 HTTP server（只回固定内容，够 OIDC discovery / JWKS 用）
// ---------------------------------------------------------------------------

/// 起一个只回 JSON 的 server。`routes` 是 (路径, body) 列表。
///
/// 返回 `(base_url, JoinHandle)`。**不用真实框架**：这里只需要"能被 httpc 拉到"，
/// 引入 axum/warp 之类只为测试反而增加依赖面。
async fn spawn_json_server(routes: Vec<(String, String)>) -> (String, tokio::task::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定测试 IdP 失败");
    let addr = l.local_addr().expect("local_addr");
    let routes = Arc::new(routes);

    let h = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                break;
            };
            let routes = routes.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let Ok(n) = s.read(&mut buf).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                // 取请求行里的路径（忽略 query）
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .split('?')
                    .next()
                    .unwrap_or("/")
                    .to_string();

                let found = routes.iter().find(|(p, _)| *p == path);
                let (code, body) = match found {
                    Some((_, b)) => (200, b.clone()),
                    None => (404, "{\"error\":\"not found\"}".to_string()),
                };
                let resp = format!(
                    "HTTP/1.1 {code} {}\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    if code == 200 { "OK" } else { "Not Found" },
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.flush().await;
                let _ = s.shutdown().await;
            });
        }
    });
    (format!("http://{addr}"), h)
}

// ---------------------------------------------------------------------------
// ECDSA P-256 密钥与 JWT
// ---------------------------------------------------------------------------

/// 一把 P-256 签名密钥。
struct SigningKey {
    kid: String,
    pair: EcdsaKeyPair,
}

impl SigningKey {
    /// 生成一把新密钥。用 ring 自己的 `generate_pkcs8`，避免额外依赖。
    fn generate(kid: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("生成 P-256 私钥失败")
                .as_ref()
                .to_vec();
        let pair = EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &pkcs8,
            &rng,
        )
        .expect("载入 P-256 私钥失败");
        Self {
            kid: kid.to_string(),
            pair,
        }
    }
}

fn b64u(b: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(b)
}

/// 把 ECB 公钥的 `x`/`y` 从 ring 的无压缩点里拆出来。
///
/// ring 的 `public_key().as_ref()` 对 P-256 返回 **65 字节**：`0x04 || X(32) || Y(32)`。
fn public_xy(key: &SigningKey) -> (Vec<u8>, Vec<u8>) {
    let p = key.pair.public_key().as_ref();
    assert_eq!(
        p.len(),
        65,
        "P-256 无压缩公钥必须是 65 字节，实际 {}",
        p.len()
    );
    assert_eq!(p[0], 0x04, "首字节应为未压缩点标记 0x04");
    (p[1..33].to_vec(), p[33..65].to_vec())
}

/// 构造一份 JWKS，只含给定的密钥。
fn jwks_doc(keys: &[&SigningKey]) -> String {
    let entries: Vec<String> = keys
        .iter()
        .map(|k| {
            let (x, y) = public_xy(k);
            format!(
                "{{\"kty\":\"EC\",\"crv\":\"P-256\",\"use\":\"sig\",\"alg\":\"ES256\",\
                 \"kid\":\"{}\",\"x\":\"{}\",\"y\":\"{}\"}}",
                k.kid,
                b64u(&x),
                b64u(&y)
            )
        })
        .collect();
    format!("{{\"keys\":[{}]}}", entries.join(","))
}

/// 用给定密钥签一个 JWT（ES256）。
///
/// ring 的 `ECDSA_P256_SHA256_FIXED_SIGNING` 输出 64 字节 `r||s`，
/// 而 JWS 的 ES256 签名格式**正是** `r||s`（不是 DER）—— 这也是选 FIXED 的原因。
fn sign_jwt(key: &SigningKey, claims: &str) -> String {
    let header = format!(
        "{{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"{}\"}}",
        key.kid
    );
    let signing_input = format!("{}.{}", b64u(header.as_bytes()), b64u(claims.as_bytes()));
    let rng = SystemRandom::new();
    let sig = key
        .pair
        .sign(&rng, signing_input.as_bytes())
        .expect("ES256 签名失败");
    format!("{signing_input}.{}", b64u(sig.as_ref()))
}

/// 起一个迷你 IdP，返回 `(issuer, jwks 可变内容, 关闭句柄)`。
///
/// 为了测"密钥轮换"，JWKS 内容必须能改 —— 所以用 `Arc<Mutex<...>>` 共享，
/// 但 server 那边每次请求都重新读，等价于"IdP 换了密钥"。
async fn spawn_idp(
    jwks_shared: Arc<std::sync::Mutex<String>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定测试 IdP 失败");
    let addr = l.local_addr().expect("local_addr");
    let issuer = format!("http://{addr}");
    let issuer_for_doc = issuer.clone();

    let h = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                break;
            };
            let jwks = jwks_shared.clone();
            let issuer = issuer_for_doc.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let Ok(n) = s.read(&mut buf).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .split('?')
                    .next()
                    .unwrap_or("/")
                    .to_string();

                let (code, body) = match path.as_str() {
                    "/.well-known/openid-configuration" => (
                        200,
                        format!(
                            "{{\"issuer\":\"{issuer}\",\"jwks_uri\":\"{issuer}/jwks\",\
                             \"authorization_endpoint\":\"{issuer}/auth\",\
                             \"token_endpoint\":\"{issuer}/token\",\
                             \"id_token_signing_alg_values_supported\":[\"ES256\"]}}"
                        ),
                    ),
                    "/jwks" => (200, jwks.lock().unwrap_or_else(|e| e.into_inner()).clone()),
                    _ => (404, "{\"error\":\"not found\"}".to_string()),
                };
                let resp = format!(
                    "HTTP/1.1 {code} {}\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    if code == 200 { "OK" } else { "Not Found" },
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.flush().await;
                let _ = s.shutdown().await;
            });
        }
    });
    (issuer, h)
}

fn cfg_for(issuer: &str, audience: &str) -> ServerOidcConfig {
    ServerOidcConfig {
        issuer: issuer.to_string(),
        audience: audience.to_string(),
        // 测试里 issuer 是 http://127.0.0.1，必须显式允许明文 ——
        // 生产默认要求 https（见 discover() 的 M9 修复）
        allow_insecure_issuer: true,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

/// ★ 主干：真实 discovery + 真实 JWKS + 真 ES256 签名，验证通过。
#[tokio::test]
async fn 真实_idp_discovery_与_jwks_与_es256_端到端() {
    let key = SigningKey::generate("kid-1");
    let jwks = Arc::new(std::sync::Mutex::new(jwks_doc(&[&key])));
    let (issuer, _h) = spawn_idp(jwks).await;

    let v = OidcVerifier::new(cfg_for(&issuer, "nfrp-test")).expect("构造验证器");
    v.refresh().await.expect("拉取 discovery + JWKS 失败");

    let now = nfrp_common::util::now_unix_secs();
    let claims = format!(
        "{{\"iss\":\"{issuer}\",\"aud\":\"nfrp-test\",\"sub\":\"alice\",\
         \"exp\":{},\"iat\":{}}}",
        now + 3600,
        now
    );
    let tok = sign_jwt(&key, &claims);

    let v2 = v.verify_token(&tok).expect("真实签名必须验证通过");
    assert_eq!(v2.get("sub").and_then(|x| x.as_str()), Some("alice"));
}

/// ★ 密钥轮换：IdP 换了密钥后，`refresh()` 必须能拉到新 key 并验证新 token。
///
/// 这是"长时间运行的进程"必须过的关：IdP 定期轮换签名密钥，
/// 如果只在启动时拉一次，几小时后就所有 token 都验不过。
#[tokio::test]
async fn 真实_idp_密钥轮换后仍能验证() {
    let k1 = SigningKey::generate("kid-old");
    let shared = Arc::new(std::sync::Mutex::new(jwks_doc(&[&k1])));
    let (issuer, _h) = spawn_idp(shared.clone()).await;

    let v = OidcVerifier::new(cfg_for(&issuer, "")).expect("构造验证器");
    v.refresh().await.expect("首次拉 JWKS");

    let now = nfrp_common::util::now_unix_secs();
    let claims = format!(
        "{{\"iss\":\"{issuer}\",\"sub\":\"bob\",\"exp\":{}}}",
        now + 3600
    );
    // 旧密钥能验过
    assert!(v.verify_token(&sign_jwt(&k1, &claims)).is_ok());

    // IdP 轮换：换成一把全新密钥（旧 kid 消失）
    let k2 = SigningKey::generate("kid-new");
    *shared.lock().unwrap_or_else(|e| e.into_inner()) = jwks_doc(&[&k2]);

    // 新 token 用新 key 签，但本地缓存还只有旧 key ⇒ 现在应当失败
    let new_tok = sign_jwt(&k2, &claims);
    assert!(
        v.verify_token(&new_tok).is_err(),
        "还没刷新就不该验过新密钥签的 token（否则说明缓存没生效）"
    );

    // 刷新后就能验过
    v.refresh().await.expect("轮换后拉 JWKS 失败");
    let ok = v
        .verify_token(&new_tok)
        .expect("刷新后新密钥签的 token 必须能验过");
    assert_eq!(ok.get("sub").and_then(|x| x.as_str()), Some("bob"));
}

/// 未知 kid（签名密钥不在 JWKS 里）必须拒绝 —— 不能"找不到 key 就放行"。
#[tokio::test]
async fn 未知_kid_必须拒绝() {
    let key = SigningKey::generate("kid-known");
    let other = SigningKey::generate("kid-unknown");
    let jwks = Arc::new(std::sync::Mutex::new(jwks_doc(&[&key])));
    let (issuer, _h) = spawn_idp(jwks).await;

    let v = OidcVerifier::new(cfg_for(&issuer, "")).expect("构造验证器");
    v.refresh().await.expect("拉 JWKS");

    let now = nfrp_common::util::now_unix_secs();
    let claims = format!(
        "{{\"iss\":\"{issuer}\",\"sub\":\"x\",\"exp\":{}}}",
        now + 3600
    );
    let tok = sign_jwt(&other, &claims);
    assert!(
        v.verify_token(&tok).is_err(),
        "签名密钥不在 JWKS 里时必须拒绝"
    );
}

/// 签名被改一个字节必须拒绝（防止"验签算了但没比对结果"这类低级错误）。
#[tokio::test]
async fn 签名被篡改必须拒绝() {
    let key = SigningKey::generate("kid-1");
    let jwks = Arc::new(std::sync::Mutex::new(jwks_doc(&[&key])));
    let (issuer, _h) = spawn_idp(jwks).await;

    let v = OidcVerifier::new(cfg_for(&issuer, "")).expect("构造验证器");
    v.refresh().await.expect("拉 JWKS");

    let now = nfrp_common::util::now_unix_secs();
    let claims = format!(
        "{{\"iss\":\"{issuer}\",\"sub\":\"x\",\"exp\":{}}}",
        now + 3600
    );
    let tok = sign_jwt(&key, &claims);
    assert!(v.verify_token(&tok).is_ok(), "原签名应当通过");

    // 改签名的最后一个字符
    let mut tampered = tok.clone();
    let last = tampered.pop().expect("非空");
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    assert!(v.verify_token(&tampered).is_err(), "篡改签名必须拒绝");
}

/// 恶意 JWKS：空 keys 必须**明确报错**，不能当成"没有密钥于是全放行"。
#[tokio::test]
async fn 恶意_jwks_空密钥集要报错() {
    let shared = Arc::new(std::sync::Mutex::new("{\"keys\":[]}".to_string()));
    let (issuer, _h) = spawn_idp(shared).await;

    let v = OidcVerifier::new(cfg_for(&issuer, "")).expect("构造验证器");
    let err = v.refresh().await.expect_err("空 JWKS 必须被拒");
    assert!(
        err.to_string().contains("没有任何密钥"),
        "错误信息要说清是空密钥集：{err}"
    );
}

/// 恶意 JWKS：畸形 JSON 必须报错。
#[tokio::test]
async fn 恶意_jwks_畸形_json_要报错() {
    let shared = Arc::new(std::sync::Mutex::new("this is not json".to_string()));
    let (issuer, _h) = spawn_idp(shared).await;

    let v = OidcVerifier::new(cfg_for(&issuer, "")).expect("构造验证器");
    assert!(v.refresh().await.is_err(), "畸形 JWKS 必须被拒");
}

/// 恶意 JWKS：`x`/`y` 是垃圾 base64 时，验证必须失败而不是 panic。
#[tokio::test]
async fn 恶意_jwks_垃圾坐标不崩溃() {
    let bogus = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"kid-1\",\
                  \"x\":\"!!!not-base64!!!\",\"y\":\"$$$$\"}]}";
    let shared = Arc::new(std::sync::Mutex::new(bogus.to_string()));
    let (issuer, _h) = spawn_idp(shared).await;

    let v = OidcVerifier::new(cfg_for(&issuer, "")).expect("构造验证器");
    // refresh 可能成功（JSON 结构合法），但用该 key 验签必须失败
    let _ = v.refresh().await;
    let now = nfrp_common::util::now_unix_secs();
    let claims = format!(
        "{{\"iss\":\"{issuer}\",\"sub\":\"x\",\"exp\":{}}}",
        now + 3600
    );
    let fake = SigningKey::generate("kid-1");
    let tok = sign_jwt(&fake, &claims);
    assert!(
        v.verify_token(&tok).is_err(),
        "垃圾坐标的公钥不能验过任何签名"
    );
}

/// discovery 文档缺失 `jwks_uri` 时必须报错。
#[tokio::test]
async fn discovery_缺_jwks_uri_要报错() {
    let (base, _h) = spawn_json_server(vec![(
        "/.well-known/openid-configuration".to_string(),
        "{\"issuer\":\"http://x\"}".to_string(),
    )])
    .await;
    let v = OidcVerifier::new(cfg_for(&base, "")).expect("构造验证器");
    assert!(
        v.refresh().await.is_err(),
        "没有 jwks_uri 就无从拉公钥，必须报错"
    );
}

/// ★ 安全：`jwks_uri` 是明文 http 时，**默认配置必须拒绝**（M9 修复的回归门）。
///
/// 这条不能漏：JWKS 是公钥，走明文被中间人替换就等于认证被完全绕过。
#[tokio::test]
async fn 明文_jwks_uri_默认必须拒绝() {
    let key = SigningKey::generate("kid-1");
    let shared = Arc::new(std::sync::Mutex::new(jwks_doc(&[&key])));
    let (issuer, _h) = spawn_idp(shared).await;

    // 注意：这里**故意不开** allow_insecure_issuer
    let mut cfg = cfg_for(&issuer, "");
    cfg.allow_insecure_issuer = false;

    let v = OidcVerifier::new(cfg).expect("构造验证器");
    let err = v.refresh().await.expect_err("明文 jwks_uri 默认必须拒绝");
    let msg = err.to_string();
    assert!(msg.contains("https"), "错误要指明要求 https：{msg}");
}
