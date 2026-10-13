//! stcp / xtcp 的 **visitor 接入表**。
//!
//! 与 tcp / udp / http 不同，stcp / xtcp 的 provider **不在公网上开端口**：
//! 服务端只为它登记一条记录（`provider 的工作连接来源 + 共享密钥`），
//! 等 visitor 主动连进来时再校验密钥、把双方配对。
//!
//! 对应官方 frps 的 `server/visitor.Manager` + `proxy.startVisitorListener`。

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::ClientState;

/// 一条已注册的 stcp / xtcp 代理（等待 visitor 来连）。
pub struct VisitorEntry {
    pub proxy_name: String,
    /// provider 配置的共享密钥；visitor 的签名必须由它算出。
    pub secret_key: String,
    /// 允许接入的访客列表；为空时退化为"只允许 provider 自己的 user"。
    pub allow_users: Vec<String>,
    /// provider 客户端在 `Login` 里声明的顶层 `user`（`allow_users` 为空时的默认白名单）。
    pub provider_user: String,
    /// provider 所属的客户端，配对工作连接时要用它去要连接。
    pub client: Arc<ClientState>,
    /// `stcp` / `xtcp` / `sudp`（仅用于日志/遥测）。
    pub proxy_type: String,
}

impl VisitorEntry {
    /// 校验 visitor 的签名：`hex(md5(secret_key + timestamp))`。
    pub fn check_sign(&self, sign_key: &str, timestamp: i64) -> bool {
        let expected = nfrp_common::frp::msg::auth_key(&self.secret_key, timestamp);
        nfrp_common::frp::msg::constant_time_eq(&expected, sign_key)
    }

    /// 校验访客用户是否被允许，语义与官方 frps 完全一致：
    ///
    /// ```text
    /// if allowUsers == [] { allowUsers = [provider.User] }   // 空 → 只允许同一 user
    /// allow  <=>  allowUsers 含 visitorUser  或  allowUsers 含 "*"
    /// ```
    ///
    /// 注意比对的是**访问方 frpc 顶层的 `user`**（`Login.User`），不是 `[[visitors]]` 的 `name`。
    pub fn check_user(&self, visitor_user: &str) -> bool {
        if self.allow_users.is_empty() {
            return self.provider_user == visitor_user;
        }
        self.allow_users
            .iter()
            .any(|u| u == "*" || u == visitor_user)
    }
}

/// 一条 stcp / xtcp 代理的只读快照（给面板 / API 用）。
#[derive(Debug, Clone)]
pub struct VisitorInfo {
    pub proxy_name: String,
    pub proxy_type: String,
    pub provider_user: String,
    pub allow_users: Vec<String>,
    pub client_id: String,
}

/// 全局的 visitor 表（按代理名索引）。
#[derive(Default)]
pub struct VisitorTable {
    inner: Mutex<HashMap<String, Arc<VisitorEntry>>>,
}

impl VisitorTable {
    /// 注册一条 stcp / xtcp 代理；同名重复注册会失败（与 frp 的 "repeated" 行为一致）。
    pub fn register(&self, entry: VisitorEntry) -> Result<(), String> {
        let name = entry.proxy_name.clone();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.contains_key(&name) {
            return Err(format!("custom listener for [{name}] is repeated"));
        }
        g.insert(name, Arc::new(entry));
        Ok(())
    }

    /// 按代理名查一条记录。
    pub fn get(&self, name: &str) -> Option<Arc<VisitorEntry>> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .cloned()
    }

    /// 客户端主动 `CloseProxy` 时摘掉一条记录，之后同名代理可以重新注册。
    ///
    /// ★★ v0.5.5 修（第四轮 B-1）：**必须同时比客户端身份，不能只比名字**。
    ///
    /// 这是第四轮 H1 的**同一个根因、漏掉的第二处**：
    /// vhost 的三处判定在 H1 里补上了客户端身份，而本函数漏了。
    /// 注意**同一个文件里** `unregister_client`（下面）一直是对的
    /// —— 用的是 `Arc::ptr_eq(&e.client, client)`。
    ///
    /// 原先只按名字摘的后果：客户端 A 发一条
    /// `CloseProxy("{victim}.{name}")` 就能摘掉**受害者 B** 的 stcp/xtcp 注册记录
    /// ⇒ B 的私密隧道对新 visitor 立即失效（B 自己的客户端还活着、日志无异常）。
    /// 而且 `register` 只在"名字已存在"时失败，所以摘掉之后攻击者还能把
    /// **自己的**记录注册到那个名字上，让 B 的隧道彻底连不上（DoS）。
    ///
    /// 与 H1 的 `remove_proxy` 面完全同构：**一次不需要任何权限的跨租户拒绝服务**。
    pub fn remove(&self, client: &Arc<ClientState>, name: &str) -> Option<Arc<VisitorEntry>> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // 先确认这条记录确实属于这个客户端，再摘 —— 不能"先删了再看是谁的"
        match g.get(name) {
            Some(e) if Arc::ptr_eq(&e.client, client) => g.remove(name),
            _ => None,
        }
    }

    /// 全部 stcp / xtcp 代理的快照（面板展示用）。
    pub fn list(&self) -> Vec<VisitorInfo> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|e| VisitorInfo {
                proxy_name: e.proxy_name.clone(),
                proxy_type: e.proxy_type.clone(),
                provider_user: e.provider_user.clone(),
                allow_users: e.allow_users.clone(),
                client_id: e.client.client_id().to_string(),
            })
            .collect()
    }

    /// 客户端断开时回收它的全部 stcp / xtcp 代理。
    pub fn unregister_client(&self, client: &Arc<ClientState>) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, e| !Arc::ptr_eq(&e.client, client));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::dummy_client;

    fn entry(name: &str, client: &Arc<ClientState>) -> VisitorEntry {
        VisitorEntry {
            proxy_name: name.to_string(),
            secret_key: "sk".to_string(),
            allow_users: Vec::new(),
            provider_user: "u".to_string(),
            client: client.clone(),
            proxy_type: "stcp".to_string(),
        }
    }

    /// 持有者自己能摘掉自己的记录。
    #[test]
    fn 持有者可以摘掉自己的_visitor_记录() {
        let t = VisitorTable::default();
        let me = dummy_client("me");
        t.register(entry("u.sec1", &me)).expect("注册");
        assert!(t.get("u.sec1").is_some());

        assert!(t.remove(&me, "u.sec1").is_some(), "持有者应当能摘掉");
        assert!(t.get("u.sec1").is_none(), "摘掉之后查不到了");
    }

    /// ★★ B-1 核心回归：**别的租户不能按名字摘掉我的记录**。
    ///
    /// 修复前 `remove` 只比名字 ⇒ 攻击者发一条
    /// `CloseProxy("u.sec1")` 就能摘掉受害者的 stcp 注册记录，
    /// 之后还能把**自己的**记录注册到那个名字上（`register` 只在重名时失败），
    /// 让受害者的私密隧道彻底连不上 —— 一次不需要任何权限的跨租户 DoS。
    #[test]
    fn 别的租户不得按名字摘掉我的_visitor_记录() {
        let t = VisitorTable::default();
        let victim = dummy_client("victim-run");
        let attacker = dummy_client("attacker-run");
        t.register(entry("victim.sec1", &victim))
            .expect("受害者注册");

        // 攻击者按名字摘 —— 必须失败（摘不到任何东西）
        assert!(
            t.remove(&attacker, "victim.sec1").is_none(),
            "攻击者不该能摘掉别人的记录"
        );
        assert!(t.get("victim.sec1").is_some(), "受害者的记录必须还在");

        // 而且攻击者也不能趁机把同名记录据为己有（register 会因重名失败）
        assert!(
            t.register(entry("victim.sec1", &attacker)).is_err(),
            "重名注册应当失败，攻击者不能抢占受害者的名字"
        );
        // 确认表里那条仍然属于受害者
        assert!(
            Arc::ptr_eq(&t.get("victim.sec1").unwrap().client, &victim),
            "记录必须仍归受害者"
        );
    }

    /// 断开清理只清自己的（这个函数一直都写对了，锁住防回退）。
    #[test]
    fn 断开只清自己的_visitor_记录() {
        let t = VisitorTable::default();
        let a = dummy_client("a");
        let b = dummy_client("b");
        t.register(entry("a.s", &a)).unwrap();
        t.register(entry("b.s", &b)).unwrap();

        t.unregister_client(&a);
        assert!(t.get("a.s").is_none(), "自己的应当被清掉");
        assert!(t.get("b.s").is_some(), "别人的不该被清掉");
    }
}
