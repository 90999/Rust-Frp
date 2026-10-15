//! 临时验证：release profile 下 tokio 任务 panic 是否会拖垮整个进程。
//!
//! 用途（v0.5.6 L17）：确认 `Cargo.toml` 里移除 `panic = "abort"` 之后，
//! 单个任务的 panic 只死那一个任务，进程与其余任务存活。
//!
//! 跑法：`cargo run --release --example panic_isolation`

#[tokio::main]
async fn main() {
    println!("[1] 起一个会 panic 的任务");

    let bad = tokio::spawn(async {
        panic!("这是我故意制造的 panic");
    });

    // 另一个任务：panic 发生后它还必须能继续被调度
    let good = tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        println!("[2] 另一个任务仍在运行 —— 进程没有被 panic 带走");
        "alive"
    });

    // 等那个坏任务结束（unwind 下会拿到 JoinError；abort 下进程根本走不到这里）
    match bad.await {
        Ok(()) => println!("[!] 坏任务居然正常返回了？（不该发生）"),
        Err(e) => {
            if e.is_panic() {
                println!("[3] 坏任务以 JoinError::is_panic 结束 —— tokio 捕获了它");
            } else {
                println!("[3] 坏任务以其他 JoinError 结束：{e}");
            }
        }
    }

    let s = good.await.expect("好任务必须能跑完");
    println!("[4] 好任务结果 = {s}");
    println!("[5] 结论：进程存活 ⇒ panic 被隔离在单个任务内");
}
