//! Tauri 的构建期钩子。
//!
//! ⚠️ 这里的 `app_manifest(...)` **不是可选项**。
//!
//! Tauri v2 起，应用自己用 `#[tauri::command]` 定义的命令**也要过 ACL**：
//! 没有在应用清单里登记的命令，前端 `invoke` 会得到
//! `xxx not allowed. Plugin not found` —— 注意这句话里没有"未注册"的字眼，
//! 它看起来像是在说某个插件没装，实际上是在说"ACL 里根本没有这条命令的条目"。
//!
//! 这个坑在本项目里潜伏了很久：`get_backend_url` 一直是被拒的，
//! 而 `api/client.js` 拿不到地址时会**静默**回退到同源 `/api` ——
//! 页面本来就是后端托管的，于是回退后一切正常，没人发现那次 invoke 其实失败了。
//! 直到 P7 加了 `otp_compute`（它没有"回退"这回事：算不出来就是算不出来），
//! 才在界面级验证里暴露出来。
//!
//! 新增命令时必须**同时**改两处：这里的清单，以及 `capabilities/default.json`。
fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(
            tauri_build::AppManifest::new()
                // 每加一个 `#[tauri::command]` 就往这里补一个名字（snake_case，与函数名一致）
                .commands(&["get_backend_url", "otp_compute", "otp_verify_challenge"]),
        ),
    )
    .expect("tauri-build 失败");
}
