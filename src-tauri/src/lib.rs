//! 口令认证基线系统 · 桌面端（Tauri v2）
//!
//! 职责：把 .NET 后端（AuthServer）当作 sidecar 子进程托管起来。
//!   - 应用启动 → 自动拉起后端
//!   - 窗口关闭 / 应用退出 → 自动终止后端进程，不留残留
//!   - 后端地址通过 IPC 命令 `get_backend_url` 下发给前端
//!
//! ⚠️ 关于 `tauri.conf.json` 的 `additionalBrowserArgs`（踩过的坑，别再改回去）：
//!   历史上这里带过 `--single-process`，在 WebView2 Runtime **155** 上会直接
//!   把渲染链路搞崩 —— 窗口出现一两秒（白屏，页面还没渲染完）就被销毁，
//!   用户看到的现象是「白屏 + 闪退」，且**没有任何错误信息**。
//!   Chromium 从未支持 `--single-process`（官方明确不推荐），不要因为
//!   "省内存/少进程"再把它加回来。诊断方法：`EnumWindows` 按 pid 采窗口，
//!   会看到 `Tauri Window` 在几秒后从列表里消失，而进程还活着。

use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tauri::{Manager, RunEvent, State, WindowEvent};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

/// sidecar 名称，对应 src-tauri/binaries/authserver-<target-triple>[.exe]
const SIDECAR_NAME: &str = "authserver";

/// 等待后端就绪的最长时间
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// 后端子进程句柄 + 监听地址
struct BackendState {
    child: Mutex<Option<CommandChild>>,
    url: Mutex<String>,
}

/// 供前端调用：返回 sidecar 后端的监听地址，例如 `https://127.0.0.1:52341`
#[tauri::command]
fn get_backend_url(state: State<'_, BackendState>) -> String {
    state.url.lock().unwrap().clone()
}

/// 后端该用哪个 scheme（https / http）。
///
/// 为什么需要这个函数而不是直接写死 `https`：后端有一个显式的对照实验开关
/// `Transport:RequireHttps=false`，打开它后端就会**退回明文 HTTP**。
/// 此时若壳仍然导航到 `https://...`，TLS 握不上手，用户看到的是一个**白窗口** ——
/// 没有任何错误信息可看。所以两边必须得出同一个结论。
///
/// 取值优先级（与后端的取值优先级刻意保持一致）：
///   ① 环境变量 `AUTHBASELINE_REQUIRE_HTTPS`（会被 sidecar 继承，两边自动一致）
///   ② 程序目录下的 `appsettings.json` 的 `Transport.RequireHttps`
///   ③ 默认 `https` —— **默认必须是加密的**，不能是"配错了就悄悄明文"
fn resolve_scheme() -> &'static str {
    if let Ok(v) = std::env::var("AUTHBASELINE_REQUIRE_HTTPS") {
        let v = v.trim().to_ascii_lowercase();
        if v == "0" || v == "false" {
            return "http";
        }
        if v == "1" || v == "true" {
            return "https";
        }
    }

    // 桌面端启动时已把 cwd 切到程序目录，而 appsettings.json 由 bundle.resources 随包就位，
    // 所以这里读到的就是后端将要读的那一份。
    if let Ok(text) = std::fs::read_to_string("appsettings.json") {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(on) = json
                .get("Transport")
                .and_then(|t| t.get("RequireHttps"))
                .and_then(|v| v.as_bool())
            {
                return if on { "https" } else { "http" };
            }
        }
    }

    "https"
}

/// 向操作系统申请一个空闲端口：绑定 :0 后立刻读取并释放。
/// 这样即使开发时手动 `dotnet run` 占着 5007，桌面端也不会冲突。
fn pick_free_port() -> Option<u16> {
    TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|listener| listener.local_addr().ok())
        .map(|addr| addr.port())
}

/// 轮询探测端口，直到后端开始监听或超时
fn wait_for_backend(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// 终止 sidecar 后端进程
fn kill_backend(app: &tauri::AppHandle) {
    if let Some(state) = app.try_state::<BackendState>() {
        if let Some(child) = state.child.lock().unwrap().take() {
            match child.kill() {
                Ok(()) => println!("[backend] 进程已随应用退出而终止"),
                Err(e) => eprintln!("[backend] 终止进程失败：{e}"),
            }
        }
    }
}

pub fn run() {
    // 无论从快捷方式、安装器还是终端启动，都统一以程序所在目录作为工作目录。
    // 这样 sidecar 可稳定找到同目录随附的 appsettings.json 与 wwwroot 静态资源。
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(app_dir) = exe_path.parent() {
            if let Err(e) = std::env::set_current_dir(app_dir) {
                eprintln!("[app] 无法切换到程序目录：{e}");
            }
        }
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![get_backend_url])
        .setup(|app| {
            let port = pick_free_port().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "无法为后端分配空闲端口",
                )
            })?;
            let scheme = resolve_scheme();
            let url = format!("{scheme}://127.0.0.1:{port}");
            let bind = format!("{scheme}://127.0.0.1:{port}");
            println!("[backend] scheme={scheme}（Transport:RequireHttps 决定）");

            // 启动 .NET 后端 sidecar，并通过 --urls 指定它监听的地址
            let (mut rx, child) = app
                .shell()
                .sidecar(SIDECAR_NAME)?
                .args(["--urls", &bind])
                .spawn()
                .map_err(|e| std::io::Error::other(format!("启动后端 sidecar 失败：{e}")))?;

            // 转发后端日志，便于排查（例如 MongoDB 没启动）
            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stdout(line) => {
                            print!("[backend] {}", String::from_utf8_lossy(&line))
                        }
                        CommandEvent::Stderr(line) => {
                            eprint!("[backend] {}", String::from_utf8_lossy(&line))
                        }
                        CommandEvent::Terminated(payload) => {
                            println!("[backend] 进程退出，code={:?}", payload.code)
                        }
                        _ => {}
                    }
                }
            });

            app.manage(BackendState {
                child: Mutex::new(Some(child)),
                url: Mutex::new(url.clone()),
            });

            // Windows 上部分 WebView2/Tauri 组合会把内置资源协议解析成无端口的
            // localhost，从而出现 ERR_CONNECTION_REFUSED。后端就绪后直接导航到
            // sidecar 的本机地址，可同时提供前端静态资源与 API，避免该兼容性问题。
            //
            // ⚠️ scheme 为 https 时 WebView2 会**校验证书链**：CA 必须在本机根存储里，
            // 否则整个界面连壳都渲染不出来（白窗口、无任何错误信息）。
            // 证书的签发与信任写入见后端的 CertificateManager ——
            // 产品路径是 NSIS 安装期写 LocalMachine\Root，开发态退化写 CurrentUser\Root。
            // 先把窗口拿到手：即使后端起不来，也要有窗口能显示原因，
            // 而不是窗口一闪即没、用户只看到"白屏 + 闪退"。
            let window = app.get_webview_window("main").ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "未找到主窗口")
            })?;

            if !wait_for_backend(port, STARTUP_TIMEOUT) {
                // 旧实现直接 return Err：setup 失败 → 进程退出、窗口消失，
                // 用户那边只看到"白屏 + 闪退"，且看不出任何原因。
                // 现在把原因直接画在窗口里，不再退出。
                let html = format!(
                    "<div style=\"font-family:system-ui,'Segoe UI',sans-serif;padding:56px;\
                     color:#e5e7eb;background:#0f172a;height:100vh;box-sizing:border-box\">\
                     <h1 style=\"font-size:20px;margin:0 0 14px;font-weight:600\">后端未能在 {} 秒内启动</h1>\
                     <p style=\"margin:0 0 10px;line-height:1.8\">桌面端已拉起 sidecar，但没有等到它开始监听。<br>\
                     常见原因：本机 MongoDB 服务未启动。</p>\
                     <p style=\"margin:0;color:#94a3b8\">后端地址：{}</p></div>",
                    STARTUP_TIMEOUT.as_secs(),
                    url
                );
                let js = format!(
                    "document.body.innerHTML = {};",
                    serde_json::to_string(&html).unwrap_or_else(|_| "\"\"".to_string())
                );
                let _ = window.eval(&js);
                eprintln!("[backend] 启动超时：已在窗口内显示原因（不再直接退出）");
                return Ok(());
            }
            println!("[backend] 已就绪：{url}");

            // 窗口本该自己显示；这里显式 show 一下，免得个别环境下窗口停在隐藏/最小化态，
            // 用户只看到任务栏图标却以为"闪退"。（幂等操作，无副作用）
            let _ = window.show();
            println!("[window] 主窗口存在，开始导航到 {url}");
            window.navigate(url.parse().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("后端地址无效：{e}"))
            })?)?;
            println!("[window] navigate() 已提交（异步，失败不会在此报错）");

            Ok(())
        })
        // 单窗口应用：窗口销毁即代表用户关闭了应用
        .on_window_event(|window, event| {
            // 排障用：窗口被谁销毁、什么时候销毁，全部留痕
            println!("[window] 事件：{event:?}");
            if matches!(event, WindowEvent::Destroyed) {
                kill_backend(window.app_handle());
            }
        })
        .build(tauri::generate_context!())
        .expect("构建 Tauri 应用失败")
        .run(|app_handle, event| {
            // 兜底：任何退出路径都确保后端进程被回收
            if matches!(event, RunEvent::Exit) {
                kill_backend(app_handle);
            }
        });
}
