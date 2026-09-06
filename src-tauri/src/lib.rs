//! 口令认证基线系统 · 桌面端（Tauri v2）
//!
//! 职责：把 .NET 后端（AuthServer）当作 sidecar 子进程托管起来。
//!   - 应用启动 → 自动拉起后端
//!   - 窗口关闭 / 应用退出 → 自动终止后端进程，不留残留
//!   - 后端地址通过 IPC 命令 `get_backend_url` 下发给前端

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

/// 供前端调用：返回 sidecar 后端的监听地址，例如 `http://127.0.0.1:52341`
#[tauri::command]
fn get_backend_url(state: State<'_, BackendState>) -> String {
    state.url.lock().unwrap().clone()
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
            let url = format!("http://127.0.0.1:{port}");
            let bind = format!("http://127.0.0.1:{port}");

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
            // sidecar 的本机 HTTP 地址，可同时提供前端静态资源与 API，避免该兼容性问题。
            if !wait_for_backend(port, STARTUP_TIMEOUT) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("后端启动超时（{}s），请确认 MongoDB 服务已启动。", STARTUP_TIMEOUT.as_secs()),
                ).into());
            }
            println!("[backend] 已就绪：{url}");

            let window = app.get_webview_window("main").ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "未找到主窗口")
            })?;
            window.navigate(url.parse().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("后端地址无效：{e}"))
            })?)?;

            Ok(())
        })
        // 单窗口应用：窗口销毁即代表用户关闭了应用
        .on_window_event(|window, event| {
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
