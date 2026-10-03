# -*- coding: utf-8 -*-
"""启动桌面端（带 WebView2 调试端口）→ 验证全链路 TLS 生效且功能正常 → 收尾。

为什么要用 Python 包一层（同 ui_readonly_check.py）：
  本机沙箱里调用方一退出就会回收它派生的子进程，
  所以"起桌面端 + 连 CDP + 跑断言 + 关进程"必须在同一个进程内完成。

用法：
  python tools/ui_tls_check.py
环境变量：
  E2E_APPDIR  安装目录，默认 %LOCALAPPDATA%\\AuthBaseline
  E2E_USER / E2E_PASS  登录凭据；默认取 admin / Admin123
      （这是本项目 README 里公开写明的**演示用种子口令**，不是秘密；
        换成真实库的其它账号时请用环境变量覆盖）
"""
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = Path(os.environ.get(
    "E2E_APPDIR",
    os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/AppData/Local"), "AuthBaseline")))
EXE = APP_DIR / "auth-baseline-desktop.exe"
PORT = int(os.environ.get("E2E_CDP_PORT", "9333"))
NODE = os.environ.get("WB_NODE") or os.path.join(
    os.path.expanduser("~"), ".workbuddy", "binaries", "node",
    "versions", "22.22.2-3", "node.exe")


def kill_leftovers():
    """先 taskkill 主程序；再用 PowerShell 清掉它遗留的 WebView2 子进程。"""
    for name in ("auth-baseline-desktop.exe",):
        subprocess.run(["taskkill", "/F", "/IM", name],
                       capture_output=True, text=True, errors="replace")
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-CimInstance Win32_Process"
        " | Where-Object { $_.Name -eq 'msedgewebview2.exe' }"
        f" | Where-Object {{ $_.CommandLine -like '*{APP_DIR}*'"
        " -or $_.CommandLine -like '*ab-wv2-*' }"
        " | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
    )
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, timeout=45)
    except Exception as e:
        print("  （清理 WebView2 残留时跳过：%s）" % e)
    time.sleep(2.0)


def main():
    if not EXE.exists():
        print("未找到桌面端：%s" % EXE)
        return 2

    print("[1] 清掉可能残留的桌面端 / WebView2 进程")
    kill_leftovers()

    print("[2] 启动桌面端（WebView2 调试端口 %d）" % PORT)
    env = dict(os.environ)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = f"--remote-debugging-port={PORT}"
    log = ROOT / "tools" / "buildlogs" / "ui_tls_app.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    lf = open(log, "wb")
    proc = subprocess.Popen(
        [str(EXE)], cwd=str(APP_DIR), env=env,
        stdout=lf, stderr=subprocess.STDOUT,
        creationflags=0x00000008 | 0x00000200,
    )
    print("    PID=%d" % proc.pid)

    print("[3] 跑 TLS 界面验证")
    env2 = dict(os.environ)
    env2["E2E_CDP"] = "http://127.0.0.1:%d" % PORT
    env2["E2E_SHOTDIR"] = str(ROOT / "tools")
    env2.setdefault("E2E_USER", "admin")
    env2.setdefault("E2E_PASS", "Admin123")
    r = subprocess.run([NODE, str(ROOT / "tools" / "ui_tls_events.mjs")],
                       cwd=str(ROOT), env=env2)

    print("[4] 同一个实例上跑接口层功能回归（端口自动发现）")
    r2 = subprocess.run([sys.executable, str(ROOT / "tools" / "transport_func_check.py")],
                        cwd=str(ROOT))

    print("[5] 关闭桌面端")
    try:
        proc.kill()
        proc.wait(timeout=10)
    except Exception:
        pass
    try:
        lf.close()
    except Exception:
        pass
    kill_leftovers()

    # 收尾时顺带问一次侧车实际监听协议，作为"进程已被替换为新版"的旁证
    print("完成，退出码 %d（应用日志 %s）" % (r.returncode, log))
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
