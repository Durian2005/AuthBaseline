# -*- coding: utf-8 -*-
"""启动桌面端（带 WebView2 调试端口）→ 跑界面验证 → 收尾。

为什么要用 Python 包一层：
  本机沙箱里调用方 shell 一退出就会回收它派生的子进程，
  所以"起桌面端 + 连 CDP + 跑断言 + 关进程"必须在同一个进程内完成。

用法：
  python tools/ui_audit_check.py [--no-seed]
环境变量：
  E2E_APPDIR  安装目录，默认 %LOCALAPPDATA%\\AuthBaseline

⚠️ 本脚本会**向真实库写入 1 条审计**：跑断言前先发一次改密请求自造「改密失败」记录
   （见 ui_audit_events.mjs 顶部说明）。造法是最温和的一条路径 —— 新旧口令传同一个值，
   后端稳定走到 PASSWORD_REUSED 分支，只记失败，**不改口令、不累加失败次数、不触发锁定**。
   --no-seed 可跳过写库（此时若库里没有改密失败记录，相关断言会失败）。
"""
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _toolchain import find_node  # noqa: E402  （同目录公共模块）

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = Path(os.environ.get("E2E_APPDIR", os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/AppData/Local"), "AuthBaseline")))
EXE = APP_DIR / "auth-baseline-desktop.exe"
PORT = 9333
NODE = find_node()


def kill_leftovers():
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-Process -Name 'auth-baseline-desktop' | Stop-Process -Force;"
        "Get-CimInstance Win32_Process"
        " | Where-Object { $_.Name -eq 'msedgewebview2.exe' }"
        f" | Where-Object {{ $_.CommandLine -like '*{APP_DIR}*'"
        " -or $_.CommandLine -like '*ab-wv2-*' }"
        " | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, timeout=60)
    time.sleep(2.5)


def main():
    if not EXE.exists():
        print("未找到桌面端：%s" % EXE)
        return 2

    print("[1] 清掉可能残留的桌面端 / WebView2 进程")
    kill_leftovers()

    print("[2] 启动桌面端（WebView2 调试端口 %d）" % PORT)
    env = dict(os.environ)
    # WebView2 通过这个环境变量接收 Chromium 参数，比传命令行可靠
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = f"--remote-debugging-port={PORT}"
    log = ROOT / "tools" / "buildlogs" / "ui_audit_app.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    lf = open(log, "wb")
    proc = subprocess.Popen(
        [str(EXE)], cwd=str(APP_DIR), env=env,
        stdout=lf, stderr=subprocess.STDOUT,
        creationflags=0x00000008 | 0x00000200,
    )
    print("    PID=%d" % proc.pid)

    print("[3] 跑界面验证")
    env2 = dict(os.environ)
    env2["E2E_CDP"] = "http://127.0.0.1:%d" % PORT
    env2["E2E_SHOTDIR"] = str(ROOT / "tools" / "evidence")
    if "--no-seed" in sys.argv:
        env2["E2E_NO_SEED"] = "1"
        print("    --no-seed：本次不写库，改为只读验证")
    r = subprocess.run(
        [NODE, str(ROOT / "tools" / "ui_audit_events.mjs")],
        cwd=str(ROOT), env=env2,
    )

    print("[4] 关闭桌面端")
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
    print("完成，退出码 %d（日志 %s）" % (r.returncode, log))
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
