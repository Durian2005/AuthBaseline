"""启动桌面程序并等待就绪，输出 sidecar 动态端口。

为什么要单独写：桌面壳会把 sidecar 后端拉起在**随机端口**上，
自动化验证必须先把该端口问出来（通过 WebView2 调试端口的 /json/list，
或直接扫 sidecar 进程的监听端口）。

用法：
  python tools/launch_desktop.py
输出（stdout 末行）：
  PORT=<端口>
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

APP_DIR = Path(os.environ.get(
    "E2E_APPDIR",
    r"<用户目录>\AppData\Local\AuthBaseline"
))
EXE = APP_DIR / "auth-baseline-desktop.exe"
CDP_PORT = os.environ.get("E2E_CDP_PORT", "9333")


def main():
    if not EXE.exists():
        print(f"未找到桌面程序：{EXE}")
        return 2

    # 调试参数必须在进程创建前进入环境
    env = dict(os.environ)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={CDP_PORT} --remote-allow-origins=*"
    )

    # DETACHED_PROCESS 让子进程脱离父控制台，避免随调用方退出被回收
    DETACHED_PROCESS = 0x00000008
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    proc = subprocess.Popen(
        [str(EXE)],
        cwd=str(APP_DIR),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
        close_fds=True,
    )
    print(f"桌面壳已启动 PID={proc.pid}")

    # 轮询 WebView2 调试端口，拿到页面 URL（即 sidecar 地址）
    deadline = time.time() + 40
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{CDP_PORT}/json/list", timeout=3
            ) as r:
                targets = json.loads(r.read().decode())
            pages = [t for t in targets if t.get("type") == "page"]
            if pages:
                url = pages[0].get("url", "")
                print(f"页面 URL={url}")
                if "://" in url and "127.0.0.1:" in url:
                    port = url.split("//", 1)[1].split("/", 1)[0].split(":")[-1]
                    # 等 sidecar 真正开始响应
                    for _ in range(30):
                        try:
                            with urllib.request.urlopen(
                                f"http://127.0.0.1:{port}/favicon.svg", timeout=3
                            ) as rr:
                                print(f"sidecar 就绪 HTTP={rr.status}")
                                print(f"PORT={port}")
                                return 0
                        except Exception:
                            time.sleep(0.4)
                    print(f"PORT={port}")
                    return 0
        except Exception:
            pass
        time.sleep(0.5)

    print("等待 WebView2 调试端口超时")
    return 1


if __name__ == "__main__":
    sys.exit(main())
