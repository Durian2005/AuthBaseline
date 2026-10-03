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
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

APP_DIR = Path(os.environ.get(
    "E2E_APPDIR",
    os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/AppData/Local"), "AuthBaseline")
))
EXE = APP_DIR / "auth-baseline-desktop.exe"
CDP_PORT = os.environ.get("E2E_CDP_PORT", "9333")


def ssl_context_for(url):
    """https 时返回带**本机 CA 信任锚**的上下文；http 返回 None。

    为什么要固定信任锚而不是 verify=False：桌面端的 leaf 由本机私有 CA 签发，
    把 CA 公钥当信任锚才是"真在验链"；verify=False 等于把 TLS 变成装饰，
    测出来的"成功"没有任何意义，也过不了验收时的追问。
    """
    if not url.lower().startswith("https://"):
        return None
    cert_dir = Path(
        os.environ.get("AUTHBASELINE_CERT_DIR")
        or (Path(os.environ.get("LOCALAPPDATA") or ".") / "AuthBaselineData" / "certs")
    )
    ca = cert_dir / "server.crt"
    if ca.exists():
        return ssl.create_default_context(cafile=str(ca))
    # 找不到公钥时不静默放行：退回默认校验，让失败以"证书错误"的形式暴露出来
    return ssl.create_default_context()


def http_get(url, timeout=3):
    ctx = ssl_context_for(url)
    if ctx is None:
        return urllib.request.urlopen(url, timeout=timeout)
    return urllib.request.urlopen(url, timeout=timeout, context=ctx)


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
            with http_get(
                f"http://127.0.0.1:{CDP_PORT}/json/list", timeout=3
            ) as r:
                targets = json.loads(r.read().decode())
            pages = [t for t in targets if t.get("type") == "page"]
            if pages:
                url = pages[0].get("url", "")
                print(f"页面 URL={url}")
                if "://" in url and "127.0.0.1:" in url:
                    # scheme 必须**沿用页面 URL 的**：桌面端已启用 TLS，
                    # 用 http 去打 https 端口只会得到"连接被重置"，
                    # 极易被误判成"后端没起来"而白查半天。
                    scheme = url.split("//", 1)[0]
                    port = url.split("//", 1)[1].split("/", 1)[0].split(":")[-1]
                    # 等 sidecar 真正开始响应
                    for _ in range(30):
                        try:
                            with http_get(
                                f"{scheme}://127.0.0.1:{port}/favicon.svg", timeout=3
                            ) as rr:
                                print(f"sidecar 就绪 scheme={scheme} HTTP={rr.status}")
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
