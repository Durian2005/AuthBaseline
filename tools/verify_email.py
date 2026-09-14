#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
验证"忘记密码"的验证码能否真实投递到邮箱。

做三件事：
  1. 用**安装目录**的后端启动（模拟桌面端真实环境）；
  2. 从启动日志确认发件通道是 SMTP 还是 Console；
  3. 调 /api/auth/send-email-code 真实发一封，报告结果。

用法：
    python tools/verify_email.py <收件邮箱> [用户名]
"""
import json
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

# 默认用安装目录的后端，这才是桌面端实际运行的那一份
APP_DIR = Path(r"<用户目录>\AppData\Local\AuthBaseline")
EXE = APP_DIR / "authserver.exe"
PORT = 5215


def wait_port(port, timeout=40):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.4)
    return False


def req(method, path, body=None, headers=None):
    h = {"Host": "127.0.0.1", "Connection": "close", "Accept": "application/json"}
    data = None
    if body is not None:
        h["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    h["Content-Length"] = str(len(data or b""))
    h.update(headers or {})
    raw = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
    s = socket.create_connection(("127.0.0.1", PORT), timeout=30)
    s.sendall(raw.encode() + (data or b""))
    buf = b""
    while True:
        try:
            c = s.recv(65536)
        except Exception:
            break
        if not c:
            break
        buf += c
    s.close()
    head, _, payload = buf.partition(b"\r\n\r\n")
    htxt = head.decode("latin1")
    if "chunked" in htxt.lower():
        out, rest = b"", payload
        while True:
            line, _, rest = rest.partition(b"\r\n")
            if not line:
                break
            try:
                n = int(line.split(b";")[0], 16)
            except ValueError:
                break
            if n == 0:
                break
            out += rest[:n]
            rest = rest[n + 2:]
        payload = out
    return htxt.split("\r\n")[0], payload


def main():
    if len(sys.argv) < 2:
        print("用法：python tools/verify_email.py <收件邮箱> [用户名]")
        return 1
    to_email = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else "admin"

    print("后端：%s" % EXE)
    print("检查 appsettings.Local.json：%s" % ("存在" if (APP_DIR / "appsettings.Local.json").exists() else "缺失！"))

    log = Path("tools/_email_verify.log")
    with open(log, "w", encoding="utf-8", errors="replace") as lf:
        proc = subprocess.Popen([str(EXE), "--urls", "http://127.0.0.1:%d" % PORT],
                                cwd=str(APP_DIR), stdout=lf, stderr=subprocess.STDOUT)
    try:
        if not wait_port(PORT):
            print("后端未就绪")
            return 1
        time.sleep(1.5)
        text = log.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"\[Email\] 发件通道：(.+)", text)
        ch = m.group(1) if m else "(未捕获到通道信息)"
        print("发件通道：%s" % ch)
        if "控制台" in ch or "Console" in ch:
            print("  ↑ 仍是控制台模式，说明配置没被读到，邮件不会真实投递！")

        st, body = req("POST", "/api/auth/send-email-code",
                       {"purpose": "RESET", "username": username, "email": to_email})
        print("\n发送请求 -> %s" % st)
        try:
            print(json.dumps(json.loads(body), ensure_ascii=False, indent=2))
        except Exception:
            print(body.decode("utf-8", "replace")[:400])

        txt2 = log.read_text(encoding="utf-8", errors="replace")
        if "SmtpEmailSender" in txt2 or "SMTP" in ch:
            print("\n结论：已通过 SMTP 真实投递，请查收邮箱（含垃圾箱）。")
        else:
            print("\n结论：未真实投递，验证码见 tools/_email_verify.log 或 email-codes.log。")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
