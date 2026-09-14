#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
在同一进程内启动后端 → 等就绪 → 调 /api/audit/verify → 打印结果 → 关闭。

为什么必须"同进程"：本机沙箱里，调用方 shell 退出会回收其派生的子进程，
nohup 也拦不住（已被实测验证）。所以验证接口这类需要后端在线的操作，
必须把"起服务 + 打接口 + 收尾"放在一个进程里完成，避免 TCP 拒绝连接。
"""
import json
import subprocess
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "AuthServer" / "publish" / "AuthServer.exe"
PORT = 5210


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
    s = socket.create_connection(("127.0.0.1", PORT), timeout=20)
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
    head_txt = head.decode("latin1")
    # 处理 chunked：按块长度拼接
    if "Transfer-Encoding: chunked" in head_txt:
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
    return head_txt.split("\r\n")[0], payload


def main():
    print("启动后端 %s" % EXE)
    proc = subprocess.Popen(
        [str(EXE), "--urls", f"http://127.0.0.1:{PORT}"],
        cwd=str(EXE.parent),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_port(PORT):
            print("后端未能在超时内监听端口")
            return 1
        print("后端已就绪")

        st, body = req("POST", "/api/auth/login", {"username": "admin", "password": "Admin123"})
        print("登录 ->", st)
        j = json.loads(body)
        d = j.get("data") or j.get("Data") or {}
        tok = d.get("ticket") or d.get("Ticket") or d.get("token") or d.get("Token")
        if not tok:
            print("未能取得票据，登录响应：", json.dumps(j, ensure_ascii=False)[:400])
            return 1

        st2, body2 = req("GET", "/api/audit/verify", headers={"Authorization": "Bearer " + tok})
        print("完整性校验 ->", st2)
        print(json.dumps(json.loads(body2), ensure_ascii=False, indent=2))
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
