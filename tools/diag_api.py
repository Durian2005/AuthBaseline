#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
在同一进程内启动后端 → 登录 → 拉用户列表与审计统计，验证数据是否正常返回。

用于排查"桌面端界面显示 0 条"这类前端为空的问题：判断到底是后端没返回数据，
还是前端渲染/时序问题。
"""
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "AuthServer" / "publish" / "AuthServer.exe"
PORT = 5211


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
    proc = subprocess.Popen([str(EXE), "--urls", f"http://127.0.0.1:{PORT}"],
                            cwd=str(EXE.parent),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_port(PORT):
            print("后端未就绪")
            return 1
        st, body = req("POST", "/api/auth/login", {"username": "admin", "password": "Admin123"})
        j = json.loads(body)
        d = j.get("data") or {}
        tok = d.get("ticket") or d.get("Ticket")
        print("登录:", st, "| 用户:", d.get("username"), "| 管理员:", d.get("isAdmin"))

        for path in ("/api/auth/users", "/api/audit/query?page=1&pageSize=5",
                     "/api/audit/verify", "/api/audit/shards"):
            st2, b2 = req("GET", path, headers={"Authorization": "Bearer " + tok})
            try:
                jj = json.loads(b2)
            except Exception:
                print(f"{path} -> {st2} (非 JSON, {len(b2)} 字节)")
                continue
            dd = jj.get("data")
            if isinstance(dd, list):
                summary = f"list[{len(dd)}]"
            elif isinstance(dd, dict):
                summary = json.dumps({k: (v if not isinstance(v, list) else f"list[{len(v)}]")
                                      for k, v in list(dd.items())[:8]}, ensure_ascii=False)[:200]
            else:
                summary = str(dd)[:120]
            print(f"{path} -> {st2} | success={jj.get('success')} | {summary}")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
