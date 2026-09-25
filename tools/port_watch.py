# -*- coding: utf-8 -*-
"""实时验证：桌面壳启动 -> sidecar 起来 -> 端口真的在 LISTENING 吗。

流程：
  1. explorer.exe 拉起桌面壳（等同双击）
  2. 轮询等待 authserver.exe 出现
  3. 用 PowerShell Get-NetTCPConnection 查它的监听端口（和用户截图同一条命令）
  4. 再用 netstat -ano 交叉验证同一个端口
  5. 直接 TCP connect 打通，发一个真实 HTTP 请求
  6. 同时打印 Get-Process / netstat 两个口径的结果，看是不是一致
"""
import os
import subprocess
import time
import socket
import re
import json
import urllib.request

EXE = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/AppData/Local"),
    "AuthBaseline", "auth-baseline-desktop.exe")


def run(cmd):
    p = subprocess.run(cmd, capture_output=True)
    out = p.stdout.decode("gbk", errors="replace")
    err = p.stderr.decode("gbk", errors="replace")
    return out + err


def ps(cmd):
    return run(["powershell", "-NoProfile", "-Command", cmd])


def find_pid(image):
    out = run(["tasklist", "/FI", "IMAGENAME eq %s" % image, "/FO", "CSV", "/NH"])
    m = re.search(r'"%s","(\d+)"' % re.escape(image), out)
    return int(m.group(1)) if m else None


def listen_ports_of(pid):
    """口径A：PowerShell Get-NetTCPConnection（用户截图用的命令）"""
    out = ps(
        "(Get-NetTCPConnection -State Listen -OwningProcess %d).LocalPort" % pid
    )
    return [int(x) for x in re.findall(r"\d+", out)]


def listen_ports_netstat(pid):
    """口径B：netstat -ano 解析"""
    ports = []
    for line in run(["netstat", "-ano"]).splitlines():
        if "LISTENING" not in line:
            continue
        parts = line.split()
        if len(parts) >= 5 and parts[-1] == str(pid):
            ports.append(int(parts[1].rsplit(":", 1)[-1]))
    return ports


def tcp_probe(port):
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def http_probe(port, path="/"):
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=5) as r:
            return r.status, len(r.read())
    except Exception as e:
        return 0, str(e)


print("=== [1] 启动桌面壳 ===")
subprocess.Popen(["explorer.exe", EXE])
print("explorer.exe 已拉取:", EXE)

print()
print("=== [2] 等待 authserver.exe 出现 ===")
srv_pid = None
for i in range(40):
    srv_pid = find_pid("authserver.exe")
    if srv_pid:
        print("第 %d 秒出现 authserver.exe PID=%d" % (i, srv_pid))
        break
    time.sleep(1)

if not srv_pid:
    print("!!! 40 秒内没等到 authserver.exe")
    raise SystemExit(1)

cli_pid = find_pid("auth-baseline-desktop.exe")
print("auth-baseline-desktop.exe PID=%s (父进程)" % cli_pid)

print()
print("=== [3] 口径A：PowerShell Get-NetTCPConnection ===")
pa = listen_ports_of(srv_pid)
print("  LocalPort =", pa if pa else "(空!)")

print()
print("=== [4] 口径B：netstat -ano ===")
pb = listen_ports_netstat(srv_pid)
print("  监听端口 =", pb if pb else "(空!)")

print()
print("=== [5] 两个口径是否一致 ===")
print("  A:", sorted(pa))
print("  B:", sorted(pb))
print("  一致:", sorted(pa) == sorted(pb))

if pa:
    port = pa[0]
    print()
    print("=== [6] TCP 实连 + 真实 HTTP 请求 (端口 %d) ===" % port)
    print("  TCP connect 127.0.0.1:%d ->" % port, "成功" if tcp_probe(port) else "失败")
    st, ln = http_probe(port, "/")
    print("  GET /            -> HTTP %s (%s bytes)" % (st, ln))
    st, ln = http_probe(port, "/index.html")
    print("  GET /index.html  -> HTTP %s (%s bytes)" % (st, ln))

print()
print("=== [7] 原始 netstat 该 PID 的所有行 ===")
for line in run(["netstat", "-ano"]).splitlines():
    if line.split() and line.split()[-1] == str(srv_pid):
        print("  " + line.strip())

print()
print("=== [8] 保持 20 秒，让你有时间自己开 PowerShell 复核 ===")
print("  你可以手动敲：netstat -ano | findstr %d" % srv_pid)
for s in range(20, 0, -5):
    print("  剩余 %d 秒 ..." % s)
    time.sleep(5)

print()
print("=== [9] 收尾确认进程仍在 ===")
print("  auth-baseline-desktop.exe:", find_pid("auth-baseline-desktop.exe"))
print("  authserver.exe           :", find_pid("authserver.exe"))
print("  端口是否仍监听           :", listen_ports_of(srv_pid))
