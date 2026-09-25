# -*- coding: utf-8 -*-
"""验证 C/S 的进程关系与端口绑定。

证明三件事：
  1. 后端 sidecar 是客户端拉起的子进程（生命周期受客户端托管）；
  2. 后端只绑 127.0.0.1（不对外网暴露）；
  3. 客户端与后端、后端与 MongoDB 之间存在已建立的 TCP 连接。
"""
import re
import subprocess


def run(cmd):
    return subprocess.run(cmd, capture_output=True).stdout.decode("gbk", errors="replace")


print("=" * 68)
print("进程关系与端口占用检查")
print("=" * 68)

# 1. 父子关系（wmic 在新版 Windows 已弃用，改用 PowerShell CIM）
print("\n[1] 进程父子关系（看 ParentProcessId 指向谁）")
ps = run(["powershell", "-NoProfile", "-Command",
          "Get-CimInstance Win32_Process -Filter \"name='auth-baseline-desktop.exe' or "
          "name='authserver.exe'\" | Select-Object Name,ProcessId,ParentProcessId | "
          "Format-Table -AutoSize | Out-String -Width 200"])
print(ps.strip() if ps.strip() else "   （未取到，可能进程已退出）")

ns = run(["netstat", "-ano"])
tl = run(["tasklist", "/FI", "IMAGENAME eq authserver.exe", "/FO", "CSV", "/NH"])
m = re.search(r'"authserver\.exe","(\d+)"', tl)
pid = m.group(1) if m else None

# 2. 监听地址
print("\n[2] 后端监听地址（必须是 127.0.0.1，不能是 0.0.0.0）")
port = None
if pid:
    for line in ns.splitlines():
        if "LISTENING" in line and line.split()[-1] == pid:
            addr = line.split()[1]
            port = addr.split(":")[-1]
            flag = "OK  仅绑定回环地址，外网不可达" if addr.startswith("127.0.0.1:") else "注意！绑定了非回环地址"
            print("   PID %s 监听 %s" % (pid, addr))
            print("   " + flag)

# 3. 客户端 <-> 后端
print("\n[3] 客户端 <-> 后端的 TCP 连接")
if port:
    hits = [l for l in ns.splitlines() if "ESTABLISHED" in l and ("127.0.0.1:" + port) in l]
    if hits:
        for h in hits:
            p = h.split()
            print("   %-24s -> %-24s [已建立]" % (p[1], p[2]))
    else:
        print("   当前无活跃连接（窗口空闲时正常：前端按 20s 轮询才建连）")

# 4. 后端 <-> MongoDB
print("\n[4] 后端 <-> MongoDB(27017) 连接")
if pid:
    hits = [l for l in ns.splitlines()
            if "ESTABLISHED" in l and "127.0.0.1:27017" in l and l.split()[-1] == pid]
    print("   共 %d 条已建立连接（连接池）" % len(hits))
    for h in hits[:4]:
        p = h.split()
        print("   %-24s -> %s" % (p[1], p[2]))
