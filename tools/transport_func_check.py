# -*- coding: utf-8 -*-
"""HTTPS 模式的功能回归：证明"启用传输加密"之后业务链路依然全通。

与 cs_connect_check.py 的区别：
    那个脚本测的是**开发态**后端（dotnet run，明文 http://localhost:5007）；
    本脚本测的是**桌面端 / 生产态**后端 —— 它用随机端口 + https，
    也用于安装包验证。两者互补，不互相替代。

用法：
    python tools/transport_func_check.py            # 自动从 AuthServer.exe 反查端口
    python tools/transport_func_check.py 8443       # 手工指定端口

判定：
    ① 协议必须是 https（用系统根存储校验，即 Schannel/WebView2 的同一判定路径）
    ② /api/auth/transport 必须 tls=true
    ③ 登录 + 票据访问受保护接口必须正常
    ④ 未授权访问必须被拒
退出码 0 = 全部通过。
"""
import json
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

ADMIN_USER = "admin"
ADMIN_PASS = "Admin123"          # 演示项目的公开默认种子口令，只用于连通性自检


def find_port():
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq authserver.exe", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True, encoding="gbk", errors="replace").stdout
    m = re.search(r'"authserver\.exe","(\d+)"', out, re.I)
    if not m:
        return None, None
    pid = m.group(1)
    ns = subprocess.run(["netstat", "-ano"], capture_output=True).stdout.decode("gbk", errors="replace")
    for line in ns.splitlines():
        if "LISTENING" in line and pid in line and "127.0.0.1:" in line:
            return int(line.split()[1].split(":")[1]), pid
    return None, pid


def call(base, method, path, body=None, ticket=None, raw=False, ctx=None):
    req = urllib.request.Request(base + path, method=method)
    req.add_header("Content-Type", "application/json")
    if ticket:
        req.add_header("Authorization", "Bearer " + ticket)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data, timeout=15, context=ctx) as r:
            text = r.read().decode("utf-8", errors="replace")
            return r.status, (text if raw else json.loads(text or "{}"))
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, (text if raw else json.loads(text or "{}"))
        except Exception:
            return e.code, (text if raw else {})
    except Exception as e:
        return 0, (str(e) if raw else {"err": str(e)})


port, pid = (int(sys.argv[1]), "手工指定") if len(sys.argv) > 1 else find_port()
if not port:
    print("未找到 AuthServer.exe 的监听端口 —— 程序可能没在运行。")
    raise SystemExit(1)

# 系统根存储校验上下文：与 Schannel / WebView2 走同一条判定路径
ctx = ssl.create_default_context()

print("=" * 68)
print("桌面端 / 生产态 HTTPS 功能回归")
print(f"  服务端  AuthServer.exe (PID {pid})  端口 127.0.0.1:{port}")
print("=" * 68)

results = []

print("\n[第1层] 协议判定（必须 https，且系统根存储必须认）")
BASE = f"https://127.0.0.1:{port}"
st, body = call(BASE, "GET", "/api/auth/transport", ctx=ctx)
if st == 200:
    d = body.get("data") or {}
    print(f"   https 可达  HTTP {st}")
    print(f"   scheme={d.get('scheme')}  tls={d.get('tls')}  trustStore={d.get('trustStore')}")
    print(f"   subject={d.get('subject')}  到期={d.get('notAfter')}")
    results.append(("协议为 https 且 tls=true", d.get("tls") is True))
else:
    print(f"   https 不可达（HTTP {st}）{json.dumps(body, ensure_ascii=False)[:120]}")
    print("   → 后端可能仍在明文模式运行")
    results.append(("协议为 https 且 tls=true", False))
    BASE = f"http://127.0.0.1:{port}"
    ctx = None

print("\n[第2层] 静态页面与根路径（窗口内页面由后端托管）")
for name, path in (("GET /", "/"), ("GET /index.html", "/index.html")):
    st, _ = call(BASE, "GET", path, raw=True, ctx=ctx)
    ok = st == 200
    results.append((name, ok))
    print(f"   {'[OK]' if ok else '[x] '} {name:16s} HTTP {st}")

print("\n[第3层] 后端 ↔ MongoDB + 票据通道")
st, body = call(BASE, "POST", "/api/auth/login",
                {"username": ADMIN_USER, "password": ADMIN_PASS}, ctx=ctx)
print(f"   POST /api/auth/login  → HTTP {st}")
tk = None
if st == 200 and body.get("data"):
    tk = body["data"]["ticket"]
    print("   [OK] 登录成功并签发票据 —— 后端确实读到了 MongoDB 中的账号")
    results.append(("登录并签发票据", True))
else:
    print(f"   [x] 登录失败：{json.dumps(body, ensure_ascii=False)[:160]}")
    results.append(("登录并签发票据", False))

if tk:
    # (接口, 期望状态码, 说明)。期望 403 的两条不是失败，而是**职责分离的既定行为**：
    # Admin 能管用户、但按设计读不到审计；审计只归 AuditAdmin。把它们标成红色叉
    # 会让验收时误读成"功能坏了"，所以这里按"预期行为"判定。
    for name, path, expect in (("读用户列表", "/api/auth/users", 200),
                               ("读审计统计(应拒)", "/api/audit/stats", 403),
                               ("校验哈希链(应拒)", "/api/audit/verify", 403)):
        st, b = call(BASE, "GET", path, ticket=tk, ctx=ctx)
        d = b.get("data") or {}
        ok = st == expect
        results.append((f"{name} 期望 HTTP {expect}", ok))
        if name == "读用户列表":
            extra = f"  用户数={len(d) if isinstance(d, list) else d.get('total', '?')}"
        elif expect == 403:
            extra = "  ← 职责分离：Admin 不可读审计" if ok else f"  code={b.get('code')}"
        else:
            extra = f"  intact={d.get('intact')} checked={d.get('checked')}"
        print(f"   {'[OK]' if ok else '[x] '} {name:16s} HTTP {st}{extra}")

print("\n[第4层] 鉴权仍然生效（未授权必须被拒）")
for name, path in (("无票据读审计", "/api/audit/logs"),
                   ("无票据读用户", "/api/auth/users")):
    st, b = call(BASE, "GET", path, ctx=ctx)
    ok = st in (401, 403)
    results.append((name, ok))
    print(f"   {'[OK]' if ok else '[x] '} {name:12s} HTTP {st}  code={b.get('code')}")

print("\n=== 汇总 ===")
for name, ok in results:
    print(f"   {'通过' if ok else '未通过'}  {name}")
raise SystemExit(0 if all(ok for _, ok in results) else 1)
