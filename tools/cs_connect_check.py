# -*- coding: utf-8 -*-
"""C/S 连通性验证：客户端窗口 ←→ 后端 sidecar ←→ MongoDB。

用法：python tools/cs_connect_check.py [端口]
端口可省略，脚本会自动从 authserver.exe 进程反查。
"""
import json, subprocess, sys, urllib.request, urllib.error, re


def find_port():
    """从 authserver.exe 的 PID 反查它在 127.0.0.1 上监听的端口。"""
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq authserver.exe", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True, encoding="gbk", errors="replace").stdout
    m = re.search(r'"authserver\.exe","(\d+)"', out)
    if not m:
        return None, None
    pid = m.group(1)
    ns = subprocess.run(["netstat", "-ano"], capture_output=True).stdout.decode("gbk", errors="replace")
    for line in ns.splitlines():
        if "LISTENING" in line and pid in line and "127.0.0.1:" in line:
            return int(line.split()[1].split(":")[1]), pid
    return None, pid


def call(base, method, path, body=None, ticket=None, raw=False):
    """请求接口并解析响应。

    raw=True 时返回 (状态码, 原始文本) —— 根路径与 index.html 返回的是 HTML，
    按 JSON 解析会抛异常，被误报成"连接失败"。这类静态资源只关心状态码。
    """
    req = urllib.request.Request(base + path, method=method)
    req.add_header("Content-Type", "application/json")
    if ticket:
        req.add_header("Authorization", "Bearer " + ticket)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data, timeout=15) as r:
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
    print("未找到 authserver.exe 的监听端口 —— 程序可能没在运行。")
    raise SystemExit(1)
BASE = f"http://127.0.0.1:{port}"

print("=" * 68)
print("C/S 架构连通性验证")
print(f"  客户端  auth-baseline-desktop.exe")
print(f"  服务端  authserver.exe (PID {pid})  监听 127.0.0.1:{port}")
print("=" * 68)

print("\n[第1层] 后端 HTTP 服务可达")
st, _ = call(BASE, "GET", "/", raw=True)
print(f"   GET /  → HTTP {st}   {'✅ 服务在监听且能响应' if st == 200 else '❌'}")

print("\n[第2层] 后端 ↔ MongoDB（服务端的数据通道）")
st, body = call(BASE, "POST", "/api/auth/login", {"username": "admin", "password": "Admin123"})
print(f"   POST /api/auth/login  → HTTP {st}")
tk = None
if st == 200 and body.get("data"):
    tk = body["data"]["ticket"]
    print("   ✅ 登录成功并签发票据 —— 证明后端确实读到了 MongoDB 中的账号")
else:
    print(f"   ❌ 登录失败: {json.dumps(body, ensure_ascii=False)[:160]}")

print("\n[第3层] 凭票据访问受保护接口（票据通道）")
if tk:
    for name, path in [("读用户列表", "/api/auth/users"),
                       ("读审计日志", "/api/audit/logs?page=1&pageSize=3"),
                       ("读审计统计", "/api/audit/stats"),
                       ("校验哈希链", "/api/audit/verify")]:
        st, b = call(BASE, "GET", path, ticket=tk)
        d = b.get("data") or {}
        if name == "读用户列表":
            extra = f"  用户数={len(d) if isinstance(d, list) else d.get('total', '?')}"
        elif name == "读审计统计":
            extra = f"  审计总数={d.get('total')}"
        elif name == "校验哈希链":
            extra = f"  intact={d.get('intact')} checked={d.get('checked')}"
        else:
            extra = f"  total={d.get('total')}"
        print(f"   {'✅' if st == 200 else '❌'} {name:10s} HTTP {st}{extra}")

print("\n[第4层] 鉴权生效（未授权访问必须被拒）")
for name, path in [("无票据读审计", "/api/audit/logs"),
                   ("URL声明管理员", "/api/auth/logs?adminUsername=admin")]:
    st, b = call(BASE, "GET", path)
    print(f"   {'✅' if st == 401 else '❌'} {name:12s} HTTP {st}  code={b.get('code')}")

print("\n[第5层] 前端静态页面（窗口内页面由后端托管）")
st, _ = call(BASE, "GET", "/index.html", raw=True)
print(f"   GET /index.html  → HTTP {st}   {'✅ 页面可由后端提供' if st == 200 else '❌'}")
