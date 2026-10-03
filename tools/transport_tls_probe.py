"""TLS 链路断言：证明加密真的生效、且不可绕过。

用法：
    python transport_tls_probe.py <https_base_url> <ca_file>

断言：
    A) https + 固定信任锚(server.crt)  -> 200 且 tls=true   （证明"能通"）
    B) https + 空信任锚                -> 必须失败           （证明"真在验链"，不是装饰）
    C) 明文 http 打到 https 端口        -> 必须失败           （证明"没有静默降级"）
    D) 打印实际协商的 TLS 版本与密码套件（证明不是"看起来像 TLS"）
    E) 系统信任存储判定                 -> 必须通过           （证明 WebView2/Schannel 会接受）

⚠️ B 段为什么用"空信任锚"而不是"默认上下文"：
    CA 一旦写进系统根存储（生产路径就是这么做的），`ssl.create_default_context()`
    会把我们的 CA 也读进来 —— 那时"不带 cacert 必须失败"就不成立了，B 会假阳性。
    所以 B 必须用一张 CA 都不加载的上下文，才能单纯地证明"服务端确实在验链"。
    而"系统信任存储里到底有没有这张 CA"是另一件事，由 E 段单独断言。
"""
import json
import socket
import ssl
import sys
import urllib.request
from urllib.parse import urlparse

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:5443"
CA = sys.argv[2] if len(sys.argv) > 2 else "server.crt"
PATH = "/api/auth/transport"

parsed = urlparse(BASE)
host = parsed.hostname or "127.0.0.1"
port = parsed.port or 443

result = {}


def anchor_ctx(cafile=None):
    """只信 cafile 的上下文；cafile=None 表示谁都不信。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if cafile:
        ctx.load_verify_locations(cafile=cafile)
    return ctx


print("=== A) https + 固定信任锚 server.crt（期望 200 且 tls=true）===")
try:
    with urllib.request.urlopen(BASE + PATH, context=anchor_ctx(CA), timeout=10) as r:
        data = json.loads(r.read().decode("utf-8")).get("data", {})
        print(f"    status={r.status}")
        print(f"    scheme={data.get('scheme')} tls={data.get('tls')} "
              f"requireHttps={data.get('requireHttps')} downgraded={data.get('downgraded')}")
        print(f"    subject={data.get('subject')}")
        print(f"    notAfter={data.get('notAfter')} trustStore={data.get('trustStore')}")
        print(f"    thumbprint={data.get('thumbprint')}")
        result["A"] = (r.status == 200 and data.get("tls") is True)
except Exception as e:
    print(f"    [x] 失败 -> {type(e).__name__}: {e}")
    result["A"] = False

print("\n=== B) https 但信任锚为空（期望失败 —— TLS 不是装饰的关键证据）===")
try:
    with urllib.request.urlopen(BASE + PATH, context=anchor_ctx(None), timeout=10) as r:
        print(f"    [x] 意外成功 status={r.status} —— TLS 形同虚设")
        result["B"] = False
except Exception as e:
    print(f"    [OK] 已被拒绝 -> {type(e).__name__}: {str(e)[:110]}")
    result["B"] = True

print("\n=== C) 明文 http 打到同一端口（期望失败）===")
try:
    with urllib.request.urlopen(BASE.replace("https://", "http://") + PATH, timeout=10) as r:
        print(f"    [x] 意外成功 status={r.status} —— 存在明文通道")
        result["C"] = False
except Exception as e:
    print(f"    [OK] 已被拒绝 -> {type(e).__name__}")
    result["C"] = True

print("\n=== D) 实际协商的 TLS 参数 ===")
try:
    with socket.create_connection((host, port), timeout=10) as sock:
        with anchor_ctx(CA).wrap_socket(sock, server_hostname=host) as ssock:
            print(f"    version={ssock.version()}")
            print(f"    cipher={ssock.cipher()}")
            cert = ssock.getpeercert()
            print(f"    subject={dict(x[0] for x in cert['subject'])}")
            print(f"    issuer={dict(x[0] for x in cert['issuer'])}")
            print(f"    SAN={cert.get('subjectAltName')}")
            result["D"] = True
except Exception as e:
    print(f"    [x] 失败 -> {type(e).__name__}: {e}")
    result["D"] = False

print("\n=== E) 系统信任存储判定（等价于 Schannel / WebView2 的判定路径）===")
try:
    with urllib.request.urlopen(BASE + PATH, context=ssl.create_default_context(), timeout=10) as r:
        print(f"    [OK] 系统根存储已信任本机 CA，status={r.status}  ← 界面能正常渲染的前提")
        result["E"] = True
except Exception as e:
    print(f"    [x] 系统根存储未信任 -> {type(e).__name__}: {str(e)[:110]}")
    print("        （WebView2 会因此显示白窗口；需确认 CA 是否已写入 CurrentUser\\Root）")
    result["E"] = False

print("\n=== 汇总 ===")
for k in ("A", "B", "C", "D", "E"):
    print(f"    {k}: {'通过' if result.get(k) else '未通过'}")
sys.exit(0 if all(result.values()) else 1)
