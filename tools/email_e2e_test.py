"""邮箱验证码功能端到端测试（后端接口级）。

覆盖：
  功能一 注册绑定邮箱：发码 / 用途隔离 / 校验 / 一次性 / 建号待审核
  功能二 忘记密码：用户名+邮箱 -> 验证码 -> 设置新密码 -> 新密码登录
  失败分支：重复用户名、弱口令、验证码错误、60 秒重发、待审核/锁定状态拒绝、防枚举

验证码从后端控制台日志中读取（当前使用控制台发件器）。
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

BASE = "http://localhost:5007"
# 注意：Git Bash 的 /tmp 映射到 %TEMP%，原生 Python 读不到 "/tmp/x"，
# 必须用 Windows 风格路径；可由环境变量 BE_LOG 覆盖。
LOG = os.environ.get("BE_LOG", os.path.join(os.environ.get("TEMP", "."), "be.log"))

PASS, FAIL = [], []


def call(path, body=None, method="POST"):
    url = BASE + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw or "{}")
        except Exception:
            return e.code, {"raw": raw}


def read_log():
    try:
        with open(LOG, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def codes_in_log():
    return re.findall(r":\s*(\d{6})\s*$", read_log(), re.M)


def latest_code(prev_len, timeout=5.0):
    """等待日志中出现一条新的验证码，返回它。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        c = codes_in_log()
        if len(c) > prev_len:
            return c[-1]
        time.sleep(0.2)
    return None


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))


def main():
    stamp = str(int(time.time()))[-6:]
    user = f"mail{stamp}"
    email = f"mail{stamp}@example.com"
    other = f"mail{stamp}b"
    print(f"测试账号：{user} / {email}\n")

    # ---------- 功能一：注册绑定邮箱 ----------
    print("== 功能一 注册绑定邮箱 ==")

    n0 = len(codes_in_log())
    st, r = call("/api/auth/send-email-code",
                 {"purpose": "REGISTER", "username": user, "email": email})
    check("发送注册验证码", st == 200 and r.get("success"), f"HTTP {st} {r.get('code')} {r.get('message')}")
    check("响应回显脱敏邮箱", str(r.get("data", {}).get("maskedEmail", "")).startswith("m*****@"),
          str(r.get("data")))

    code = latest_code(n0)
    check("后端日志中能取到 6 位验证码", bool(code and re.fullmatch(r"\d{6}", code)), str(code))
    if not code:
        return summary()

    st, r = call("/api/auth/send-email-code",
                 {"purpose": "REGISTER", "username": user, "email": email})
    check("60 秒内重发被拒", st == 429 and r.get("code") == "RESEND_TOO_SOON",
          f"HTTP {st} {r.get('code')} {r.get('message')}")

    st, r = call("/api/auth/send-email-code",
                 {"purpose": "REGISTER", "username": "admin", "email": "x@example.com"})
    check("重复用户名发码被拒", st == 409 and r.get("code") == "DUPLICATE_USERNAME",
          f"HTTP {st} {r.get('code')}")

    st, r = call("/api/auth/send-email-code",
                 {"purpose": "REGISTER", "username": user, "email": "not-an-email"})
    check("非法邮箱被拒", st == 400 and r.get("code") == "INVALID_EMAIL", f"HTTP {st} {r.get('code')}")

    st, r = call("/api/auth/register",
                 {"username": user, "password": "weak", "email": email, "code": code})
    check("弱口令注册被拒", st == 400 and r.get("code") == "WEAK_PASSWORD", f"HTTP {st} {r.get('code')}")

    st, r = call("/api/auth/register",
                 {"username": user, "password": "Passw0rdX", "email": email, "code": "000000"})
    check("错误验证码注册被拒", st == 400 and r.get("code") == "CODE_MISMATCH",
          f"HTTP {st} {r.get('code')} {r.get('message')}")

    st, r = call("/api/auth/register",
                 {"username": user, "password": "Passw0rdX", "email": "someone@example.com", "code": code})
    check("验证码与邮箱不匹配被拒", st == 400 and r.get("code") == "EMAIL_MISMATCH", f"HTTP {st} {r.get('code')}")

    st, r = call("/api/auth/register",
                 {"username": user, "password": "Passw0rdX", "email": email, "code": code})
    ok = st == 200 and r.get("success") and r.get("data", {}).get("status") == "Pending"
    check("正确验证码建号成功且为待审核", ok, f"HTTP {st} {r.get('code')} {r.get('message')}")
    check("建号响应标记邮箱已验证", (r.get("data") or {}).get("emailVerified") is True)

    st, r = call("/api/auth/login", {"username": user, "password": "Passw0rdX"})
    check("待审核账号不能登录", st == 401 and r.get("code") == "PENDING_APPROVAL", f"HTTP {st} {r.get('code')}")

    st, r = call("/api/auth/send-email-code",
                 {"purpose": "RESET", "username": user, "email": email})
    check("待审核账号不能找回密码", st == 403 and r.get("code") == "PENDING_APPROVAL", f"HTTP {st} {r.get('code')}")

    # ---------- 管理员审核通过 ----------
    st, r = call("/api/auth/approve", {"username": user, "adminUsername": "admin"})
    check("管理员审核通过", st == 200 and r.get("success"), f"HTTP {st} {r.get('code')} {r.get('message')}")

    # ---------- 功能二：忘记密码 ----------
    print("\n== 功能二 忘记密码 ==")

    n1 = len(codes_in_log())
    st, r = call("/api/auth/send-email-code",
                 {"purpose": "RESET", "username": user, "email": email})
    check("发送重置验证码", st == 200 and r.get("success"), f"HTTP {st} {r.get('code')}")
    reset_code = latest_code(n1)
    check("取到重置验证码", bool(reset_code), str(reset_code))

    # 防枚举：邮箱不匹配时响应一致、且不真正发信
    n2 = len(codes_in_log())
    st, r = call("/api/auth/send-email-code",
                 {"purpose": "RESET", "username": user, "email": "wrong@example.com"})
    same_shape = r.get("code") == "OK" and "maskedEmail" in (r.get("data") or {})
    check("邮箱不匹配时响应与成功一致（防枚举）", st == 200 and same_shape, f"HTTP {st} {r.get('code')}")
    check("邮箱不匹配时不真正发信", len(codes_in_log()) == n2, "日志未新增验证码")

    st, r = call("/api/auth/send-email-code",
                 {"purpose": "RESET", "username": "ghost_no_such_user", "email": "ghost@example.com"})
    check("账号不存在时响应与成功一致（防枚举）", st == 200 and r.get("code") == "OK", f"HTTP {st} {r.get('code')}")

    st, r = call("/api/auth/send-email-code",
                 {"purpose": "LOGIN", "username": user, "email": email})
    check("非法用途被拒", st == 400 and r.get("code") == "INVALID_PURPOSE", f"HTTP {st} {r.get('code')}")

    st, r = call("/api/auth/register",
                 {"username": other, "password": "Passw0rdX", "email": f"{other}@example.com", "code": reset_code})
    check("重置码不能用于注册（用途隔离）", st == 400 and r.get("code") == "CODE_INVALID",
          f"HTTP {st} {r.get('code')}")

    st, r = call("/api/auth/reset-password",
                 {"username": user, "email": email, "code": reset_code, "newPassword": "abc"})
    check("弱口令重置被拒", st == 400 and r.get("code") == "WEAK_PASSWORD", f"HTTP {st} {r.get('code')}")

    st, r = call("/api/auth/reset-password",
                 {"username": user, "email": "wrong@example.com", "code": reset_code, "newPassword": "NewPassw0rd"})
    check("邮箱不匹配重置被拒", st == 401 and r.get("code") == "INVALID_CREDENTIALS", f"HTTP {st} {r.get('code')}")

    st, r = call("/api/auth/reset-password",
                 {"username": user, "email": email, "code": "111111", "newPassword": "NewPassw0rd"})
    check("错误验证码重置被拒", st == 400 and r.get("code") == "CODE_MISMATCH",
          f"HTTP {st} {r.get('code')} {r.get('message')}")

    st, r = call("/api/auth/reset-password",
                 {"username": user, "email": email, "code": reset_code, "newPassword": "NewPassw0rd"})
    check("正确验证码重置成功", st == 200 and r.get("success"), f"HTTP {st} {r.get('code')} {r.get('message')}")

    st, r = call("/api/auth/login", {"username": user, "password": "Passw0rdX"})
    check("旧密码立即失效", st == 401 and r.get("code") == "INVALID_CREDENTIALS", f"HTTP {st} {r.get('code')}")

    st, r = call("/api/auth/login", {"username": user, "password": "NewPassw0rd"})
    check("新密码可正常登录", st == 200 and r.get("success"), f"HTTP {st} {r.get('code')} {r.get('message')}")

    st, r = call("/api/auth/reset-password",
                 {"username": user, "email": email, "code": reset_code, "newPassword": "Another1Pass"})
    check("验证码一次性（不可重复使用）", st == 400 and r.get("code") in ("CODE_USED", "CODE_INVALID"),
          f"HTTP {st} {r.get('code')}")

    # ---------- 锁定状态拒绝 ----------
    print("\n== 锁定状态门禁 ==")
    for _ in range(3):
        call("/api/auth/login", {"username": user, "password": "WrongPass1"})
    st, r = call("/api/auth/send-email-code",
                 {"purpose": "RESET", "username": user, "email": email})
    check("锁定期间不能找回密码", st == 423 and r.get("code") == "ACCOUNT_LOCKED",
          f"HTTP {st} {r.get('code')} {r.get('message')}")

    st, r = call("/api/auth/reset-password",
                 {"username": user, "email": email, "code": "123456", "newPassword": "Another1Pass"})
    check("锁定期间不能重置密码", st == 423 and r.get("code") == "ACCOUNT_LOCKED", f"HTTP {st} {r.get('code')}")

    # ---------- 审计 ----------
    print("\n== 审计日志 ==")
    st, r = call(f"/api/auth/logs?adminUsername=admin", method="GET")
    actions = [x.get("action") for x in (r.get("data") or [])]
    for a in ("SEND_EMAIL_CODE", "RESET_PASSWORD", "REGISTER"):
        check(f"审计含 {a}", a in actions, f"共 {len(actions)} 条")
    targets = [x.get("target") for x in (r.get("data") or []) if x.get("action") == "RESET_PASSWORD"]
    check("重置密码审计记录了操作对象", user in targets, str(targets[:3]))

    summary()


def summary():
    print(f"\n{'=' * 46}")
    print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  -", f)
    print("=" * 46)
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
