# -*- coding: utf-8 -*-
"""一次性口令 P8 的端到端验证：**口令路径已被删除**。

用法：
  python tools/otp_p8_probe.py [exe路径] [端口]

P8 的交付物是一堆"删除"，而删除最难验收 —— 代码里搜不到 `PasswordHasher.Verify`
只能说明写得干净，说明不了**线上真的没人能凭口令进来**。所以这条探针只做一件事：
从外部（HTTP + 库 + 子命令）把这个结论逐条钉住。

断言分组
========
  A. 口令进不来
     A1 带 `password` 的登录 → 400 EMPTY_FIELDS（字段已从 DTO 删除，只剩"缺 otpCode"）
     A2 口令正确也一样 400，且**不签票**
     A3 改密带 `oldPassword`（不带链值）→ 400 EMPTY_FIELDS

  B. 链值仍是唯一入口
     B1 链值登录 → 200 + 票据
     B2 链值错 → 401 INVALID_CREDENTIALS，且话术与改造前一致（"密码错误，还剩 N 次机会"）

  C. 所有写入口只建链、不落哈希
     C1 播种 admin：库里无 `passwordHash`，有链
     C2 管理员建号：新账号无 `passwordHash`、有链，且能用给定口令链值登录
     C3 自助注册：同上（邮件关闭时走无邮箱老流程）

  D. 六处二次确认只认确认凭据
     D1 create-account 缺凭据 → 401 OTP_CONFIRM_REQUIRED
     D2 create-account 带正确凭据 → 200
     D3 set-role 缺凭据 → 401
     D4 批量 set-role 缺凭据 ⇒ 逐条 401（部分成功是批量的常态）

  E. 没有链的账号
     E1 链值登录 → 401 INVALID_CREDENTIALS（统一话术，防枚举）
     E2 challenge 仍返回完整参数（不暴露"没有链"）

  F. 端点与审计面
     F1 `POST /api/auth/otp/recover` 已不存在（404）
     F2 库里不出现 OTP_MIGRATED / PASSWORD_HASH_UPGRADED 这两类历史动作

  G. 迁移工具
     G1 `--rechain --force` 能把"无链账号"建成有链，且随后能用该口令登录

只碰 `AuthBaselineOtpP8Probe`（过守卫），结束时 drop；真实库连读都不读。
"""
import base64
import hashlib
import os
import re
import subprocess
import sys
import time

from _probe_common import (ProbeDb, resolve_probe_db, start_backend, require_backend_ready,
                           stop_backend, http_call, otp_login, otp_challenge)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    ROOT, "AuthServer", "bin", "Debug", "net8.0", "AuthServer.exe")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5128
DB = resolve_probe_db("AuthBaselineOtpP8Probe")
BASE = "http://127.0.0.1:%d" % PORT

CHAIN_N = 32
CHAIN_ITER = 1000
ADMIN_PW = "Admin123"
NEW_USER_PW = "Abc12345"

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print("  [%s] %s%s" % ("OK  " if cond else "FAIL", name,
                          ("  ← " + str(detail)) if detail and not cond else ""))


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def code_for(password, ch):
    """按挑战参数算出这一格（独立实现，不复用 C#）。"""
    x = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                            ch["r"].encode("utf-8"), int(ch["iterations"]), dklen=32)
    for _ in range(int(ch["k"])):
        x = hashlib.sha256(x).digest()
    return b64(x)


def read_email_code(to_email, timeout_s=10):
    """从控制台发件器的日志里取出最近一条该邮箱的验证码。

    控制台发件器把验证码写进 `<exe目录>/email-codes.log` —— 这是"没有 SMTP 也能
    离线演示"那条退路。探针用它验证注册流程，而不是把邮件模块整个关掉：
    注册的**唯一**入口就是"邮箱验证通过后落库"，绕开它等于没测注册。
    """
    log = os.path.join(os.path.dirname(os.path.abspath(EXE)), "email-codes.log")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if os.path.exists(log):
            with open(log, "r", encoding="utf-8", errors="replace") as fh:
                hits = re.findall(r"收件邮箱=%s 验证码=(\d{6})" % re.escape(to_email), fh.read())
            if hits:
                return hits[-1]
        time.sleep(0.3)
    return ""


def ticket_of(body):
    return (body.get("data") or {}).get("ticket") if isinstance(body, dict) else None


def login(username, password):
    return otp_login(BASE, username, password)


def confirm(ticket, purpose, target, password, username):
    """换一张一次性确认凭据（与客户端同一条路径）。"""
    st, ch = otp_challenge(BASE, username)
    body = {"purpose": purpose, "target": target, "otpCode": code_for(password, ch)}
    st, resp = http_call(BASE, "POST", "/api/auth/reconfirm", body, ticket=ticket)
    return st, (resp.get("data") or {}).get("confirmToken") if isinstance(resp, dict) else None


def run(probe_db):
    # ── A. 口令进不来 ─────────────────────────────────────────────
    print("\n[A] 口令路径已删除")

    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": "admin", "password": ADMIN_PW})
    check("A1 带 password 的登录 → 400 EMPTY_FIELDS",
          st == 400 and b.get("code") == "EMPTY_FIELDS", "HTTP %s / %s" % (st, b.get("code")))
    check("A2 且不签发任何票据", not ticket_of(b), b)

    st, b = http_call(BASE, "POST", "/api/auth/change-password",
                      {"username": "admin", "oldPassword": ADMIN_PW, "newPassword": "Zzz12345"})
    check("A3 改密带 oldPassword（无链值）→ 400 EMPTY_FIELDS",
          st == 400 and b.get("code") == "EMPTY_FIELDS", "HTTP %s / %s" % (st, b.get("code")))

    # ── B. 链值仍是唯一入口 ───────────────────────────────────────
    print("\n[B] 链值登录")
    st, b = login("admin", ADMIN_PW)
    admin_ticket = ticket_of(b)
    check("B1 链值登录 → 200 且签发票据", st == 200 and bool(admin_ticket),
          "HTTP %s / %s" % (st, b.get("code")))

    st, b = login("admin", "WrongPass1")
    check("B2 链值错 → 401 INVALID_CREDENTIALS 且话术不变",
          st == 401 and b.get("code") == "INVALID_CREDENTIALS"
          and b.get("message") == "密码错误，还剩 2 次机会",
          "HTTP %s / %s / %s" % (st, b.get("code"), b.get("message")))

    # 上面那次错会把计数推到 1，先登录成功复位，避免后续用例被锁定干扰
    login("admin", ADMIN_PW)

    # ── C. 写入口只建链 ──────────────────────────────────────────
    print("\n[C] 写入口：只建链，不落哈希")

    admin_doc = probe_db["Users"].find_one({"username": "admin"}) or {}
    admin_chain = probe_db["OtpChains"].count_documents({"username": "admin"})
    check("C1a 播种 admin 库里没有 passwordHash", not admin_doc.get("passwordHash"),
          "passwordHash=%r" % admin_doc.get("passwordHash"))
    check("C1b 播种 admin 有链", admin_chain == 1, "链数量 %d" % admin_chain)

    # 管理员建号（带正确的确认凭据）
    st, token = confirm(admin_ticket, "create-account", "p8user", ADMIN_PW, "admin")
    check("D2a create-account 的确认凭据换到了", st == 200 and bool(token), "HTTP %s" % st)

    st, b = http_call(BASE, "POST", "/api/auth/create-account",
                      {"username": "p8user", "password": NEW_USER_PW, "role": "User",
                       "confirmToken": token}, ticket=admin_ticket)
    check("D2b 带凭据建号 → 200", st == 200, "HTTP %s / %s" % (st, b.get("code")))

    new_doc = probe_db["Users"].find_one({"username": "p8user"}) or {}
    new_chain = probe_db["OtpChains"].count_documents({"username": "p8user"})
    check("C2a 新建账号没有 passwordHash", not new_doc.get("passwordHash"),
          "passwordHash=%r" % new_doc.get("passwordHash"))
    check("C2b 新建账号有链", new_chain == 1, "链数量 %d" % new_chain)

    st, b = login("p8user", NEW_USER_PW)
    check("C2c 新账号能用建号时给的口令登录（链绑的是它）", st == 200 and bool(ticket_of(b)),
          "HTTP %s / %s" % (st, b.get("code")))

    # 自助注册：走真实的"先验邮箱再落库"流程。
    # 之所以不把邮件关掉图省事：`Email:Enabled` 被 appsettings.Local.json 覆盖
    # （那份文件在 CreateBuilder **之后**才加入，优先级最高），环境变量改不动它。
    # 于是改用控制台发件器 —— 它把验证码写进程序目录的 email-codes.log，探针直接读。
    self_email = "p8self@example.com"
    st, _ = http_call(BASE, "POST", "/api/auth/send-email-code",
                      {"purpose": "REGISTER", "username": "p8self", "email": self_email})
    reg_code = read_email_code("p8self@example.com")
    st, b = http_call(BASE, "POST", "/api/auth/register",
                      {"username": "p8self", "password": NEW_USER_PW,
                       "email": self_email, "code": reg_code})
    reg_doc = probe_db["Users"].find_one({"username": "p8self"}) or {}
    reg_chain = probe_db["OtpChains"].count_documents({"username": "p8self"})
    check("C3a 自助注册 → 200", st == 200, "HTTP %s / %s" % (st, b.get("code")))
    check("C3b 注册出来的账号没有 passwordHash", not reg_doc.get("passwordHash"),
          "passwordHash=%r" % reg_doc.get("passwordHash"))
    check("C3c 注册出来的账号有链（Pending 也先建好）", reg_chain == 1, "链数量 %d" % reg_chain)

    # ── D. 二次确认只认凭据 ──────────────────────────────────────
    print("\n[D] 六处二次确认")

    st, b = http_call(BASE, "POST", "/api/auth/create-account",
                      {"username": "p8nope", "password": NEW_USER_PW, "role": "User"},
                      ticket=admin_ticket)
    check("D1 缺确认凭据 → 401 OTP_CONFIRM_REQUIRED",
          st == 401 and b.get("code") == "OTP_CONFIRM_REQUIRED", "HTTP %s / %s" % (st, b.get("code")))

    st, b = http_call(BASE, "POST", "/api/auth/set-role",
                      {"username": "p8user", "role": "UserAdmin"}, ticket=admin_ticket)
    check("D3 set-role 缺凭据 → 401 OTP_CONFIRM_REQUIRED",
          st == 401 and b.get("code") == "OTP_CONFIRM_REQUIRED", "HTTP %s / %s" % (st, b.get("code")))

    st, b = http_call(BASE, "POST", "/api/auth/batch",
                      {"action": "set-role", "usernames": ["p8user"], "role": "User"},
                      ticket=admin_ticket)
    items = ((b.get("data") or {}).get("items") or []) if isinstance(b, dict) else []
    check("D4 批量 set-role 缺逐目标凭据 ⇒ 该目标被 401 挡下",
          bool(items) and items[0].get("code") == "OTP_CONFIRM_REQUIRED",
          "items=%s" % items)

    # ── E. 没有链的账号 ──────────────────────────────────────────
    print("\n[E] 无链账号")

    probe_db["OtpChains"].delete_many({"username": "p8user"})
    st, b = login("p8user", NEW_USER_PW)
    check("E1 无链账号链值登录 → 401 INVALID_CREDENTIALS（统一话术）",
          st == 401 and b.get("code") == "INVALID_CREDENTIALS", "HTTP %s / %s" % (st, b.get("code")))

    st, ch = otp_challenge(BASE, "p8user")
    check("E2 无链账号 challenge 仍返回完整参数（8 个字段）",
          st == 200 and len(ch.keys()) == 8, "HTTP %s / %s" % (st, ch))

    # ── F. 端点与审计面 ─────────────────────────────────────────
    print("\n[F] 端点与审计面")

    st, _ = http_call(BASE, "POST", "/api/auth/otp/recover",
                      {"username": "admin", "email": "a@b.c", "code": "1", "password": ADMIN_PW})
    check("F1 POST /otp/recover 已不存在（404）", st == 404, "HTTP %s" % st)

    migrated = probe_db["AuditLogs"].count_documents(
        {"action": {"$in": ["OTP_MIGRATED", "PASSWORD_HASH_UPGRADED"]}})
    check("F2 审计里没有 OTP_MIGRATED / PASSWORD_HASH_UPGRADED（历史动作不再产生）",
          migrated == 0, "命中 %d 条" % migrated)

    # ── G. 迁移工具 ─────────────────────────────────────────────
    print("\n[G] 存量迁移工具 --rechain")

    env = dict(os.environ)
    env["MongoDbSettings__DatabaseName"] = DB          # 与后端同一个库（探针库）
    env["AUTHBASELINE_REQUIRE_HTTPS"] = "false"
    env["AUTHBASELINE_RECHAIN_PASSWORD"] = "Rechain123"

    proc = subprocess.run([EXE, "--rechain", "--username", "p8user", "--force"],
                          env=env, capture_output=True, text=True, timeout=120)
    out = (proc.stdout or "") + (proc.stderr or "")
    chain_after = probe_db["OtpChains"].count_documents({"username": "p8user"})
    check("G1a rechain 退出码 0", proc.returncode == 0, "rc=%s\n%s" % (proc.returncode, out[-500:]))
    check("G1b rechain 之后账号有链", chain_after == 1, "链数量 %d" % chain_after)

    st, b = login("p8user", "Rechain123")
    check("G1c 用 rechain 给的口令能登录", st == 200 and bool(ticket_of(b)),
          "HTTP %s / %s" % (st, b.get("code")))


def main():
    probe_db = ProbeDb(DB)
    probe_db.drop_if_exists()

    # 清掉上一次跑留下的验证码日志：否则 read_email_code 可能读到旧的六位数。
    stale = os.path.join(os.path.dirname(os.path.abspath(EXE)), "email-codes.log")
    if os.path.exists(stale):
        os.remove(stale)

    # 邮件关闭 ⇒ 注册走无邮箱老流程，探针不必依赖 SMTP。
    # `Email__Enabled` 是 .NET 标准配置覆盖（节名 + 双下划线），EmailOptions 上没有专门的
    # 环境变量 —— 直接改它的 Enabled 字段就能让"注册"这条路不依赖外部服务。
    proc = start_backend(EXE, PORT, DB, extra_env={
        "AUTHBASELINE_REQUIRE_HTTPS": "false",
        "AUTHBASELINE_OTP_LENGTH": str(CHAIN_N),
        "AUTHBASELINE_OTP_KDF_ITERATIONS": str(CHAIN_ITER),
        # 控制台发件器：验证码落 email-codes.log，探针据此完成注册流程。
        # 环境变量能改 Provider（ApplyEnvironmentOverrides 专门读它），
        # 但改不动 Enabled —— 那一位在 appsettings.Local.json 里。
        "AUTHBASELINE_EMAIL_PROVIDER": "Console",
    })
    try:
        require_backend_ready(BASE, proc)
        run(probe_db)
    finally:
        stop_backend(proc)
        if "--keep" not in sys.argv:
            probe_db.drop()

    print()
    print("=" * 78)
    print("  通过 %d 项，失败 %d 项" % (len(PASSED), len(FAILED)))
    if FAILED:
        print("  失败项：")
        for f in FAILED:
            print("   ·", f)
    print("  结论：%s" % ("PASS ✅ 口令路径确实不在了" if not FAILED else "FAIL ❌"))
    print("=" * 78)
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
