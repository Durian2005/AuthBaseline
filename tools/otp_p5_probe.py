# -*- coding: utf-8 -*-
"""一次性口令（哈希链）P5 的端到端验证：**六处二次确认改用 reconfirm**。

用法：
  python tools/otp_p5_probe.py <exe路径> <端口>

这一步改的是"敏感操作的再确认"，而它有两个互相拉扯的要求：

  · 换掉口令比对之后，**不能**在再认证这条路上留下一条无节流的口令爆破通道；
  · 又**不能**把再认证失败算进登录失败计数 —— 否则拿着一张偷来的票据连点三次，
    就能把受害者的账号锁掉（白送的拒绝服务）。

因此本探针的核心不是"新路径能用"，而是下面四条同时成立：

  A. 确认凭据本身：一次性、绑定用途、绑定目标、会过期；
  B. 新路径确实能驱动敏感操作（用确认凭据建出一个账号，而不是只拿到一张票）；
  C. 失败会被节流（第 6 次 429），但 **`failedLoginAttempts` 仍是 0、登录照常**；
  D. 六处端点的旧口令路径**逐字不变**（话术、状态码、计次口径全都不动）。

D 是"可以回滚"的唯一证据：客户端还没改（P7 才改），所以现在线上跑的全部是旧路径，
它一旦有位移，用户当天就会察觉。

⚠️ 顺序是有讲究的：节流用例（第 7 节）会让 admin 在这条路上被封 5 分钟，
so 凡是**还需要 admin 再签一张确认凭据**的用例都必须排在它前面（第 6 节的归属用例）。

库名只碰 `AuthBaselineOtpP5Probe`（过守卫），结束时 drop。
"""
import base64
import hashlib
import json
import os
import sys
import time

from _probe_common import ProbeDb, resolve_probe_db, start_backend, require_backend_ready, stop_backend, http_call

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    ROOT, "AuthServer", "bin", "Debug", "net8.0", "AuthServer.exe")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5122
DB = resolve_probe_db("AuthBaselineOtpP5Probe")
BASE = "http://127.0.0.1:%d" % PORT

N = 20                     # 链长：本阶段只关心"能不能核销一格"，与续期线无关
ITER = 1000
CONFIRM_TTL = 3            # 把确认凭据的 TTL 压到 3 秒，好在探针里真的测一次"过期"
PW = "Admin123"            # 种子管理员口令
U2 = "p5probe1"            # 第二个账号：旧路径测试与"别人的票"都靠它
PW2 = "Abc12345"           # 新建账号的初始口令（复杂度合规）

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print("  [%s] %s%s" % ("OK  " if cond else "FAIL", name, ("  ← " + detail) if detail and not cond else ""))


# ---------------------------------------------------------------- 独立实现
def root(password, r, iterations=ITER):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), r.encode("utf-8"), iterations, dklen=32)


def iterate(x, times):
    for _ in range(times):
        x = hashlib.sha256(x).digest()
    return x


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def bag(field):
    if field is None:
        return {}
    if isinstance(field, dict):
        return field
    try:
        return json.loads(field)
    except (TypeError, ValueError):
        return {}


# ---------------------------------------------------------------- 调用封装
def challenge(username="admin"):
    st, b = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": username})
    return b.get("data") or {}



def login_otp(username, pw):
    """链值登录（P8 起唯一的第一因子）：取挑战 → 按当前 k 现算一格 → 提交。"""
    data = challenge(username)
    code = b64(iterate(root(pw, data["r"]), data["k"]))
    return http_call(BASE, "POST", "/api/auth/login",
                     {"username": username, "otpCode": code,
                      "challengeToken": data.get("challengeToken")})


def chain_of(probe_db, username="admin"):
    return probe_db["OtpChains"].find_one({"username": username})


def k_of(probe_db, username="admin"):
    doc = chain_of(probe_db, username)
    return None if doc is None else doc["k"]


def reconfirm(ticket, purpose, target=None, code=None, username="admin", pw=PW):
    """签一张确认凭据。code=None 时按当前 k 现算一格（也就是"正确的那一格"）。"""
    data = challenge(username)
    if code is None:
        code = b64(iterate(root(pw, data["r"]), data["k"]))
    body = {"purpose": purpose, "otpCode": code}
    if target is not None:
        body["target"] = target
    return http_call(BASE, "POST", "/api/auth/reconfirm", body, ticket=ticket)


def token_of(body):
    return (body.get("data") or {}).get("confirmToken") or ""


def audit_docs(probe_db, action=None, target=None):
    out = []
    for name in probe_db.list_collection_names():
        if not name.startswith("AuditLogs"):
            continue
        q = {}
        if action is not None:
            q["action"] = action
        if target is not None:
            q["target"] = target
        out.extend(probe_db[name].find(q))
    return out


def reset_failures(probe_db, username):
    """把失败计数复位。

    为什么探针要直接改库：这一步测的是"话术与计次**是否**发生"，不是"锁三分钟"。
    每个用例只验证"确实 +1"就立刻复位 —— 否则三个用例之后账号自己就被锁了，
    后面的断言会全部变得无法归因（这是"探针自己制造的故障"混淆真实缺陷的典型形态）。
    """
    probe_db["Users"].update_one({"username": username}, {"$set": {
        "failedLoginAttempts": 0,
        "status": "Enabled",             # UserStatus 用 BsonType.String 存，别写数字
        "lockoutEnd": None,
        "lockoutWallAt": None,
        "lockoutUptimeAt": None,
        "lockoutDriftLogged": False,
        "failedWindowWallAt": None,
        "failedWindowUptimeAt": None,
    }})


def main():
    probe_db = ProbeDb(DB)
    probe_db.drop_if_exists()

    os.environ.pop("AUTHBASELINE_OTP_ENABLED", None)
    proc = start_backend(EXE, PORT, DB, extra_env={
        "AUTHBASELINE_REQUIRE_HTTPS": "false",
        "AUTHBASELINE_OTP_LENGTH": str(N),
        "AUTHBASELINE_OTP_KDF_ITERATIONS": str(ITER),
        "AUTHBASELINE_OTP_CONFIRM_TTL_SECONDS": str(CONFIRM_TTL),
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
    for f in FAILED:
        print("   ·", f)
    print("  结论：%s" % ("PASS ✅ 二次确认只认一次性凭据，且旧口令通道在六个端点上都不存在"
                       if not FAILED else "FAIL ❌"))
    print("=" * 78)
    return 0 if not FAILED else 1


def run(probe_db):
    # ── 0. 准备 ────────────────────────────────────────────────
    print("\n[0] 准备：链值登录 admin（链由空库播种建好）")
    st, b = login_otp("admin", PW)
    ticket = (b.get("data") or {}).get("ticket")
    check("0.1 链值登录成功并拿到票据", st == 200 and bool(ticket), "HTTP %s" % st)
    # P8：链在空库播种时就建好了（k=N-1），这次登录核销一格 ⇒ N-2。
    # 以前这里是"口令登录触发懒迁移 → k=N-1"，那条路已经不存在。
    check("0.2 链已建好且本次登录核销了一格（k=N-2）", k_of(probe_db) == N - 2,
          "k=%r" % k_of(probe_db))
    if not ticket:
        return

    # ── 1. 入参校验：这些都不该消耗链、也不该计次 ──────────────
    print("\n[1] 入参校验")
    data = challenge()
    good = b64(iterate(root(PW, data["r"]), data["k"]))

    st, b = http_call(BASE, "POST", "/api/auth/reconfirm",
                      {"purpose": "face-enroll", "otpCode": good}, ticket=None)
    check("1.1 无票据 → 401（身份只由票据回答）", st == 401, "HTTP %s / %s" % (st, b.get("code")))

    st, b = http_call(BASE, "POST", "/api/auth/reconfirm",
                      {"purpose": "delete-everything", "otpCode": good}, ticket=ticket)
    check("1.2 未知用途 → 400 INVALID_PURPOSE", st == 400 and b.get("code") == "INVALID_PURPOSE",
          "HTTP %s / %s" % (st, b.get("code")))

    st, b = http_call(BASE, "POST", "/api/auth/reconfirm",
                      {"purpose": "create-account", "otpCode": good}, ticket=ticket)
    check("1.3 管理类用途缺目标 → 400 EMPTY_FIELDS", st == 400 and b.get("code") == "EMPTY_FIELDS",
          "HTTP %s / %s" % (st, b.get("code")))

    st, b = http_call(BASE, "POST", "/api/auth/reconfirm",
                      {"purpose": "face-enroll", "otpCode": ""}, ticket=ticket)
    check("1.4 缺链值 → 400 EMPTY_FIELDS", st == 400 and b.get("code") == "EMPTY_FIELDS",
          "HTTP %s / %s" % (st, b.get("code")))

    check("1.5 以上四次都没消耗链", k_of(probe_db) == N - 2, "k=%r" % k_of(probe_db))

    # ── 2. 成功路径 ────────────────────────────────────────────
    print("\n[2] 正确链值 → 签发确认凭据")
    k_before = k_of(probe_db)
    st, b = reconfirm(ticket, "face-enroll")
    tok_enroll = token_of(b)
    check("2.1 200 且拿到凭据", st == 200 and len(tok_enroll) == 43, "HTTP %s / len=%d" % (st, len(tok_enroll)))
    check("2.2 回显用途与目标（本人）",
          (b.get("data") or {}).get("purpose") == "face-enroll" and (b.get("data") or {}).get("target") == "admin",
          str(b.get("data")))
    check("2.3 有效期取自配置（3s）", (b.get("data") or {}).get("expiresInSeconds") == CONFIRM_TTL,
          str((b.get("data") or {}).get("expiresInSeconds")))
    check("2.4 核销了一格", k_of(probe_db) == k_before - 1, "k %r → %r" % (k_before, k_of(probe_db)))

    consumes = [d for d in audit_docs(probe_db, "OTP_CONSUME", "admin")
                if bag(d.get("response")).get("Purpose") == "RECONFIRM"]
    check("2.5 审计 OTP_CONSUME 标明 Purpose=RECONFIRM（分得清这一格被谁吃掉）",
          len(consumes) == 1, "找到 %d 条" % len(consumes))
    check("2.6 核销审计里没有链值本身",
          all(good not in json.dumps(d, default=str) for d in consumes),
          "链值出现在审计里")

    recon = audit_docs(probe_db, "OTP_RECONFIRM", "admin")
    check("2.7 审计 OTP_RECONFIRM 一条", len(recon) == 1, "找到 %d 条" % len(recon))
    rbag = bag(recon[0].get("response")) if recon else {}
    check("2.8 该审计记下用途与目标、且不含链值",
          rbag.get("Purpose") == "face-enroll" and rbag.get("Target") == "admin"
          and tok_enroll not in json.dumps(recon, default=str), str(rbag))

    # ── 3. 一次性与绑定 ────────────────────────────────────────
    print("\n[3] 一次性与绑定")
    st, b = reconfirm(ticket, "face-delete")
    tok_del = token_of(b)
    st, b = http_call(BASE, "POST", "/api/auth/face/delete", {"confirmToken": tok_del}, ticket=ticket)
    check("3.1 凭据在它自己的端点上可用（face/delete → 200）",
          st == 200 and b.get("success") is True, "HTTP %s / %s" % (st, b.get("code")))
    st, b = http_call(BASE, "POST", "/api/auth/face/delete", {"confirmToken": tok_del}, ticket=ticket)
    check("3.2 同一张凭据第二次 → 401 OTP_CONFIRM_REQUIRED（一次性）",
          st == 401 and b.get("code") == "OTP_CONFIRM_REQUIRED", "HTTP %s / %s" % (st, b.get("code")))

    st, b = reconfirm(ticket, "face-enroll")
    tok_misuse = token_of(b)
    st2, b2 = http_call(BASE, "POST", "/api/auth/face/delete", {"confirmToken": tok_misuse}, ticket=ticket)
    check("3.3 用途不符（录入的票去删人脸）→ 401", st2 == 401 and b2.get("code") == "OTP_CONFIRM_REQUIRED",
          "HTTP %s / %s" % (st2, b2.get("code")))
    st3, b3 = http_call(BASE, "POST", "/api/auth/face/delete", {"confirmToken": tok_misuse}, ticket=ticket)
    check("3.4 用途不符的那次也已把它作废（不能换个端点再试）",
          st3 == 401 and b3.get("code") == "OTP_CONFIRM_REQUIRED", "HTTP %s / %s" % (st3, b3.get("code")))

    st, b = reconfirm(ticket, "create-account", target="p5target")
    tok_target = token_of(b)
    st2, b2 = http_call(BASE, "POST", "/api/auth/create-account", {
        "username": "p5other", "password": PW2, "role": "User", "confirmToken": tok_target,
    }, ticket=ticket)
    check("3.5 目标不符（给 p5target 的票去建 p5other）→ 401",
          st2 == 401 and b2.get("code") == "OTP_CONFIRM_REQUIRED", "HTTP %s / %s" % (st2, b2.get("code")))
    check("3.6 那次没有建出账号", probe_db["Users"].find_one({"username": "p5other"}) is None)

    # ── 4. 新路径端到端：用确认凭据建一个账号 ───────────────────
    print("\n[4] 新路径端到端：确认凭据 → 真正建出账号")
    st, b = reconfirm(ticket, "create-account", target=U2)
    tok_create = token_of(b)
    check("4.1 为 create-account 签出凭据", st == 200 and bool(tok_create), "HTTP %s / %s" % (st, b.get("code")))

    st, b = http_call(BASE, "POST", "/api/auth/create-account", {
        "username": U2, "password": PW2, "role": "User", "confirmToken": tok_create,
    }, ticket=ticket)
    check("4.2 凭据驱动建号成功（**没有传操作者口令**）", st == 200 and b.get("success") is True,
          "HTTP %s / %s" % (st, b.get("code")))
    u2 = probe_db["Users"].find_one({"username": U2})
    # UserRole 用 BsonType.String 存（"User" / "Admin" / ...），不是数字
    check("4.3 库里确实出现了该账号、且角色为普通用户",
          u2 is not None and u2.get("role") == "User", "role=%r" % (u2 or {}).get("role"))

    st, b = login_otp(U2, PW2)
    ticket2 = (b.get("data") or {}).get("ticket")
    check("4.4 新账号能正常登录", st == 200 and bool(ticket2), "HTTP %s" % st)

    # ── 5. 过期 ────────────────────────────────────────────────
    print("\n[5] 过期（TTL=%ds）" % CONFIRM_TTL)
    st, b = reconfirm(ticket, "face-enroll")
    tok_expire = token_of(b)
    k_before = k_of(probe_db)
    check("5.1 签出凭据（此刻有效）", st == 200 and bool(tok_expire), "HTTP %s" % st)
    time.sleep(CONFIRM_TTL + 0.6)
    st, b = http_call(BASE, "POST", "/api/auth/face/delete", {"confirmToken": tok_expire}, ticket=ticket)
    check("5.2 过期后 → 401 OTP_CONFIRM_REQUIRED",
          st == 401 and b.get("code") == "OTP_CONFIRM_REQUIRED", "HTTP %s / %s" % (st, b.get("code")))
    check("5.3 签发票本身不消耗链（只在核销时才算数）", k_of(probe_db) == k_before,
          "k %r → %r" % (k_before, k_of(probe_db)))

    # ── 6. 归属：别人的票不能用（必须排在节流之前）──────────────
    print("\n[6] 归属：别人的确认凭据不能用")
    st, b = reconfirm(ticket, "face-enroll")
    tok_admin = token_of(b)
    check("6.0 admin 签出一张凭据", st == 200 and bool(tok_admin), "HTTP %s / %s" % (st, b.get("code")))
    if ticket2:
        st, b = http_call(BASE, "POST", "/api/auth/face/delete",
                          {"confirmToken": tok_admin}, ticket=ticket2)   # u2 拿去用
        check("6.1 u2 拿着 admin 的确认 → 401",
              st == 401 and b.get("code") == "OTP_CONFIRM_REQUIRED", "HTTP %s / %s" % (st, b.get("code")))
        st, b = http_call(BASE, "POST", "/api/auth/face/delete",
                          {"confirmToken": tok_admin}, ticket=ticket)    # 还给 admin 也不能用
        check("6.2 被旁人试过之后，原主也不能再用（验之前先删）",
              st == 401 and b.get("code") == "OTP_CONFIRM_REQUIRED", "HTTP %s / %s" % (st, b.get("code")))

    # ── 7. 节流：封这条路，但不封登录 ──────────────────────────
    print("\n[7] 连续错误链值 → 节流（且不影响登录）")
    data = challenge()
    wrong = b64(iterate(root(PW, data["r"]), max(1, data["k"] - 1)))   # 相邻格：H(它) ≠ v
    codes = []
    for _ in range(5):
        st, b = reconfirm(ticket, "face-enroll", code=wrong)
        codes.append((st, b.get("code")))
    check("7.1 前 5 次都是 401（还没封）",
          all(c == (401, "OTP_CONFIRM_REQUIRED") for c in codes), str(codes))

    st, b = reconfirm(ticket, "face-enroll")
    check("7.2 第 6 次 → 429 OTP_RECONFIRM_THROTTLED（即使链值是对的）",
          st == 429 and b.get("code") == "OTP_RECONFIRM_THROTTLED", "HTTP %s / %s" % (st, b.get("code")))

    admin = probe_db["Users"].find_one({"username": "admin"})
    check("7.3 **登录失败计数仍是 0**（再认证失败没进那个计数器）",
          (admin.get("failedLoginAttempts") or 0) == 0, "failedLoginAttempts=%r" % admin.get("failedLoginAttempts"))
    check("7.4 账号没被锁（status 仍为启用，不是 Locked）", admin.get("status") == "Enabled",
          "status=%r" % admin.get("status"))

    st, b = login_otp("admin", PW)
    check("7.5 被节流期间**登录照常成功**（封的是这条路，不是这个账号）",
          st == 200 and bool((b.get("data") or {}).get("ticket")), "HTTP %s / %s" % (st, b.get("code")))

    fails = audit_docs(probe_db, "OTP_RECONFIRM_FAILED", "admin")
    check("7.6 审计留下 ≥5 条 OTP_RECONFIRM_FAILED（对用户静默 ≠ 对系统静默）",
          len(fails) >= 5, "找到 %d 条" % len(fails))
    login_fails = [d for d in audit_docs(probe_db, "LOGIN_FAILED") if d.get("target") == "admin"]
    check("7.7 这些失败**没有**变成 LOGIN_FAILED", len(login_fails) == 0, "找到 %d 条" % len(login_fails))

    # ── 8. 六处确认：旧口令路径已不存在（P8）─────────────────────
    #
    # P5 时这一节断言的是"旧口令路径逐字不变"（错误口令 401 + 计次 + 原话术），
    # 那是**回滚能力**的判据：模块关掉后前端能立刻退回老路。
    # P8 删掉口令路径之后，判据翻面，而且比原来更硬：
    #   不是"旧路还能用"，而是"旧路根本不在" —— 六个端点全部只认一次性确认票。
    # 判据选 401 OTP_CONFIRM_REQUIRED 而不是 400：
    #   带口令的请求本身是**完整**的（用户名、目标、口令都有），
    #   它失败的原因是"没有确认票"，这正是 401 要表达的意思。
    print("\n[8] 六处确认：带口令不带票 ⇒ 全部 401（旧路径已不存在）")

    six = [
        ("/api/auth/face/enroll", {"password": PW2},
         "face/enroll（人脸第二因子录入）"),
        ("/api/auth/face/delete", {"password": PW2},
         "face/delete（人脸第二因子删除）"),
        ("/api/faceid/enroll", {"password": PW2},
         "faceid/enroll（纯人脸录入）"),
        ("/api/faceid/delete", {"password": PW2},
         "faceid/delete（纯人脸删除）"),
        ("/api/auth/create-account",
         {"username": "p5never", "password": PW2, "role": "User", "operatorPassword": PW},
         "create-account（管理员建号）"),
        ("/api/auth/set-role",
         {"username": U2, "role": "UserAdmin", "operatorPassword": PW},
         "set-role（管理员任免角色）"),
    ]

    # 注意：这些请求**带票据**（会话是有效的），失败只因为缺确认票。
    # 这样才分得清"没登录"和"没确认" —— 否则测出来的只是 401 而已。
    for path, body, label in six:
        st, b = http_call(BASE, "POST", path, body, ticket=ticket)
        check("8.x %s：口令不再被受理 ⇒ 401 OTP_CONFIRM_REQUIRED" % label,
              st == 401 and b.get("code") == "OTP_CONFIRM_REQUIRED",
              "HTTP %s / %s" % (st, b.get("code")))

    # 副作用面：被拒的请求不能留下半个结果
    check("8.7 那六次全部没有副作用：没建出账号",
          probe_db["Users"].find_one({"username": "p5never"}) is None)
    u2_doc = probe_db["Users"].find_one({"username": U2}) or {}
    check("8.8 那六次全部没有副作用：u2 角色未变",
          u2_doc.get("role") == "User", "role=%r" % u2_doc.get("role"))
    admin = probe_db["Users"].find_one({"username": "admin"}) or {}
    check("8.9 这些拒绝**不计入**登录失败计数（不是凭据猜测，是缺票）",
          (admin.get("failedLoginAttempts") or 0) == 0,
          "failedLoginAttempts=%r" % admin.get("failedLoginAttempts"))

    # ── 9. 收尾 ────────────────────────────────────────────────
    print("\n[9] 收尾")
    st, b = login_otp("admin", PW)
    check("9.1 admin 仍能口令登录", st == 200, "HTTP %s / %s" % (st, b.get("code")))
    doc = chain_of(probe_db)
    check("9.2 链仍在、代数未变（本阶段不做续期）",
          doc is not None and doc["generation"] == 1, "gen=%r" % (doc or {}).get("generation"))
    check("9.3 u2 的链也已建好（登录即迁移）", chain_of(probe_db, U2) is not None)


if __name__ == "__main__":
    sys.exit(main())
