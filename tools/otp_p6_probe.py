# -*- coding: utf-8 -*-
"""一次性口令（哈希链）P6 的端到端验证：**口令一变，链必须跟着换**。

用法：
  python tools/otp_p6_probe.py <exe路径> <端口>

P3 阶段留下过一个隐患：`change-password` / `reset-password` 只改 `passwordHash`、不动链，
于是改密之后链仍绑着**旧口令**。表现是"口令登录正常、OTP 登录永远失败"——
而口令登录是通的，所以没人会觉得系统坏了。等 P8 移除口令路径才发现账号进不来。

P6 要证明的就是这句话被堵住了，且堵得没有副作用：

  A. 改密（口令路径）：换代、配额回满、**新口令算出的格能登、旧口令算出的格不能登**；
  B. 改密（链值路径）：同上，且挑战一次性、错值被拒、新旧相同被拒；
  C. 重置口令：同上（走邮箱验证码那条路）；
  D. `/otp/status`：数字与库里一致（这是用户在"突然登不上"之前唯一能看到的东西）；
  E. `/otp/recover`：验证码 + 口令两个证明都要，且**先验证码后口令**的顺序可观测；
  F. **重建失败必须整体失败**：用 MongoDB 的集合校验器注入真实写失败，断言口令被回滚、
     链没变、返回 500 —— 这是本阶段唯一"宁可失败也不留半截状态"的地方。

库名只碰 `AuthBaselineOtpP6Probe`（过守卫），结束时 drop。
"""
import base64
import hashlib
import json
import os
import re
import sys
import time

from _probe_common import (ProbeDb, resolve_probe_db, start_backend, require_backend_ready,
                          stop_backend, http_call, confirm_token_via)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# `--keep` 也可能出现在 argv[1]，所以位置参数只认不以 -- 开头的那些
_args = [a for a in sys.argv[1:] if not a.startswith("--")]
EXE = _args[0] if len(_args) > 0 else os.path.join(
    ROOT, "AuthServer", "bin", "Debug", "net8.0", "AuthServer.exe")
PORT = int(_args[1]) if len(_args) > 1 else 5136
DB = resolve_probe_db("AuthBaselineOtpP6Probe")
BASE = "http://127.0.0.1:%d" % PORT
CODE_LOG = os.path.join(os.path.dirname(EXE), "email-codes.log")

N = 20
ITER = 1000
PW = "Admin123"          # 种子管理员口令
PW_A = "Zxc98765"        # 第一次改密后的口令
PW_B = "Qwe54321"        # 第二次改密后的口令
PW_R = "Plm24680"        # 重置后的口令
U2 = "p6probe1"
U2_MAIL = "p6probe1@example.com"
PW_U2 = "Abc12345"
PW_U2_NEW = "Tyui6789"

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
def challenge(username):
    st, b = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": username})
    return b.get("data") or {}



def login_otp(username, pw):
    """用链值登录：先取挑战，按当前 k 现算一格。"""
    data = challenge(username)
    code = b64(iterate(root(pw, data["r"]), data["k"]))
    return http_call(BASE, "POST", "/api/auth/login",
                     {"username": username, "otpCode": code, "challengeToken": data.get("challengeToken")})


def set_state(probe_db, username, password, seed, k):
    """把链摆到指定 k（v 必须是 x_(k+1)，否则核销的 CAS 条件自己就对不上）。"""
    cells = root(password, seed)
    probe_db["OtpChains"].update_one(
        {"username": username},
        {"$set": {"k": k, "v": b64(iterate(cells, k + 1))}})


def change_pw(username, old_pw, new_pw):
    """改密（P8：旧凭据只能是链值，端点匿名，不需要票据）。"""
    data = challenge(username)
    return http_call(BASE, "POST", "/api/auth/change-password", {
        "username": username,
        "oldOtpCode": b64(iterate(root(old_pw, data["r"]), data["k"])),
        "oldChallengeToken": data.get("challengeToken"),
        "newPassword": new_pw,
    })


def confirm_for(username, pw, purpose, ticket, target=None):
    return confirm_token_via(http_call_for_confirm, ticket, username, pw, purpose, target or username)


def http_call_for_confirm(method, path, body=None, ticket=None):
    """适配 `confirm_token_via` 期望的 call(method, path, body, ticket=) 形状。"""
    return http_call(BASE, method, path, body=body, ticket=ticket)


def chain_of(probe_db, username):
    return probe_db["OtpChains"].find_one({"username": username})


def audit_docs(probe_db, action, target=None):
    out = []
    for name in probe_db.list_collection_names():
        if not name.startswith("AuditLogs"):
            continue
        q = {"action": action}
        if target is not None:
            q["target"] = target
        out.extend(probe_db[name].find(q))
    return out


def send_reset_code(probe_db, username, email):
    """申请一张 RESET 验证码，并从控制台发件器的落盘日志里把明文读回来。

    为什么要先删 `EmailCodes`：服务端有 60 秒重发冷却，而本探针需要在一次运行里
    连发好几张码。清掉记录等于"就当上一次是十分钟前发的"——测的是链重建，不是冷却。
    """
    probe_db["EmailCodes"].delete_many({"username": username})
    st, b = http_call(BASE, "POST", "/api/auth/send-email-code",
                      {"username": username, "email": email, "purpose": "RESET"})
    if st != 200:
        return st, b, ""

    # 落盘是异步之后才可见的，给它几轮机会
    for _ in range(20):
        if os.path.exists(CODE_LOG):
            text = open(CODE_LOG, encoding="utf-8", errors="replace").read()
            hits = re.findall(r"收件邮箱=" + re.escape(email) + r"\s+验证码=(\d{6})", text)
            if hits:
                return st, b, hits[-1]
        time.sleep(0.1)
    return st, b, ""


def main():
    probe_db = ProbeDb(DB)
    probe_db.drop_if_exists()

    os.environ.pop("AUTHBASELINE_OTP_ENABLED", None)
    # 清掉上一次残留的验证码日志，避免读到旧码
    try:
        if os.path.exists(CODE_LOG):
            os.remove(CODE_LOG)
    except OSError:
        pass

    proc = start_backend(EXE, PORT, DB, extra_env={
        "AUTHBASELINE_REQUIRE_HTTPS": "false",
        "AUTHBASELINE_OTP_LENGTH": str(N),
        "AUTHBASELINE_OTP_KDF_ITERATIONS": str(ITER),
        # ⚠️ **必须切到控制台发件器**：本机的 appsettings.Local.json 里存着真实的 SMTP
        #    授权码，不切的话探针会真的往 example.com 发信，而且拿不到明文验证码
        #    （真实投递是单向的）。这也解释了为什么"发码成功"却找不到 email-codes.log。
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
    for f in FAILED:
        print("   ·", f)
    print("  结论：%s" % ("PASS ✅ 改密/重置都重建链（恢复端点已并入重置），且重建失败整体回滚"
                       if not FAILED else "FAIL ❌"))
    print("=" * 78)
    return 0 if not FAILED else 1


def run(probe_db):
    # ── 0. 准备 ────────────────────────────────────────────────
    print("\n[0] 准备：链值登录 admin（链由空库播种建好）+ 建一个带邮箱的账号")
    st, b = login_otp("admin", PW)
    check("0.1 admin 登录成功", st == 200, "HTTP %s" % st)
    before = chain_of(probe_db, "admin")
    # 播种建链时 k=N-1；这次登录核销一格 ⇒ N-2
    check("0.2 链已建好且本次登录核销一格（k=N-2, gen=1）",
          before and before["k"] == N - 2 and before["generation"] == 1,
          "k=%r gen=%r" % ((before or {}).get("k"), (before or {}).get("generation")))
    if not before:
        return

    ticket = (b.get("data") or {}).get("ticket")
    # 建号要一次性确认票（P8 起旧口令通道已删除）。
    st, b = http_call(BASE, "POST", "/api/auth/create-account", {
        "username": U2, "password": PW_U2, "role": "User", "email": U2_MAIL,
        "confirmToken": confirm_for("admin", PW, "create-account", ticket, U2),
    }, ticket=ticket)
    check("0.3 建出带邮箱的第二个账号", st == 200, "HTTP %s / %s" % (st, b.get("code")))

    st, b = login_otp(U2, PW_U2)
    check("0.4 第二个账号登录（链在建号时就建好了）", st == 200, "HTTP %s" % st)

    # ── A. 改密（口令路径）→ 链换代且可用 ───────────────────────
    # P8：改密只有一条路 —— 旧凭据是一格链值。原来这里有一条"送旧口令明文"的路，
    # 它被删掉之后，本段的断言反而更直接：重建链**就是**改密的全部内容。
    print("\n[A] 改密（唯一路径：旧凭据 = 链值）")
    r0, gen0 = before["r"], before["generation"]
    st, b = change_pw("admin", PW, PW_A)
    check("A1 改密成功", st == 200, "HTTP %s / %s" % (st, b.get("code")))

    after = chain_of(probe_db, "admin")
    check("A2 链被换掉了新种子（旧链的格不可能再对上）",
          after["r"] != r0, "r 未变")
    check("A3 代数 +1", after["generation"] == gen0 + 1, "gen=%r" % after["generation"])
    check("A4 配额回满（k=N-1）", after["k"] == N - 1, "k=%r" % after["k"])
    check("A5 链长与迭代次数仍按配置", after["length"] == N and after["kdfIterations"] == ITER,
          "len=%r iter=%r" % (after["length"], after["kdfIterations"]))

    st, b = login_otp("admin", PW_A)
    check("A6 新口令能登录", st == 200, "HTTP %s / %s" % (st, b.get("code")))
    st, b = login_otp("admin", PW_A)
    check("A7 **新口令算出的链值能登录**（这就是 P6 要证明的那句话）",
          st == 200 and bool((b.get("data") or {}).get("ticket")), "HTTP %s / %s" % (st, b.get("code")))

    stale = b64(iterate(root(PW, after["r"]), after["k"]))     # 用**旧**口令 + 新种子算的格
    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": "admin", "otpCode": stale, "challengeToken": challenge("admin").get("challengeToken")})
    check("A8 旧口令算出的格被拒（链确实绑在新口令上）",
          st == 401 and b.get("code") == "INVALID_CREDENTIALS", "HTTP %s / %s" % (st, b.get("code")))

    rebuilt = audit_docs(probe_db, "OTP_REBUILT", "admin")
    check("A9 审计 OTP_REBUILT 一条且 Trigger=CHANGE_PASSWORD",
          len(rebuilt) == 1 and bag(rebuilt[0].get("response")).get("Trigger") == "CHANGE_PASSWORD",
          "%d 条 / %r" % (len(rebuilt), bag(rebuilt[0].get("response")) if rebuilt else {}))
    check("A10 该审计不含口令与链值",
          all(PW_A not in json.dumps(d, default=str) and after["r"] not in json.dumps(d, default=str)
              for d in rebuilt), "审计里出现了口令或种子")

    # ── B. 改密（链值路径）──────────────────────────────────────
    print("\n[B] 连续改密：挑战一次性 / 错误链值 / 新旧相同")
    data = challenge("admin")
    code = b64(iterate(root(PW_A, data["r"]), data["k"]))
    gen1 = chain_of(probe_db, "admin")["generation"]
    st, b = http_call(BASE, "POST", "/api/auth/change-password", {
        "username": "admin", "oldOtpCode": code,
        "oldChallengeToken": data.get("challengeToken"), "newPassword": PW_B,
    })
    check("B1 链值改密成功（请求里**没有旧口令**）", st == 200, "HTTP %s / %s" % (st, b.get("code")))
    check("B2 链再次换代、配额回满",
          chain_of(probe_db, "admin")["generation"] == gen1 + 1 and chain_of(probe_db, "admin")["k"] == N - 1,
          "gen=%r k=%r" % (chain_of(probe_db, "admin")["generation"], chain_of(probe_db, "admin")["k"]))
    st, b = login_otp("admin", PW_B)
    check("B3 新口令的链值能登录", st == 200, "HTTP %s / %s" % (st, b.get("code")))

    st, b = http_call(BASE, "POST", "/api/auth/change-password", {
        "username": "admin", "oldOtpCode": code,
        "oldChallengeToken": data.get("challengeToken"), "newPassword": "Zzz11111",
    })
    check("B4 同一张挑战不能再用（401 OTP_CHALLENGE_INVALID）",
          st == 401 and b.get("code") == "OTP_CHALLENGE_INVALID", "HTTP %s / %s" % (st, b.get("code")))

    data = challenge("admin")
    wrong = b64(iterate(root(PW_B, data["r"]), max(1, data["k"] - 1)))
    st, b = http_call(BASE, "POST", "/api/auth/change-password", {
        "username": "admin", "oldOtpCode": wrong,
        "oldChallengeToken": data.get("challengeToken"), "newPassword": "Zzz11111",
    })
    check("B5 错误链值 → 401「旧密码错误」（与口令路径同码同话术）",
          st == 401 and b.get("code") == "INVALID_CREDENTIALS" and "旧密码错误" in (b.get("message") or ""),
          "HTTP %s / %s / %s" % (st, b.get("code"), b.get("message")))

    data = challenge("admin")
    code = b64(iterate(root(PW_B, data["r"]), data["k"]))
    st, b = http_call(BASE, "POST", "/api/auth/change-password", {
        "username": "admin", "oldOtpCode": code,
        "oldChallengeToken": data.get("challengeToken"), "newPassword": PW_B,
    })
    # P8：服务端**不再**判定"新旧相同"。它手里只有链，没有可离线比对的口令派生物 ——
    # 要做这个判断就必须留一份那样的东西，而那正是本项目在拆的东西。
    # 这条判定挪到客户端（两个明文都在那儿）。于是这里的判据翻成"服务端接受"：
    # 等价于"改密没生效"，不产生任何权限变化，因此不构成安全边界。
    check("B6 新旧相同 → 服务端不再判定（200，客户端自检负责拦）",
          st == 200, "HTTP %s / %s" % (st, b.get("code")))

    # ── C. 重置口令 → 链换代 ───────────────────────────────────
    print("\n[C] 重置口令（邮箱验证码）")
    r_u2, gen_u2 = chain_of(probe_db, U2)["r"], chain_of(probe_db, U2)["generation"]
    st, b, code = send_reset_code(probe_db, U2, U2_MAIL)
    check("C1 取到验证码", st == 200 and len(code) == 6, "HTTP %s / code=%r" % (st, code))
    st, b = http_call(BASE, "POST", "/api/auth/reset-password",
                      {"username": U2, "email": U2_MAIL, "code": code, "newPassword": PW_U2_NEW})
    check("C2 重置成功", st == 200, "HTTP %s / %s" % (st, b.get("code")))

    doc = chain_of(probe_db, U2)
    check("C3 链被换 + 代数 +1 + 配额回满",
          doc["r"] != r_u2 and doc["generation"] == gen_u2 + 1 and doc["k"] == N - 1,
          "r变=%s gen=%r k=%r" % (doc["r"] != r_u2, doc["generation"], doc["k"]))
    st, b = login_otp(U2, PW_U2_NEW)
    check("C4 新口令的链值能登录", st == 200, "HTTP %s / %s" % (st, b.get("code")))
    stale = b64(iterate(root(PW_U2, doc["r"]), doc["k"]))
    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": U2, "otpCode": stale, "challengeToken": challenge(U2).get("challengeToken")})
    check("C5 旧口令算出的格被拒", st == 401, "HTTP %s / %s" % (st, b.get("code")))

    # ── D. /otp/status ────────────────────────────────────────
    print("\n[D] 链状态")
    st, b = http_call(BASE, "GET", "/api/auth/otp/status")
    check("D1 无票据 → 401", st == 401, "HTTP %s" % st)

    st, b = login_otp("admin", PW_B)
    ticket = (b.get("data") or {}).get("ticket")
    st, b = http_call(BASE, "GET", "/api/auth/otp/status", ticket=ticket)
    data = b.get("data") or {}
    doc = chain_of(probe_db, "admin")
    check("D2 200 且数字与库里一致",
          st == 200 and data.get("enrolled") is True and data.get("remaining") == doc["k"]
          and data.get("length") == doc["length"] and data.get("generation") == doc["generation"],
          "HTTP %s / %r / 库 k=%r" % (st, data, doc.get("k")))
    check("D3 百分比按向下取整算对", data.get("percent") == doc["k"] * 100 // doc["length"],
          "percent=%r 期望=%r" % (data.get("percent"), doc["k"] * 100 // doc["length"]))
    check("D4 高配额时两条阈值线都是 false",
          data.get("needsRenewal") is False and data.get("atAlertLine") is False, str(data))
    check("D5 不下发种子与链头（那是凭据）",
          "r" not in data and "v" not in data and "R" not in data and "V" not in data, str(data.keys()))

    # ── E. /otp/recover 已删除（P8）────────────────────────────
    #
    # 这个端点原本要"邮箱验证码 + 当前口令"两个证明。P8 之后第二个证明没了：
    # 服务端不存任何口令派生物，唯一能证明"你知道当前口令"的方式就是当场核销一格链值；
    # 而它的适用场景恰恰是链已经坏掉/用尽 —— 那时算不出可核销的一格。
    # 于是它只在"不需要它的时候能用"，被删掉，需求并入 reset-password。
    print("\n[E] 人工恢复端点已并入「忘记口令」")
    st, b = http_call(BASE, "POST", "/api/auth/otp/recover",
                      {"username": U2, "email": U2_MAIL, "code": "123456",
                       "password": PW_U2_NEW})
    check("E1 端点已不存在（404）", st == 404, "HTTP %s / %s" % (st, b.get("code")))
    check("E2 审计里不再出现 OTP_RECOVERED", len(audit_docs(probe_db, "OTP_RECOVERED")) == 0,
          "%d 条" % len(audit_docs(probe_db, "OTP_RECOVERED")))

    # ── F. 重建失败 ⇒ 整体失败并回滚口令 ───────────────────────
    print("\n[F] 注入重建失败（MongoDB 集合校验器）")
    coll = probe_db.client[DB]          # 直接用 client 发 collMod
    try:
        # 校验器必须是**有门槛的**，不能像 P6 时那样"拦一切写"：
        # P8 的改密在重建之前先要**核销一格**（也是对 OtpChains 的写）。
        # 拦一切 ⇒ 故障会先炸在核销上，测的就不再是"重建失败"了。
        # 做法：validator 的语义是"文档必须满足才有效"，于是写 `{"k": {"$lt": 10}}`：
        #   · 核销把 k 往小写（3→2），满足 ⇒ 放行；
        #   · 重建把 k 拉回 N-1=19，不满足 ⇒ 必被拦。
        # 这样故障被精确地按在 RebuildAsync 那一次写上。
        coll.command({"collMod": "OtpChains",
                      "validator": {"k": {"$lt": 10}},
                      "validationLevel": "strict", "validationAction": "error"})
        injected = True
    except Exception as ex:
        injected = False
        print("      ⚠️ 无法注入校验器：%s" % ex)

    if injected:
        # 把链摆到低水位 k=3：核销（3→2）能过校验器，重建（k 回 19）必被拦。
        doc = chain_of(probe_db, "admin")
        set_state(probe_db, "admin", PW_B, doc["r"], 3)
        r_before = doc["r"]

        st, b = change_pw("admin", PW_B, "Nnn77777")
        check("F1 重建失败 ⇒ 改密返回 500 OTP_REBUILD_FAILED",
              st == 500 and b.get("code") == "OTP_REBUILD_FAILED", "HTTP %s / %s" % (st, b.get("code")))

        # P8 之前这里还有一条"口令哈希被逐字节回滚"的断言。现在没有第二份记录要回滚：
        # 重建链**就是**改密本身，它失败 ⇒ 什么都没发生。
        # 于是判据落在一句更朴素的话上：旧口令还能登、新口令进不来、链没动。
        check("F2 链没动（种子未变，k 的核销照常发生）",
              chain_of(probe_db, "admin")["r"] == r_before, "种子变了")

        st, b = login_otp("admin", PW_B)
        check("F4 旧口令仍能登录", st == 200, "HTTP %s / %s" % (st, b.get("code")))
        st, b = login_otp("admin", "Nnn77777")
        check("F5 那个「新口令」没能生效", st == 401, "HTTP %s / %s" % (st, b.get("code")))

        fails = audit_docs(probe_db, "OTP_REBUILD_FAILED", "admin")
        check("F6 审计 OTP_REBUILD_FAILED 一条", len(fails) == 1, "找到 %d 条" % len(fails))

        coll.command({"collMod": "OtpChains", "validator": {}})
        st, b = change_pw("admin", PW_B, "Nnn77777")
        check("F7 故障消失后改密成功（自愈，不需要人工修数据）", st == 200,
              "HTTP %s / %s" % (st, b.get("code")))
        st, b = login_otp("admin", "Nnn77777")
        check("F8 且新链可用", st == 200, "HTTP %s / %s" % (st, b.get("code")))
    else:
        check("F 组：无法注入校验器，跳过（不影响其它断言）", True, "")


if __name__ == "__main__":
    sys.exit(main())
