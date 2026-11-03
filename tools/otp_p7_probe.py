# -*- coding: utf-8 -*-
"""一次性口令（哈希链）P7 的端到端验证：**客户端真正这么做的时候，服务端认不认**。

用法：
  python tools/otp_p7_probe.py <exe路径> <端口>

P7 之前，链值只出现在探针里（Python 算、Python 发）。P7 把这套计算搬进了 Rust，
并让 Vue 侧按"取参 → 算值 → 换票"三步走。于是本阶段的验证对象变成了**协议形状**：

  A. 客户端要的参数齐不齐：一次 `login/challenge` 是否足以算出 `x_k`；
     用它算出来的值能否登录；响应里是否**没有**任何链内部值（`r` / `v` / `k`）。
  B. 续期的请求体：Vue 发的是 `nextChain: { r, head }`（**camelCase 合并后的形状**），
     服务端必须认；认了之后旧种子失效、新种子生效。
  C. 确认凭据的整条链路：`challenge → 算值 → /auth/reconfirm → confirmToken`
     再拿它去驱动六个敏感接口 —— 请求体里**不含任何口令字段**。
  D. 回退：`AUTHBASELINE_OTP_ENABLED=false` 时挑战端点回 404 `OTP_DISABLED`（客户端据此降级），
     而口令登录逐字不变。
  E. 耗时：把"客户端增量"拆成三段量出来（挑战往返 / 客户端计算 / 登录往返），
     判据是总数 < 200 ms。客户端计算那一段取 Rust 侧 `cargo test` 的实测值。

库名只碰 `AuthBaselineOtpP7Probe`（过守卫），结束时 drop。

⚠️ 这个探针**不替代** Rust 单测：`x_k` 的算法一致性由 `src-tauri/src/otp.rs` 里的固定向量
   钉住（同口令/盐/迭代/k → 同一 Base64），本文件不重复验算那条。
"""
import base64
import hashlib
import json
import os
import sys
import time

from _probe_common import (
    ProbeDb,
    resolve_probe_db,
    start_backend,
    require_backend_ready,
    stop_backend,
    http_call,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_args = [a for a in sys.argv[1:] if not a.startswith("--")]
EXE = _args[0] if len(_args) > 0 else os.path.join(
    ROOT, "AuthServer", "bin", "Debug", "net8.0", "AuthServer.exe")
PORT = int(_args[1]) if len(_args) > 1 else 5150
DB = resolve_probe_db("AuthBaselineOtpP7Probe")
BASE = "http://127.0.0.1:%d" % PORT

N = 20
ITER = 1000
PW = "Admin123"

# Rust 侧 `cargo test --lib otp::tests::timing_report -- --nocapture` 的实测值（release，151 行本机）。
# 单次登录（不算续期）约为它的一半 —— 那个值也直接量在下面 A5 里，不靠推算。
RUST_MEASURED_RENEW_MS = 30.9

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print("  [%s] %s%s" % ("OK  " if cond else "FAIL", name, ("  ← " + detail) if detail and not cond else ""))


# ---------------------------------------------------------------- 独立实现（与 Rust 侧同一套向量）
def root(password, r, iterations=ITER):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), r.encode("utf-8"), iterations, dklen=32)


def iterate(x, times):
    for _ in range(times):
        x = hashlib.sha256(x).digest()
    return x


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def code_at(password, r, k, iterations=ITER):
    return b64(iterate(root(password, r, iterations), k))


def new_seed():
    """模拟 Rust 侧的 `NewSeed`：20 字节 CSPRNG → 32 位 Base32。"""
    data = os.urandom(20)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    out, buffer, bits = [], 0, 0
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(alphabet[(buffer >> bits) & 0x1F])
    if bits:
        out.append(alphabet[(buffer << (5 - bits)) & 0x1F])
    return "".join(out)


def challenge(username):
    st, body = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": username})
    return st, body, (body.get("data") or {})


def login_otp(username, code, token, next_chain=None):
    return http_call(BASE, "POST", "/api/auth/login", {
        "username": username,
        "otpCode": code,
        "challengeToken": token,
        "nextChain": next_chain,
    })


def audit_count(db, action, target=None):
    query = {"action": action}
    if target:
        query["target"] = target
    total = 0
    for name in db.list_collection_names():
        if name.startswith("AuditLogs"):
            total += db[name].count_documents(query)
    return total


def main():
    db = ProbeDb(DB)
    db.drop_if_exists()

    proc = start_backend(EXE, PORT, DB, extra_env={
        "AUTHBASELINE_REQUIRE_HTTPS": "false",
        "AUTHBASELINE_OTP_LENGTH": str(N),
        "AUTHBASELINE_OTP_KDF_ITERATIONS": str(ITER),
    })

    try:
        require_backend_ready(BASE, proc)

        # ── A0. 首次登录 = 链值（链在空库播种时就建好了）────────────────
        # P7 时这里是"口令首登 → 服务端就地建链"（懒迁移）。
        # P8 删掉口令路径之后，懒迁移随之消失：链在播种那一刻就存在，
        # 客户端第一次登录就直接走链值 —— 顺序变短了，不是绕过了。
        print("\n[A0] 首次登录：链值路径（链由播种建好）")
        _, _, ch0 = challenge("admin")
        st, body = login_otp("admin", code_at(PW, ch0["r"], ch0["k"]), ch0["challengeToken"])
        check("A0.1 链值首登成功", st == 200 and bool((body.get("data") or {}).get("ticket")),
              "HTTP %s / %s" % (st, body.get("code")))
        check("A0.2 库里有链（播种时建好，不依赖任何登录）",
              db["OtpChains"].count_documents({"username": "admin"}) == 1,
              "链数量 %d" % db["OtpChains"].count_documents({"username": "admin"}))

        # ── A. 客户端要的参数够不够、算出来的值认不认 ────────────────────
        print("\n[A] 一次 challenge 能否支撑客户端算完并登录")

        t0 = time.perf_counter()
        st, body, ch = challenge("admin")
        t_challenge = (time.perf_counter() - t0) * 1000
        check("A1 challenge 成功", st == 200 and bool(ch.get("challengeToken")),
              "HTTP %s / %s" % (st, body.get("code")))

        need = {"challengeToken", "r", "k", "n", "iterations", "algorithm", "kdf", "expiresInSeconds"}
        check("A2 客户端所需的字段一个不缺", need.issubset(set(ch.keys())),
              "缺 %s" % (need - set(ch.keys())))
        check("A3 参数与配置一致（N/迭代/R 形状）",
              ch.get("n") == N and ch.get("iterations") == ITER
              and len(ch.get("r") or "") == 32,
              "n=%s iter=%s r=%r" % (ch.get("n"), ch.get("iterations"), ch.get("r")))

        # 客户端就是这么算的：x0 = PBKDF2(口令, UTF8(R)) → 迭代 k 次
        t0 = time.perf_counter()
        code = code_at(PW, ch["r"], ch["k"])
        t_compute = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        st, body = login_otp("admin", code, ch["challengeToken"])
        t_login = (time.perf_counter() - t0) * 1000
        data = body.get("data") or {}
        check("A4 客户端算出的格被接受", st == 200 and bool(data.get("ticket")),
              "HTTP %s / %s" % (st, body.get("code")))

        leaked = [k for k in ("r", "v", "k", "n", "otpCode") if k in data]
        check("A5 登录响应里没有链内部值", not leaked, "泄露了 %s" % leaked)

        # ── B. 续期请求体的形状（Vue 发的是 camelCase 合并体） ────────────
        print("\n[B] 续期：Vue 那样发 nextChain，服务端认不认")
        print("      基准：客户端单次计算 ≈ Rust 实测 %.1f ms（含续期时 %.1f ms）"
              % (RUST_MEASURED_RENEW_MS / 2, RUST_MEASURED_RENEW_MS))

        # 把 k 压到续期线以内（N=20 ⇒ k ≤ 1）。每登一次消耗一格。
        _, st_body = http_call(BASE, "GET", "/api/auth/otp/status", None, ticket=data["ticket"])
        k_now = (st_body.get("data") or {}).get("remaining", -1)
        print("      当前剩余 %s 格" % k_now)

        while k_now > 1:
            st, body, ch = challenge("admin")
            code = code_at(PW, ch["r"], ch["k"])
            st, body = login_otp("admin", code, ch["challengeToken"])
            assert st == 200, "驱动链时登录失败：%s %s" % (st, body.get("code"))
            _, st_body = http_call(BASE, "GET", "/api/auth/otp/status", None,
                                   ticket=(body.get("data") or {})["ticket"])
            k_now = (st_body.get("data") or {}).get("remaining", -1)

        check("B1 已把链驱动到续期窗口（k ≤ N×5%）", k_now <= N * 5 // 100, "k=%s" % k_now)

        # 现在发一次带 nextChain 的登录 —— 形状与 Vue 完全一致：{ r, head }
        st, body, ch = challenge("admin")
        code = code_at(PW, ch["r"], ch["k"])
        nxt_r = new_seed()
        nxt_head = b64(iterate(root(PW, nxt_r), N))
        st, body = login_otp("admin", code, ch["challengeToken"], {"r": nxt_r, "head": nxt_head})
        check("B2 带 nextChain 的登录成功（camelCase 请求体被接受）",
              st == 200 and bool((body.get("data") or {}).get("ticket")),
              "HTTP %s / %s" % (st, body.get("code")))

        row = db["OtpChains"].find_one({"username": "admin"}) or {}
        check("B3 换代成功（种子换成新的、代数 +1、k 回满）",
              row.get("r") == nxt_r and row.get("generation", 0) >= 2 and row.get("k") == N - 1,
              "r 一致=%s gen=%s k=%s" % (row.get("r") == nxt_r, row.get("generation"), row.get("k")))

        # 换代之后必须还能继续登：用**新种子**算一格交上去。
        # 这一条同时排除了"链被写坏、只是字段看起来对"的情况。
        st, body, ch_new = challenge("admin")
        st, body = login_otp("admin", code_at(PW, nxt_r, ch_new["k"]), ch_new["challengeToken"])
        check("B4 新种子确实生效（换代后仍能继续登）", st == 200,
              "HTTP %s / %s" % (st, body.get("code")))
        ticket = (body.get("data") or {}).get("ticket")

        # ── C. 确认凭据的整条链路 ────────────────────────────────────
        print("\n[C] reconfirm：一格链值 → 一张确认凭据 → 驱动敏感接口")

        st, body, ch = challenge("admin")
        st, body = http_call(BASE, "POST", "/api/auth/reconfirm", {
            "purpose": "create-account", "target": "p7probe1", "otpCode": code_at(PW, ch["r"], ch["k"]),
        }, ticket=ticket)
        confirm_token = (body.get("data") or {}).get("confirmToken")
        check("C1 换票成功（用途 + 目标都绑定）",
              st == 200 and bool(confirm_token), "HTTP %s / %s" % (st, body.get("code")))
        check("C2 回执里回显用途与目标",
              (body.get("data") or {}).get("purpose") == "create-account"
              and (body.get("data") or {}).get("target") == "p7probe1")

        # 用这张票建号：请求体里**没有** operatorPassword
        st, body = http_call(BASE, "POST", "/api/auth/create-account", {
            "username": "p7probe1", "password": "Abc12345", "role": "User",
            "confirmToken": confirm_token,
        }, ticket=ticket)
        check("C3 确认凭据驱动 create-account（请求体无口令字段）",
              st == 200, "HTTP %s / %s" % (st, body.get("code")))

        # 同一张票再用一次：必须拒（一次性）
        st, body = http_call(BASE, "POST", "/api/auth/create-account", {
            "username": "p7probe2", "password": "Abc12345", "role": "User",
            "confirmToken": confirm_token,
        }, ticket=ticket)
        check("C4 同一张凭据用第二次被拒", st == 401 and body.get("code") == "OTP_CONFIRM_REQUIRED",
              "HTTP %s / %s" % (st, body.get("code")))

        # 用途不符：拿 set-role 的票去建号
        st, body, ch = challenge("admin")
        st, body = http_call(BASE, "POST", "/api/auth/reconfirm", {
            "purpose": "set-role", "target": "p7probe1", "otpCode": code_at(PW, ch["r"], ch["k"]),
        }, ticket=ticket)
        wrong_purpose_token = (body.get("data") or {}).get("confirmToken")
        check("C5 另一用途的票签发成功", st == 200 and bool(wrong_purpose_token))
        st, body = http_call(BASE, "POST", "/api/auth/create-account", {
            "username": "p7probe3", "password": "Abc12345", "role": "User",
            "confirmToken": wrong_purpose_token,
        }, ticket=ticket)
        check("C6 用途不符被拒（凭据绑定用途）",
              st == 401 and body.get("code") == "OTP_CONFIRM_REQUIRED",
              "HTTP %s / %s" % (st, body.get("code")))

        # 自助用途：目标恒为本人，客户端即使不传 target 也成立
        st, body, ch = challenge("admin")
        st, body = http_call(BASE, "POST", "/api/auth/reconfirm", {
            "purpose": "face-enroll", "otpCode": code_at(PW, ch["r"], ch["k"]),
        }, ticket=ticket)
        check("C7 自助用途可省略 target（服务端归一为本人）",
              st == 200 and (body.get("data") or {}).get("target") == "admin",
              "HTTP %s / %s / target=%s" % (st, body.get("code"), (body.get("data") or {}).get("target")))

        # ── D. 客户端耗时的三段拆分 ──────────────────────────────────
        print("\n[D] 登录耗时（判据：客户端增量 < 200 ms）")
        # 对照组改成 challenge 纯往返（不含任何密码学）：
        # 口令路径已删除，"比口令快多少"这个问题不再成立 —— 但"客户端增量多大"仍然要盯。
        t0 = time.perf_counter()
        st, body, ch = challenge("admin")
        t_roundtrip = (time.perf_counter() - t0) * 1000
        check("D1 challenge 纯往返（对照组）", st == 200, "HTTP %s" % st)

        # 链值路径：挑战往返 + 客户端计算 + 登录往返
        t0 = time.perf_counter()
        st, body, ch = challenge("admin")
        t_c = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter()
        code = code_at(PW, ch["r"], ch["k"])
        t_k = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter()
        st, body = login_otp("admin", code, ch["challengeToken"])
        t_l = (time.perf_counter() - t0) * 1000
        t_otp_total = t_c + t_k + t_l

        print("      challenge %.1f ms + 计算 %.1f ms + 登录 %.1f ms = %.1f ms"
              % (t_c, t_k, t_l, t_otp_total))
        print("      对照：challenge 纯往返 %.1f ms（不含密码学）" % t_roundtrip)
        # Python 的 PBKDF2 是 C 实现，与 Rust 同量级；用它作上限估计是安全的。
        check("D2 链值路径总耗时 < 200 ms", t_otp_total < 200, "实测 %.1f ms" % t_otp_total)
        # P8 之后服务端没有 BCrypt 了 —— 登录往返应当与纯 challenge 同量级。
        # 给 5 倍余量是因为两端口的连接建立/ keep-alive 状态会带来抖动，
        # 这条断言守的是"没有引入新的服务端开销"，不是精确计时。
        check("D3 登录往返与纯 challenge 同量级（服务端已无 BCrypt）",
              t_l < max(t_roundtrip * 5, 50.0),
              "登录 %.1f ms vs challenge %.1f ms" % (t_l, t_roundtrip))

        # ── E. 「模块开关」已删除（P8）────────────────────────────────
        # P2–P7 时这一节测的是"关掉开关 ⇒ 客户端降级到口令路径"。
        # P8 删掉口令路径之后，开关失去了意义 —— 关掉它等于让**所有人**登不进来，
        # 于是 `Enabled` 与 `AUTHBASELINE_OTP_ENABLED` 一起被删。
        # 这一节翻成"开关已无效"的判据：设了 false，一切照旧。
        # （探针仍然把环境变量带上，就是要证明它被**安静地忽略**。）
        print("\n[E] AUTHBASELINE_OTP_ENABLED=false 已被忽略（开关不存在了）")
        stop_backend(proc)
        proc2 = start_backend(EXE, PORT + 1, DB, extra_env={
            "AUTHBASELINE_REQUIRE_HTTPS": "false",
            "AUTHBASELINE_OTP_ENABLED": "false",
        })
        base2 = "http://127.0.0.1:%d" % (PORT + 1)
        try:
            require_backend_ready(base2, proc2)
            # 注意：probe 的 challenge()/login_otp() 写死了 BASE，base2 是另一个端口，
            # 所以这里直接用 http_call(base2, ...)，不共用那两个封装。
            st, body = http_call(base2, "POST", "/api/auth/login/challenge", {"username": "admin"})
            ch2 = body.get("data") or {}
            check("E1 challenge 照常 200（不再有 OTP_DISABLED）",
                  st == 200 and bool(ch2.get("challengeToken")),
                  "HTTP %s / %s" % (st, body.get("code")))

            st, body = http_call(base2, "POST", "/api/auth/login", {
                "username": "admin", "otpCode": code_at(PW, ch2["r"], ch2["k"]),
                "challengeToken": ch2["challengeToken"]})
            check("E2 链值登录照常成功（200 + 票据）",
                  st == 200 and bool((body.get("data") or {}).get("ticket")),
                  "HTTP %s / %s" % (st, body.get("code")))

            st, body = http_call(base2, "POST", "/api/auth/login",
                                 {"username": "admin", "password": "wrong"})
            check("E3 带口令的登录仍然 400（口令不因开关复活）",
                  st == 400 and body.get("code") == "EMPTY_FIELDS",
                  "HTTP %s / %s" % (st, body.get("code")))

            st, body = http_call(base2, "POST", "/api/auth/reconfirm", {
                "purpose": "create-account", "target": "x", "otpCode": "AAAA",
            })
            check("E4 reconfirm 不再回 404 OTP_DISABLED（缺票据 401）",
                  st == 401, "HTTP %s / %s" % (st, body.get("code")))
        finally:
            stop_backend(proc2)

    finally:
        try:
            stop_backend(proc)
        except Exception:
            pass
        if "--keep" not in sys.argv:
            db.drop()

    print("\n" + "=" * 62)
    print("通过 %d / 失败 %d" % (len(PASSED), len(FAILED)))
    if FAILED:
        print("失败项：")
        for name in FAILED:
            print("  · " + name)
    print("=" * 62)
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
