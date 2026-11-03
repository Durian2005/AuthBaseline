# -*- coding: utf-8 -*-
"""一次性口令（哈希链）P4 的端到端验证：**静默续期**（两步写的第二步）。

用法：
  python tools/otp_p4_probe.py <exe路径> <端口>

要证明的是一句听起来很弱、其实很强的话：**续期出任何问题，用户都感觉不到。**
所以断言围绕三条展开：

  A. 判定点
     · 不在续期窗口（`k > N×5%`）时，客户端递上来的新链**必须被忽略** ——
       否则每登一次就能把 k 刷回 N-1，"链有配额"名存实亡；
     · 进入窗口（`k ≤ N×5%`）才换，且换完 `generation+1`、`k` 回到 N-1、链长与迭代次数**继承旧链**。

  B. 两步写
     · 没提交新链 ⇒ 登录照常成功，只是链继续变短（审计 `OTP_RENEW_FAILED / NO_NEXT_CHAIN`）；
     · 新链形状非法 ⇒ 登录照常成功，链原封不动（审计 `ERROR / ArgumentException`）；
     · 写库失败 ⇒ 登录照常成功、**本次核销已经生效**（k 已减 1）、旧链继续可用。
       这一条是"两步写"的全部意义：换链失败不能连累核销，也不能连累登录。

  C. 换代之后
     · 旧种子的格全部失效；新种子的格可用；
     · 失败之后下一次登录能补上（不是一次失败就永久卡住）。

用 N=20 而不是默认 1000：20 的续期线是 k≤1，驱动 18 次登录就能走到，
而 1000 要走 950 次（这不是"省事"，是让这条路径**能被自动化反复覆盖**）。

与前缀无关的细节：只碰 `AuthBaselineOtpP4Probe`（过守卫），结束时 drop。
"""
import base64
import datetime
import hashlib
import json
import os
import sys

from _probe_common import ProbeDb, resolve_probe_db, start_backend, require_backend_ready, stop_backend, http_call

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    ROOT, "AuthServer", "bin", "Debug", "net8.0", "AuthServer.exe")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5117
DB = resolve_probe_db("AuthBaselineOtpP4Probe")
BASE = "http://127.0.0.1:%d" % PORT

N = 20                 # 续期线：k ≤ N*5% = 1
ITER = 1000
PW = "Admin123"
USER = "admin"

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


def new_seed():
    return base64.b32encode(os.urandom(20)).decode("ascii")


def bag(field):
    if field is None:
        return {}
    if isinstance(field, dict):
        return field
    try:
        return json.loads(field)
    except (TypeError, ValueError):
        return {}


def audits(probe_db, action, target=USER):
    out = []
    for name in probe_db.list_collection_names():
        if name.startswith("AuditLogs"):
            out.extend(probe_db[name].find({"action": action, "target": target}))
    return out


def challenge():
    st, b = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": USER})
    return b.get("data") or {}


def login(code, token, next_chain=None):
    body = {"username": USER, "otpCode": code, "challengeToken": token}
    if next_chain is not None:
        body["nextChain"] = next_chain
    return http_call(BASE, "POST", "/api/auth/login", body)


def chain(probe_db):
    return probe_db["OtpChains"].find_one({"username": USER})


def set_state(probe_db, seed, k):
    """把链摆到指定的 k（v 必须是 x_(k+1)，否则判定式自己就对不上）。"""
    cells = root(PW, seed)
    probe_db["OtpChains"].update_one(
        {"username": USER},
        {"$set": {"k": k, "v": b64(iterate(cells, k + 1))}})


def main():
    probe_db = ProbeDb(DB)
    probe_db.drop_if_exists()

    os.environ.pop("AUTHBASELINE_OTP_ENABLED", None)
    proc = start_backend(EXE, PORT, DB, extra_env={
        "AUTHBASELINE_REQUIRE_HTTPS": "false",
        "AUTHBASELINE_OTP_LENGTH": str(N),
        "AUTHBASELINE_OTP_KDF_ITERATIONS": str(ITER),
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
    print("  结论：%s" % ("PASS ✅ 续期全程静默，且失败不影响登录与核销" if not FAILED else "FAIL ❌"))
    print("=" * 78)
    return 0 if not FAILED else 1


def run(probe_db):
    # ── 0. 准备：空库播种时就已建链（P8 起种子不再写口令哈希） ──
    # 改动点：以前这里靠"口令登录触发懒迁移"顺带把链造出来，那条路在 P8 被删了。
    # 现在种子流程直接建链，于是本探针**不必**再依赖一个已被删除的机制 ——
    # 它只需要一条 N=20 的链，而那条链在启动时就存在。
    print("\n[0] 准备：空库播种已建好 N=20 的链，直接用链值登录")
    data = challenge()
    st, b = login(b64(iterate(root(PW, data["r"]), data["k"])), data.get("challengeToken"))
    check("0.1 登录成功", st == 200 and bool((b.get("data") or {}).get("ticket")), "HTTP %s" % st)

    doc = chain(probe_db)
    # 播种建链时 k = N-1；上面那次登录核销了一格 ⇒ N-2。
    check("0.2 链已建好且本次登录核销了一格（k=N-2, generation=1）",
          doc["k"] == N - 2 and doc["generation"] == 1 and doc["length"] == N,
          "k=%r gen=%r len=%r" % (doc.get("k"), doc.get("generation"), doc.get("length")))
    seed1 = doc["r"]

    # 把 k 从 N-2 推到 2（每次都是一次真实的链值登录）
    print("\n[1] 把链用到 k=2（窗口外）")
    for _ in range(N - 4):
        data = challenge()
        st, b = login(b64(iterate(root(PW, data["r"]), data["k"])), data.get("challengeToken"))
        if st != 200:
            check("1.0 驱动到窗口外时登录失败", False, "HTTP %s / %s" % (st, b.get("code")))
            return
    check("1.1 已到 k=2", chain(probe_db)["k"] == 2, "k=%r" % chain(probe_db)["k"])

    # ── A. 窗口外必须忽略新链 ──
    print("\n[A] 窗口外（k=2 > N×5%）提交新链 → 忽略")
    fakeseed = new_seed()
    fakehead = b64(iterate(root(PW, fakeseed), N))   # 形状与内容都合法，只有"时机"不对
    data = challenge()
    st, b = login(b64(iterate(root(PW, data["r"]), data["k"])), data.get("challengeToken"),
                  {"r": fakeseed, "head": fakehead})
    check("A1 登录成功", st == 200, "HTTP %s / %s" % (st, b.get("code")))
    doc = chain(probe_db)
    check("A2 链没被换（仍是旧种子、generation 仍为 1）",
          doc["r"] == seed1 and doc["generation"] == 1, "gen=%r" % doc.get("generation"))
    check("A3 只正常核销一格（k=1）", doc["k"] == 1, "k=%r" % doc.get("k"))
    check("A4 没有 OTP_RENEWED 审计", len(audits(probe_db, "OTP_RENEWED")) == 0)

    # ── B1. 窗口内但不给新链 ──
    print("\n[B1] 窗口内（k=1）不提交新链")
    data = challenge()
    st, b = login(b64(iterate(root(PW, data["r"]), data["k"])), data.get("challengeToken"))
    check("B1.1 登录照常成功", st == 200, "HTTP %s" % st)
    doc = chain(probe_db)
    check("B1.2 链未换、k 已降到 0（核销照常发生）",
          doc["k"] == 0 and doc["r"] == seed1 and doc["generation"] == 1, "k=%r" % doc.get("k"))
    skipped = [d for d in audits(probe_db, "OTP_RENEW_FAILED") if bag(d.get("response")).get("Outcome") == "NO_NEXT_CHAIN"]
    check("B1.3 审计记下'到线但未提交新链'（否则链缩短没有任何线索）", len(skipped) == 1,
          "找到 %d 条" % len(skipped))

    # ── B2. 形状非法 ──
    print("\n[B2] 窗口内提交形状非法的新链")
    set_state(probe_db, seed1, 1)
    data = challenge()
    st, b = login(b64(iterate(root(PW, data["r"]), data["k"])), data.get("challengeToken"),
                  {"r": new_seed(), "head": "AAAA"})     # head 只有 3 字节
    check("B2.1 登录照常成功（形状错误只影响续期）", st == 200, "HTTP %s / %s" % (st, b.get("code")))
    doc = chain(probe_db)
    check("B2.2 坏形状**没有**被写进库（仍是旧种子、k 已核销）",
          doc["r"] == seed1 and doc["k"] == 0, "r=%s… k=%r" % (doc["r"][:8], doc.get("k")))
    bad = [d for d in audits(probe_db, "OTP_RENEW_FAILED") if bag(d.get("response")).get("ErrorType") == "ArgumentException"]
    check("B2.3 审计记下形状错误（含异常类型，便于区分'客户端 bug'与'库坏了'）", len(bad) == 1,
          "找到 %d 条" % len(bad))

    # ── C. 正常续期 ──
    print("\n[C] 窗口内提交合法新链 → 换代")
    set_state(probe_db, seed1, 1)
    seed2 = new_seed()
    data = challenge()
    st, b = login(b64(iterate(root(PW, data["r"]), data["k"])), data.get("challengeToken"),
                  {"r": seed2, "head": b64(iterate(root(PW, seed2), N))})
    check("C1 登录成功", st == 200, "HTTP %s / %s" % (st, b.get("code")))
    doc = chain(probe_db)
    check("C2 链已换代：新种子 / k 回到 N-1 / generation=2",
          doc["r"] == seed2 and doc["k"] == N - 1 and doc["generation"] == 2,
          "gen=%r k=%r" % (doc.get("generation"), doc.get("k")))
    check("C3 链长与迭代次数继承旧链（不看当前配置）",
          doc["length"] == N and doc["kdfIterations"] == ITER)
    renewed = audits(probe_db, "OTP_RENEWED")
    rs = bag(renewed[0].get("response")) if renewed else {}
    check("C4 审计 OTP_RENEWED：带代数与 k，且不含新链头",
          len(renewed) == 1 and rs.get("Generation") == 1 and rs.get("Renewed") is True
          and "Head" not in json.dumps(rs),
          "logs=%d resp=%r" % (len(renewed), rs))

    # ── D. 换代之后 ──
    print("\n[D] 换代之后：旧种子的格全部失效")
    data = challenge()
    old_cell = b64(iterate(root(PW, seed1), data["k"]))
    st, b = login(old_cell, data.get("challengeToken"))
    check("D1 用**旧种子**算出的格 → 401（旧链已作废，不存在并行窗口）",
          st == 401 and b.get("code") == "INVALID_CREDENTIALS",
          "HTTP %s / %s" % (st, b.get("code")))

    data = challenge()
    st, b = login(b64(iterate(root(PW, seed2), data["k"])), data.get("challengeToken"))
    check("D2 用**新种子**算出的格 → 200（新链确实可用）", st == 200, "HTTP %s / %s" % (st, b.get("code")))

    # ── B3. 写库失败：两步写的关键 ──
    print("\n[B3] 故障注入：续期写库失败")
    set_state(probe_db, seed2, 1)
    seed3 = new_seed()
    probe_db["OtpChains"].create_index("r", unique=True, name="tmp_uniq_otp_r")
    probe_db["OtpChains"].insert_one({
        "userId": "decoy-user-id", "username": "decoy", "r": seed3,
        "algorithm": "SHA256", "kdf": "PBKDF2-HMACSHA256", "kdfIterations": ITER,
        "length": N, "v": "AAAA", "k": 1, "generation": 1,
        "createdAt": datetime.datetime.now(datetime.timezone.utc),
    })

    data = challenge()
    st, b = login(b64(iterate(root(PW, data["r"]), data["k"])), data.get("challengeToken"),
                  {"r": seed3, "head": b64(iterate(root(PW, seed3), N))})
    check("B3.1 续期写失败 → **登录仍然 200**", st == 200, "HTTP %s / %s / %s" % (st, b.get("code"), b.get("message")))
    doc = chain(probe_db)
    check("B3.2 核销仍然生效（k 已从 1 减到 0）—— 这正是两步写的意义",
          doc["k"] == 0, "k=%r" % doc.get("k"))
    check("B3.3 旧链原封不动（种子仍是上一代、generation 未变）",
          doc["r"] == seed2 and doc["generation"] == 2)
    errs = [d for d in audits(probe_db, "OTP_RENEW_FAILED")
            if bag(d.get("response")).get("Outcome") == "ERROR"
            and bag(d.get("response")).get("ErrorType") not in (None, "ArgumentException")]
    check("B3.4 审计记下写库失败（对用户静默≠对系统静默）", len(errs) >= 1, "找到 %d 条" % len(errs))

    # ── E. 失败之后能补上 ──
    print("\n[E] 故障消失后下一次登录补上续期")
    probe_db["OtpChains"].delete_one({"userId": "decoy-user-id"})
    probe_db["OtpChains"].drop_index("tmp_uniq_otp_r")
    set_state(probe_db, seed2, 1)

    data = challenge()
    st, b = login(b64(iterate(root(PW, data["r"]), data["k"])), data.get("challengeToken"),
                  {"r": seed3, "head": b64(iterate(root(PW, seed3), N))})
    doc = chain(probe_db)
    check("E1 续期补上：登录 200、种子换成第三代理、generation=3",
          st == 200 and doc["r"] == seed3 and doc["generation"] == 3 and doc["k"] == N - 1,
          "HTTP %s / gen=%r" % (st, doc.get("generation")))

    data = challenge()
    st, b = login(b64(iterate(root(PW, seed3), data["k"])), data.get("challengeToken"))
    check("E2 第三代链可用", st == 200, "HTTP %s" % st)


if __name__ == "__main__":
    sys.exit(main())
