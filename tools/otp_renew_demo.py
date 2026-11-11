# -*- coding: utf-8 -*-
"""续期演示：链不会用尽（N=20，续期线 k ≤ 1）。

用法：
    python tools/otp_renew_demo.py            # 交互式（关键节点按回车）
    python tools/otp_renew_demo.py --auto     # 一口气跑完
    python tools/otp_renew_demo.py --verbose  # 每次登录都单独打一行

它要让人一眼看到的四件事
========================
1. `k` 随着登录一次一格地减少（不是"一次跳到 0"）；
2. 减到 `k ≤ N×5%` 时，链**当场**换新：`r` 换掉、`generation` +1、`k` 回到 N-1；
3. 换的是**整条新链**（新盐 + 用同一口令重算的链头），不是把 `k` 改大；
4. 旧种子的格随后立刻失效 —— 这一条能区分"换链"与"重置计数"。

为什么用 N=20：续期线是 `k ≤ N×5%`。默认 N=1000 的线在 k=50，要走 950 次；
N=20 的线在 k=1，19 次登录就演完。**这不是把链条改短好演**，是让这条路径能被一分钟看完。

只碰 `AuthBaselineRenewDemoProbe`（过守卫），结束时 drop；真实库连读都不读。
"""

import base64
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _probe_common import (  # noqa: E402
    ProbeDb,
    http_call,
    resolve_probe_db,
    start_backend,
    stop_backend,
    wait_backend_ready,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
AUTO = "--auto" in sys.argv
VERBOSE = "--verbose" in sys.argv

EXE = ARGS[0] if len(ARGS) > 0 else os.path.join(
    ROOT, "AuthServer", "bin", "Debug", "net8.0", "AuthServer.exe")
PORT = int(ARGS[1]) if len(ARGS) > 1 else 5133

DB = resolve_probe_db("AuthBaselineRenewDemoProbe")
BASE = "http://127.0.0.1:%d" % PORT

N = 20          # 链长（续期线 k <= 1）
ITER = 1000     # 演示用低迭代：不影响判定，只让 19 次登录几秒跑完
USER = "admin"
PW = "Admin123"

RENEW_LINE = N * 5 // 100   # = 1


def pause(text="按回车继续…"):
    if AUTO:
        print()
        return
    try:
        input(text)
    except EOFError:
        pass


def root(password, r):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               r.encode("utf-8"), ITER, dklen=32)


def iterate(x, times):
    for _ in range(times):
        x = hashlib.sha256(x).digest()
    return x


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def new_seed():
    """新盐：20 字节 CSPRNG → 32 位 Base32（与客户端 otp.rs 同一形式）。"""
    return base64.b32encode(os.urandom(20)).decode("ascii")


def short(s, n=8):
    return (s[:n] + "…") if len(s) > n else s


def state(probe_db):
    doc = probe_db["OtpChains"].find_one({"username": USER}) or {}
    return {
        "r": doc.get("r", ""),
        "k": int(doc.get("k", -1)),
        "gen": int(doc.get("generation", -1)),
        "len": int(doc.get("length", -1)),
        "iter": int(doc.get("kdfIterations", -1)),
        "v": doc.get("v", ""),
    }


def login(password, seed, k, next_chain=None):
    """申请一次挑战（k 由服务端下发），算 x_k 提交。返回 (状态码, 响应体)。"""
    st, body = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": USER})
    ch = (body or {}).get("data") or {}
    if st != 200 or not ch:
        raise SystemExit("取挑战失败：HTTP %s / %s" % (st, body))

    cell = b64(iterate(root(password, seed), k))
    payload = {"username": USER, "otpCode": cell, "challengeToken": ch.get("challengeToken")}
    if next_chain is not None:
        payload["nextChain"] = next_chain
    st2, body2 = http_call(BASE, "POST", "/api/auth/login", payload)
    return st2, (body2 or {})


def main():
    probe_db = ProbeDb(DB)
    probe_db.drop_if_exists()

    proc = start_backend(EXE, PORT, DB, extra_env={
        "AUTHBASELINE_REQUIRE_HTTPS": "false",
        "AUTHBASELINE_OTP_LENGTH": str(N),
        "AUTHBASELINE_OTP_KDF_ITERATIONS": str(ITER),
    })

    try:
        wait_backend_ready(BASE, proc)

        s0 = state(probe_db)
        print()
        print("=" * 70)
        print("  链不会用尽：静默续期演示（N=%d，续期线 k ≤ %d）" % (s0["len"], RENEW_LINE))
        print("=" * 70)
        print("  库里现在只有：r = %s   k = %d   generation = %d" % (short(s0["r"]), s0["k"], s0["gen"]))
        print("  没有口令，也没有任何中间格。")
        print()
        print("  规则：k ≤ N×5%% = %d 时换链。所以先正常登录 18 次（k: %d → 1），"
              % (RENEW_LINE, s0["k"]))
        print("        第 19 次才在线上 —— 换链发生在这一次。")
        pause("\n  【开始】按回车连续登录 18 次…")

        # 18 次登录：k 从 19 走到 1（每次都在线之上）
        steps = []
        for i in range(1, s0["k"]):
            before = state(probe_db)
            st, _ = login(PW, before["r"], before["k"])
            after = state(probe_db)
            steps.append("%d→%d" % (before["k"], after["k"]))
            if st != 200:
                raise SystemExit("第 %d 次登录失败（HTTP %s）" % (i, st))
            if VERBOSE:
                print("    [第 %2d 次] 提交 x_%-2d  →  HTTP 200   库里的 k: %d → %d"
                      % (i, before["k"], before["k"], after["k"]))

        mid = state(probe_db)
        if not VERBOSE:
            print("  k: %s" % "  ".join(steps))
        print()
        print("  18 次登录完成，库里确认：k = %d，r 没变（%s），generation 仍是 %d"
              % (mid["k"], short(mid["r"]), mid["gen"]))
        print("  → 还没到线，所以一次都没换链。这就是「配额」的含义。")

        pause("\n  【关键】按回车做第 19 次登录 —— 这一次会跨过续期线…")

        # 第 19 次：跨线，随登录递上新链
        before = state(probe_db)
        seed2 = new_seed()
        head2 = b64(iterate(root(PW, seed2), mid["len"]))
        print()
        print("  [第 19 次] 提交 x_%d（此时 k = %d，已经在线上了）" % (before["k"], before["k"]))
        print("             顺手把新链递上去：")
        print("               新盐 r' = %s（32 位 Base32，本机 CSPRNG）" % short(seed2, 12))
        print("               新链头  = %s（x_%d，用新盐重算整条链）" % (short(head2, 12), mid["len"]))

        st, body = login(PW, before["r"], before["k"], {"r": seed2, "head": head2})
        after = state(probe_db)

        print()
        print("  登录结果：HTTP %s %s" % (st, body.get("code") or "（成功）"))
        print()
        print("  换代前后（全部读库得到，不是我打印的常量）：")
        print("    %-14s %-16s %-16s" % ("字段", "续期前", "续期后"))
        print("    %-14s %-16s %-16s" % ("r", short(before["r"], 12), short(after["r"], 12)))
        print("    %-14s %-16s %-16s" % ("generation", before["gen"], after["gen"]))
        print("    %-14s %-16s %-16s" % ("k", before["k"], after["k"]))
        print("    %-14s %-16s %-16s" % ("length", before["len"], after["len"]))
        print("    %-14s %-16s %-16s" % ("kdfIterations", before["iter"], after["iter"]))

        ok_renew = (st == 200 and after["r"] == seed2
                    and after["gen"] == before["gen"] + 1
                    and after["k"] == after["len"] - 1
                    and after["len"] == before["len"])

        pause("\n  【校验】按回车验证「旧链真的作废了」…")

        # 旧链作废：用旧种子算一格
        st_old, body_old = login(PW, before["r"], before["k"])
        print()
        print("  [旧链] 用旧种子 r 算一格 → HTTP %s  %s"
              % (st_old, body_old.get("code") or ""))
        print("  [新链] 用新种子 r' 算下一格 → ", end="")
        st_new, body_new = login(PW, after["r"], after["k"])
        print("HTTP %s  %s" % (st_new, body_new.get("code") or "（登录成功）"))

        final = state(probe_db)
        print("  新链继续走：k = %d → %d" % (after["k"], final["k"]))

        ok = ok_renew and st_old == 401 and st_new == 200

        print()
        print("=" * 70)
        print("  结论")
        print("=" * 70)
        print("  · 链在还剩 %d 格时自动换新，用户只看到「登录成功」" % RENEW_LINE)
        print("  · 新链 = 新随机盐 + 用同一口令重算的整条链，不是把 k 改大")
        print("  · 旧链当场作废（旧盐的格 401）—— 这才叫换链，不是重置计数")
        print("  · N=1000 时这条线在 k=50，缓冲 50 次；本例压到 20 只是为了看得完")
        print()
        print("  判定：%s" % ("PASS ✅ 与设计一致" if ok else "FAIL ❌ 请检查上面的输出"))
        pause("\n  库里现在就是换代后的状态，可按回车结束（结束后会删除探针库）…")
        return 0 if ok else 1
    finally:
        stop_backend(proc)
        probe_db.drop()


if __name__ == "__main__":
    sys.exit(main())
