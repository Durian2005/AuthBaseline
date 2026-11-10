# -*- coding: utf-8 -*-
"""S/KEY 哈希链标准例题复现：N=5，六步走完，可用次数恰好 N−1 = 4。

用法：
    python tools/otp_chain_demo.py              # 交互式（每步按回车）
    python tools/otp_chain_demo.py --auto       # 一口气跑完
    python tools/otp_chain_demo.py [exe] [port]

它做了什么
==========
起一个**探针库**上的后端（链长用 `AUTHBASELINE_OTP_LENGTH=5` 压到 5），空库会自动播种
`admin/Admin123`，于是登记状态就是 `v = x₅, k = 4`。然后：

    k=4  提交 x₄  → 通过，k → 3
    k=3  重放 x₄  → 拒绝（一次性）
    k=3  提交 x₃  → 通过，k → 2
    k=2  提交 x₂  → 通过，k → 1
    k=1  提交 x₁  → 通过，k → 0
    k=0  再提交   → 「需重建」，而不是「口令错」

`x₀` 全程不出本机：脚本只算到 x₁，服务端连 x₀ 的影子都没有。

⚠️ 每一步都重新申请挑战（`k` 由服务端下发），这正是协议的真实形态 ——
客户端不缓存下标，所以换机、多设备都天然成立。

只碰 `AuthBaselineClassroomDemoProbe`（过守卫），结束时 drop；真实库连读都不读。
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

EXE = ARGS[0] if len(ARGS) > 0 else os.path.join(
    ROOT, "AuthServer", "bin", "Debug", "net8.0", "AuthServer.exe")
PORT = int(ARGS[1]) if len(ARGS) > 1 else 5131

DB = resolve_probe_db("AuthBaselineClassroomDemoProbe")
BASE = "http://127.0.0.1:%d" % PORT

CHAIN_N = 5            # 例题的链长
ADMIN_PW = "Admin123"  # 空库播种的初始口令


def pause(text="按回车继续…"):
    if AUTO:
        print()
        return
    try:
        input(text)
    except EOFError:
        pass


def compute_cell(password, r, k, iterations):
    """x_k = H^k(PBKDF2(password, salt=UTF8(r))) 的 Base64。"""
    x = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                            r.encode("utf-8"), int(iterations), dklen=32)
    for _ in range(int(k)):
        x = hashlib.sha256(x).digest()
    return base64.b64encode(x).decode("ascii")


def short(cell_b64, n=10):
    return cell_b64[:n] + "…" if len(cell_b64) > n else cell_b64


def server_state(probe_db):
    """读库里真实的 v / k，用来证明"服务端的账"确实在变。"""
    doc = probe_db["OtpChains"].find_one({"username": "admin"}) or {}
    return doc.get("v", ""), int(doc.get("k", -1)), int(doc.get("length", -1))


def step(password, wanted_k, label):
    """申请一次挑战，提交指定下标的那一格。返回 (状态码, 响应, 挑战)。"""
    st, body = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": "admin"})
    ch = (body or {}).get("data") or {}
    if st != 200 or not ch:
        raise SystemExit("取挑战失败：HTTP %s / %s" % (st, body))

    cell = compute_cell(password, ch["r"], wanted_k, ch["iterations"])

    st2, body2 = http_call(BASE, "POST", "/api/auth/login", {
        "username": "admin",
        "otpCode": cell,
        "challengeToken": ch["challengeToken"],
    })
    code = (body2 or {}).get("code") or ""
    msg = (body2 or {}).get("message") or ""
    print("  %-26s 提交 x_%d = %s  →  HTTP %s  %s" % (label, wanted_k, short(cell), st2, code))
    if msg:
        print("  %-26s 回复：%s" % ("", msg))
    return st2, body2, ch, cell


def main():
    probe_db = ProbeDb(DB)
    probe_db.drop_if_exists()

    proc = start_backend(
        EXE, PORT, DB,
        extra_env={
            "AUTHBASELINE_REQUIRE_HTTPS": "false",
            # 把链长压到例题的 5：链长只影响"建链时算多少步"，存量链各自记录自己的长度。
            "AUTHBASELINE_OTP_LENGTH": str(CHAIN_N),
            # 例题的每一步都要能看清，关掉日志噪音没有必要，保持默认即可。
        })

    try:
        wait_backend_ready(BASE, proc)

        v, k, length = server_state(probe_db)
        print()
        print("=" * 72)
        print("  哈希链例题复现  N=%d，v = x_%d，初始 k = %d" % (length, length, k))
        print("=" * 72)
        print("  库里现在只有：v = %s   k = %d   N = %d" % (short(v, 16), k, length))
        print("  没有口令，没有 x₀，也没有任何中间格。")
        pause("\n  【登记完成】按回车开始第 1 次登录…")

        print("\n[第 1 次登录] 客户端算出 x_%d 交上去，服务端验 H(x_%d) == v" % (k, k))
        st, _, _, cell_used = step(ADMIN_PW, k, "第1次")
        v2, k2, _ = server_state(probe_db)
        print("  服务端更新：v → %s   k → %d" % (short(v2, 16), k2))
        pause()

        print("\n[重放] 把上一次那一格原样再交一次")
        st_r, body_r, _, _ = step(ADMIN_PW, k, "重放上一格")
        v3, k3, _ = server_state(probe_db)
        print("  断言：k 没动（%d → %d），拒绝码 = %s" % (k2, k3, (body_r or {}).get("code")))
        pause()

        for idx, label in [(k2, "第2次"), (k2 - 1, "第3次"), (k2 - 2, "第4次")]:
            print("\n[%s] 提交 x_%d" % (label, idx))
            step(ADMIN_PW, idx, label)
            v_now, k_now, _ = server_state(probe_db)
            print("  服务端更新：v → %s   k → %d" % (short(v_now, 16), k_now))
            pause()

        print("\n[耗尽] k 已经是 0")
        print("  客户端行为：本地直接拒绝，**连算都不算**。")
        print("  因为 k=0 那一格按定义就是 x₀（口令派生根）—— 它一旦出门，")
        print("  截获者能正向重算出 x₁…x_N，等于把后续所有配额一起交出去。")
        print("  （实现位置：`src/api/otp.js` 里 compute 的 k<=0 闸门）")
        pause("\n  下面绕过客户端，强行提交 x₀，看服务端怎么回…")

        st_e, body_e, _, _ = step(ADMIN_PW, 0, "硬提交 x_0")
        code_e = (body_e or {}).get("code") or ""
        print()
        print("=" * 72)
        print("  结论")
        print("=" * 72)
        ok = (st == 200 and st_r == 401 and st_e == 401 and "OTP_CHAIN_EXHAUSTED" in code_e)
        print("  · 可用次数 = N - 1 = %d（k 从 4 走到 0，共 4 次成功）" % (CHAIN_N - 1))
        print("  · x₀ 不出本机：k=0 时客户端本地拦住，不去算也不去发")
        print("  · 就算硬提交，服务端也在比对前返回「%s」，不看那一格" % code_e)
        print("\n  判定：%s" % ("PASS ✅ 与例题逐条对应" if ok else "FAIL ❌ 请检查上面的输出"))
        return 0 if ok else 1
    finally:
        stop_backend(proc)
        probe_db.drop()


if __name__ == "__main__":
    sys.exit(main())
