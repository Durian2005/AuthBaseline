# -*- coding: utf-8 -*-
"""挑战签名（防「小数攻击」）的端到端验证。

用法：
  python tools/otp_challenge_proof_probe.py [exe路径] [端口]

背景
====
S/KEY 的「小数攻击」：中间人截获服务端下发的挑战，把**期望下标 k 改小**再转发。
客户端若照算，交出的是更靠前的一格 `x_k'`；攻击者正向哈希 `k - k'` 次就得到
真正的 `x_k`，既能冒充本次登录，还顺带握住后续若干格。

服务端对此**无从分辨**（它收到的就是真正的 `x_k`），所以防线只能在客户端：
先验签，确认 `(r, k, n)` 是服务端签发的，再动笔算。

这条探针验证的是"服务端签出的 proof 确实可以被独立复算、且改动任一字段就复算不出来"。
客户端侧的同一判断由 Rust 单测 `tampered_k_breaks_signature` 覆盖（同一函数、同一向量）。

断言分组
========
  A. 真账号
     A1 挑战里带非空 proof
     A2 Python 用服务端同一份密钥独立复算，与返回**逐字相同**
     A3 把 k 改小 1 ⇒ 复算结果不等（这就是小数攻击会被识破的判据）
     A4 改种子 R ⇒ 不等
     A5 改链长 N ⇒ 不等
  B. 防枚举不被破坏
     B1 不存在账号的响应字段集合与真账号**完全一致**
     B2 假账号的 proof 同样能被独立验过（不是空串占位）
  C. 不影响正常登录
     C1 真挑战算出的链值 → 200 + 票据
     C2 登录后 k 减 1

只碰 `AuthBaselineChallengeProofProbe`（过守卫），结束时 drop；真实库连读都不读。
"""

import base64
import ctypes
import ctypes.wintypes
import hashlib
import hmac
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
EXE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    ROOT, "AuthServer", "bin", "Debug", "net8.0", "AuthServer.exe")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5129
DB = resolve_probe_db("AuthBaselineChallengeProofProbe")
BASE = "http://127.0.0.1:%d" % PORT

ADMIN_PW = "Admin123"

# 与服务端 `OtpChallengeKey.Entropy` 逐字一致：熵不同就解不开。
KEY_ENTROPY = b"AuthBaseline.OtpChallenge.v1"

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print("  [%s] %s%s" % ("OK  " if cond else "FAIL", name,
                          ("  <- " + str(detail)) if detail and not cond else ""))


# ---------------------------------------------------------------------------
# DPAPI：与服务端共读同一份「本机配对密钥」
# ---------------------------------------------------------------------------

class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_unprotect(blob: bytes, entropy: bytes) -> bytes:
    """`CryptUnprotectData`，CurrentUser 作用域、无 UI。"""
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    data_buf = ctypes.create_string_buffer(blob, len(blob))
    ent_buf = ctypes.create_string_buffer(entropy, len(entropy))

    data_in = _Blob(len(blob), ctypes.cast(data_buf, ctypes.POINTER(ctypes.c_char)))
    ent_in = _Blob(len(entropy), ctypes.cast(ent_buf, ctypes.POINTER(ctypes.c_char)))
    data_out = _Blob()

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(data_in), None, ctypes.byref(ent_in), None, None, 0,
        ctypes.byref(data_out))
    if not ok:
        raise OSError("CryptUnprotectData 失败（密钥不属于当前用户？）")

    try:
        return ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        kernel32.LocalFree(data_out.pbData)


def load_key() -> bytes:
    base = os.environ.get("LOCALAPPDATA", "")
    path = os.path.join(base, "AuthBaselineData", "otp-challenge.key")
    with open(path, "rb") as fh:
        return dpapi_unprotect(fh.read(), KEY_ENTROPY)


# ---------------------------------------------------------------------------
# 与 C# / Rust 逐字一致的签名
# ---------------------------------------------------------------------------

def payload_of(username: str, r: str, k: int, n: int) -> str:
    name_digest = hashlib.sha256(username.encode("utf-8")).hexdigest()
    return "%s|%s|%d|%d" % (name_digest, r, k, n)


def sign_challenge(key: bytes, username: str, r: str, k: int, n: int) -> str:
    mac = hmac.new(key, payload_of(username, r, k, n).encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")


def main():
    probe_db = ProbeDb(DB)
    probe_db.drop_if_exists()

    proc = start_backend(
        EXE, PORT, DB,
        extra_env={
            "AUTHBASELINE_REQUIRE_HTTPS": "false",
            "AUTHBASELINE_EMAIL_PROVIDER": "Console",
        })

    try:
        wait_backend_ready(BASE, proc)

        print("\n[A] 真账号：proof 可被独立复算")
        st, body = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": "admin"})
        ch = (body or {}).get("data") or {}
        check("A0 挑战取得成功", st == 200 and bool(ch.get("challengeToken")), "%s %s" % (st, body))

        proof = ch.get("proof") or ""
        check("A1 挑战带非空 proof", bool(proof), repr(proof))

        key = load_key()
        r, k, n = ch.get("r", ""), int(ch.get("k", -1)), int(ch.get("n", -1))
        recomputed = sign_challenge(key, "admin", r, k, n)
        check("A2 独立复算与服务端返回逐字相同", recomputed == proof,
              "expected=%s got=%s" % (recomputed, proof))

        # 小数攻击：把 k 改小 1（攻击者要的就是更靠前、更容易被补齐的那一格）
        smaller_k = max(0, k - 1)
        check("A3 k 改小 1 后复算不出原 proof",
              sign_challenge(key, "admin", r, smaller_k, n) != proof)

        tampered_r = r[:-1] + ("A" if r[-1] != "A" else "B")
        check("A4 改种子 R 后复算不出原 proof",
              sign_challenge(key, "admin", tampered_r, k, n) != proof)

        check("A5 改链长 N 后复算不出原 proof",
              sign_challenge(key, "admin", r, k, n + 1) != proof)

        print("\n[B] 防枚举：假参数与真参数字段一致")
        st2, body2 = http_call(BASE, "POST", "/api/auth/login/challenge",
                               {"username": "no-such-user-xyz"})
        fake = (body2 or {}).get("data") or {}
        check("B1 字段集合与真账号完全一致",
              st2 == 200 and sorted(fake.keys()) == sorted(ch.keys()),
              "%s vs %s" % (sorted(fake.keys()), sorted(ch.keys())))

        fake_proof = fake.get("proof") or ""
        fake_expected = sign_challenge(key, "no-such-user-xyz", fake.get("r", ""),
                                       int(fake.get("k", -1)), int(fake.get("n", -1)))
        check("B2 假账号的 proof 也能被独立验过（不是占位空串）",
              bool(fake_proof) and fake_proof == fake_expected,
              "expected=%s got=%s" % (fake_expected, fake_proof))

        print("\n[C] 正常登录不受影响")
        chain_before = probe_db["OtpChains"].find_one({"username": "admin"}) or {}
        code = compute_code(ADMIN_PW, ch)
        st3, body3 = http_call(BASE, "POST", "/api/auth/login", {
            "username": "admin",
            "otpCode": code,
            "challengeToken": ch.get("challengeToken"),
        })
        ticket = ((body3 or {}).get("data") or {}).get("ticket") or ""
        check("C1 真挑战算出的链值登录成功（200 + 票据）",
              st3 == 200 and bool(ticket), "%s %s" % (st3, (body3 or {}).get("code")))

        chain_after = probe_db["OtpChains"].find_one({"username": "admin"}) or {}
        check("C2 登录后 k 减 1",
              int(chain_after.get("k", -1)) == int(chain_before.get("k", -2)) - 1,
              "before=%s after=%s" % (chain_before.get("k"), chain_after.get("k")))
    finally:
        stop_backend(proc)
        probe_db.drop()

    print("\n" + "=" * 62)
    if FAILED:
        print("  结论：FAIL  %d 项通过 / %d 项失败" % (len(PASSED), len(FAILED)))
        print("  失败：%s" % ", ".join(FAILED))
        return 1
    print("  结论：PASS  %d 项断言全部通过" % len(PASSED))
    return 0


def compute_code(password, ch):
    """按挑战参数算出这一格（独立实现，不复用 C#）。"""
    x = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                            ch["r"].encode("utf-8"), int(ch["iterations"]), dklen=32)
    for _ in range(int(ch["k"])):
        x = hashlib.sha256(x).digest()
    return base64.b64encode(x).decode("ascii")


if __name__ == "__main__":
    sys.exit(main())
