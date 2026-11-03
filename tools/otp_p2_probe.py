# -*- coding: utf-8 -*-
"""一次性口令（哈希链）P2 的端到端验证：`login/challenge` + 登录链值分支。

用法：
  python tools/otp_p2_probe.py <exe路径> <端口>

为什么必须同一进程内跑完：调用方 shell 退出后子进程会被回收，
分步执行拿不到活着的后端。

本探针要证明的只有一件事：**新路径可用，且旧路径一点没变**。
所以断言分成两组，故意交错执行（同一进程、同一个库）：

  A. 旧路径（回归）
     口令错 → 与改造前逐字一致的话术与计数；口令对 → 照常签票。
     这一组在"库里已经有链"之后再跑一遍 —— 证明新路径的存在不会污染旧路径。

  B. 新路径（本次新增）
     ① 防枚举：有链 / 无链两种账号的 challenge 响应**字段完全相同**，
        且都长得像随机（R 同长、k 同取值域、N 与迭代次数一致）；
     ② 真参数：有链账号拿到的 R/k 与库内一致；
     ③ 链值登录：Python 独立算出的 x_k 能被 C# 接受 —— 这同时是
        **跨实现的向量校验**（PBKDF2 加盐方式、Utf8 编码、SHA-256 迭代方向）；
     ④ 一次性：重放同一格被拒、挑战 token 不能二次使用；
     ⑤ 计次：链值不符按口令错同等计次，三次后锁定；
     ⑥ 用尽：k=0 时回 OTP_CHAIN_EXHAUSTED（不是"凭据错"），且**不计次**；
     ⑦ 冻结：ACCOUNT_DISABLED 出现在核销之前（k 不变 ⇒ 没有白吃配额）。

与前缀无关的细节：探针只碰 `AuthBaselineOtpP2Probe`（库名过守卫），
结束时 drop；真实库连读都不读。
"""
import base64
import datetime
import hashlib
import os
import sys
import time

from _probe_common import ProbeDb, resolve_probe_db, start_backend, require_backend_ready, stop_backend, http_call

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    ROOT, "AuthServer", "bin", "Debug", "net8.0", "AuthServer.exe")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5107
DB = resolve_probe_db("AuthBaselineOtpP2Probe")
BASE = "http://127.0.0.1:%d" % PORT

CHAIN_N = 8            # 探针用短链：8 格 ⇒ 7 次可用，跑得快
CHAIN_ITER = 1000      # PBKDF2 迭代，探针调小（生产默认 100000）
PASSWORD = "Admin123"  # 种子管理员的初始口令
USERNAME = "admin"

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print("  [%s] %s%s" % ("OK  " if cond else "FAIL", name, ("  ← " + detail) if detail and not cond else ""))


# ---------------------------------------------------------------- 链条计算
# 这一段是**独立实现**，刻意不复用任何 C# 代码：
# 只有独立算出来的格被服务端接受，"两端算法一致"才算被证明了，而不是自我印证。
def chain_root(password, r, iterations):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), r.encode("utf-8"), iterations, dklen=32)


def iterate(x, times):
    for _ in range(times):
        x = hashlib.sha256(x).digest()
    return x


def cell(i):
    return iterate(ROOT_X0, i)


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


ROOT_X0 = None  # 建链时赋值


def new_seed():
    # 20 字节 → Base32 32 字符（不带填充），与 C# 的 ToBase32 同字母表（RFC 4648）。
    return base64.b32encode(os.urandom(20)).decode("ascii")


def main():
    global ROOT_X0

    probe_db = ProbeDb(DB)
    probe_db.drop_if_exists()

    os.environ.pop("AUTHBASELINE_OTP_ENABLED", None)  # 别让外部环境变量改变探针前提
    proc = start_backend(EXE, PORT, DB, extra_env={
        "AUTHBASELINE_REQUIRE_HTTPS": "false",
        "AUTHBASELINE_OTP_LENGTH": str(CHAIN_N),
        "AUTHBASELINE_OTP_KDF_ITERATIONS": str(CHAIN_ITER),
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
    print("  结论：%s" % ("PASS ✅ 链值路径可用，且口令字段在协议层已不存在" if not FAILED else "FAIL ❌"))
    print("=" * 78)
    return 0 if not FAILED else 1


def run(probe_db):
    global ROOT_X0

    # ── A. 口令路径已在 P8 删除 ────────────────────────────────
    # ⚠️ 这一节在 P2 时断言的是"改造前那条路逐字不变"（口令错 401、口令对 200）。
    #    P8 之后那条路**整条不存在**，于是断言反过来：带口令的登录一律 400，
    #    因为服务端已经没有接收它的字段，只剩"缺 otpCode"这一个结果。
    #    把它留在这里而不是删掉，是因为"口令再也进不来"本身就是要长期盯住的性质。
    print("\n[A] P8：口令字段已从协议里删除")

    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": USERNAME, "password": "wrong-on-purpose"})
    check("A1 带 password 的登录 → 400 EMPTY_FIELDS（字段被忽略）",
          st == 400 and b.get("code") == "EMPTY_FIELDS",
          "HTTP %s / %s" % (st, b.get("code")))

    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": USERNAME, "password": PASSWORD})
    check("A2 口令正确也一样 400（不存在凭口令登录的路径）",
          st == 400 and b.get("code") == "EMPTY_FIELDS" and not (b.get("data") or {}).get("ticket"),
          "HTTP %s / %s" % (st, b.get("code")))

    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": "no-such-user", "password": "whatever"})
    check("A3 不存在的账号同样是 400（不在这一层泄露账号是否存在）",
          st == 400 and b.get("code") == "EMPTY_FIELDS",
          "HTTP %s / %s" % (st, b.get("code")))

    seeded = probe_db["Users"].find_one({"username": USERNAME}) or {}
    check("A4 播种管理员没有任何口令哈希（P8 起种子也走建链）",
          not seeded.get("passwordHash"), "passwordHash=%r" % seeded.get("passwordHash"))

    seeded_chain = probe_db["OtpChains"].count_documents({"username": USERNAME})
    check("A5 播种管理员已有一条链（空库播种即建链）", seeded_chain == 1, "链数量 %d" % seeded_chain)

    # 后半段要验证"没有链"时的行为：把链删掉，回到未建链状态。
    probe_db["OtpChains"].delete_many({})

    # ── B0. challenge 防枚举（此时 admin 还没有链）───────────────
    print("\n[B0] challenge：无链账号")

    st, b = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": USERNAME})
    fake = b.get("data") or {}
    fake_keys = sorted(fake.keys())
    check("B1 无链账号也返回 200 + 完整参数（不暴露'没有链'）",
          st == 200 and b.get("success") is True and len(fake_keys) == 8,
          "HTTP %s / %s" % (st, b.get("code")))
    check("B2 假 R 是 32 字符 Base32、N/迭代次数取配置值",
          len(fake.get("r", "")) == 32 and fake.get("n") == CHAIN_N
          and fake.get("iterations") == CHAIN_ITER,
          "r=%r n=%r it=%r" % (fake.get("r"), fake.get("n"), fake.get("iterations")))

    st, b2 = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": "no-such-user"})
    unknown = b2.get("data") or {}
    check("B3 不存在账号的响应字段与有账号**完全一致**",
          st == 200 and sorted(unknown.keys()) == fake_keys,
          "keys %s vs %s" % (sorted(unknown.keys()), fake_keys))
    check("B4 两次假响应的 R 不同（是随机，不是常量）",
          unknown.get("r") != fake.get("r"), "%r vs %r" % (unknown.get("r"), fake.get("r")))

    # ── B1. 建链（P3 之前没有端点，直接写库）────────────────────
    print("\n[B1] 建链（直接写库，模拟 P3 迁移结果）")
    admin = probe_db["Users"].find_one({"username": USERNAME})
    user_id = str(admin["_id"])
    r = new_seed()
    ROOT_X0 = chain_root(PASSWORD, r, CHAIN_ITER)
    head = cell(CHAIN_N)
    probe_db["OtpChains"].insert_one({
        "userId": user_id,
        "username": USERNAME,
        "r": r,
        "algorithm": "SHA256",
        "kdf": "PBKDF2-HMACSHA256",
        "kdfIterations": CHAIN_ITER,
        "length": CHAIN_N,
        "v": b64(head),
        "k": CHAIN_N - 1,
        "generation": 1,
        "createdAt": datetime.datetime.now(datetime.timezone.utc),
    })
    check("B5 链已落库（v=x_N, k=N-1）",
          probe_db["OtpChains"].count_documents({"userId": user_id}) == 1)

    st, b = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": USERNAME})
    real = b.get("data") or {}
    check("B6 有链账号拿到**真参数**（R/k/N 与库内一致）",
          st == 200 and real.get("r") == r and real.get("k") == CHAIN_N - 1
          and real.get("n") == CHAIN_N and real.get("iterations") == CHAIN_ITER,
          "r=%r k=%r n=%r" % (real.get("r"), real.get("k"), real.get("n")))
    check("B7 真/假响应字段集合仍然一致（防枚举在两条分支上都成立）",
          sorted(real.keys()) == fake_keys)

    # ── B2. 链值登录 ─────────────────────────────────────────────
    print("\n[B2] 链值登录")
    token = real.get("challengeToken")
    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": USERNAME, "otpCode": b64(cell(CHAIN_N - 1)), "challengeToken": token})
    ticket = (b.get("data") or {}).get("ticket")
    check("B8 Python 独立算出的 x_(N-1) 被接受（跨实现向量一致）",
          st == 200 and bool(ticket), "HTTP %s / %s / %s" % (st, b.get("code"), b.get("message")))

    doc = probe_db["OtpChains"].find_one({"userId": user_id})
    check("B9 核销后 k 减 1、v 变成刚提交的那一格",
          doc["k"] == CHAIN_N - 2 and doc["v"] == b64(cell(CHAIN_N - 1)),
          "k=%r" % doc.get("k"))

    consume_logs = [d for name in probe_db.list_collection_names() if name.startswith("AuditLogs")
                    for d in probe_db[name].find({"action": "OTP_CONSUME"})]
    check("B10 审计留下 OTP_CONSUME（成功也留痕，且不记链值）",
          len(consume_logs) == 1 and consume_logs[0].get("reasonCode") == "OTP_CHAIN_VERIFIED"
          and str(cell(CHAIN_N - 1)) not in str(consume_logs[0]),
          "找到 %d 条 / reason=%r" % (len(consume_logs), consume_logs[0].get("reasonCode") if consume_logs else None))

    # ── B3. 一次性 ───────────────────────────────────────────────
    print("\n[B3] 一次性：重放与挑战复用")
    st, b = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": USERNAME})
    token2 = (b.get("data") or {}).get("challengeToken")
    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": USERNAME, "otpCode": b64(cell(CHAIN_N - 1)), "challengeToken": token2})
    check("B11 重放刚才那一格 → 401，话术与口令错一致，计 1 次",
          st == 401 and b.get("code") == "INVALID_CREDENTIALS"
          and b.get("message") == "密码错误，还剩 2 次机会",
          "HTTP %s / %s / %s" % (st, b.get("code"), b.get("message")))

    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": USERNAME, "otpCode": b64(cell(CHAIN_N - 2)), "challengeToken": token2})
    check("B12 同一张挑战用第二次 → 401 OTP_CHALLENGE_INVALID，**不计次**",
          st == 401 and b.get("code") == "OTP_CHALLENGE_INVALID"
          and probe_db["Users"].find_one({"username": USERNAME})["failedLoginAttempts"] == 1,
          "HTTP %s / %s" % (st, b.get("code")))

    # ── B4. 跨格 + 锁定（计次语义与口令路径一致）─────────────────
    print("\n[B4] 跨格与锁定")
    st, b = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": USERNAME})
    t3 = (b.get("data") or {}).get("challengeToken")
    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": USERNAME, "otpCode": b64(cell(CHAIN_N - 3)), "challengeToken": t3})
    check("B13 下一格（尚未轮到）→ 拒，计 2 次",
          st == 401 and b.get("message") == "密码错误，还剩 1 次机会",
          "HTTP %s / %s" % (st, b.get("message")))

    st, b = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": USERNAME})
    t4 = (b.get("data") or {}).get("challengeToken")
    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": USERNAME, "otpCode": b64(cell(0)), "challengeToken": t4})
    check("B14 第三次失败 → ACCOUNT_LOCKED（链值路径也计次、也锁号）",
          st == 401 and b.get("code") == "ACCOUNT_LOCKED",
          "HTTP %s / %s" % (st, b.get("code")))

    probe_db["Users"].update_one({"username": USERNAME}, {"$set": {
        "status": "Enabled", "lockoutEnd": None, "lockoutWallAt": None, "lockoutUptimeAt": None,
        "lockoutDriftLogged": False, "failedLoginAttempts": 0,
        "failedWindowWallAt": None, "failedWindowUptimeAt": None,
    }})

    # ── B5. 用尽 ─────────────────────────────────────────────────
    print("\n[B5] 配额用尽")
    probe_db["OtpChains"].update_one({"userId": user_id},
                                     {"$set": {"k": 0, "v": b64(cell(1))}})
    st, b = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": USERNAME})
    t5 = (b.get("data") or {}).get("challengeToken")
    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": USERNAME, "otpCode": b64(cell(0)), "challengeToken": t5})
    check("B15 k=0 时提交 x0 → 401 OTP_CHAIN_EXHAUSTED（不是'凭据错'）",
          st == 401 and b.get("code") == "OTP_CHAIN_EXHAUSTED",
          "HTTP %s / %s / %s" % (st, b.get("code"), b.get("message")))
    check("B16 用尽**不计次**（attempts 仍为 0）",
          probe_db["Users"].find_one({"username": USERNAME})["failedLoginAttempts"] == 0)

    # ── B6. 冻结先于核销 ─────────────────────────────────────────
    print("\n[B6] 冻结账号：拒绝发生在核销之前")
    probe_db["OtpChains"].update_one({"userId": user_id},
                                     {"$set": {"k": 3, "v": b64(cell(4))}})
    probe_db["Users"].update_one({"username": USERNAME}, {"$set": {"status": "Disabled"}})
    st, b = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": USERNAME})
    t6 = (b.get("data") or {}).get("challengeToken")
    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": USERNAME, "otpCode": b64(cell(3)), "challengeToken": t6})
    after = probe_db["OtpChains"].find_one({"userId": user_id})
    check("B17 冻结 → 401 ACCOUNT_DISABLED，且 k 未变（没白吃一格）",
          st == 401 and b.get("code") == "ACCOUNT_DISABLED"
          and after["k"] == 3 and after["v"] == b64(cell(4)),
          "HTTP %s / %s / k=%r" % (st, b.get("code"), after.get("k")))

    # ── A'. 链存在之后，口令依然进不来 ──────────────────────────
    # ⚠️ 这一节在 P2–P7 断言的是"链存在与否都不影响旧口令路径"（那是回滚能力的判据）。
    #    P8 删掉口令路径之后，判据翻面：**无论链在不在**，带 password 的请求都只能得到
    #    "缺少 otpCode" 这一个结果。留着它是因为它守的正是本阶段最核心的一条性质 ——
    #    口令不再是一条可以走的门。
    print("\n[A'] 口令路径（链存在之后仍然不存在）")
    probe_db["Users"].update_one({"username": USERNAME}, {"$set": {"status": "Enabled"}})

    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": USERNAME, "password": "wrong-on-purpose"})
    check("A4 口令错 → 400 EMPTY_FIELDS（话术不再是\"密码错误，还剩 N 次机会\"）",
          st == 400 and b.get("code") == "EMPTY_FIELDS",
          "HTTP %s / %s / %s" % (st, b.get("code"), b.get("message")))

    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": USERNAME, "password": PASSWORD})
    check("A5 口令**对**也拿不到票据（唯一凭据是链值）",
          st == 400 and b.get("code") == "EMPTY_FIELDS"
          and not (b.get("data") or {}).get("ticket"),
          "HTTP %s / %s" % (st, b.get("code")))

    # ── B7. 开关与畸形输入 ──────────────────────────────────────
    print("\n[B7] 边界")
    # P8 的入口比 P2 更严：`otpCode` 与 `challengeToken` 都是必填，
    # 缺任何一项都在**进入计次逻辑之前**回 400 —— 一个写错的客户端不该把主子的账号锁掉。
    # （P2–P7 时这里走的是 401 OTP_CHALLENGE_INVALID，因为当时空挑战是在核销那一步被发现的。）
    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": USERNAME, "otpCode": b64(cell(3))})
    check("B18 缺挑战凭据 → 400 EMPTY_FIELDS（请求不完整，不进计次）",
          st == 400 and b.get("code") == "EMPTY_FIELDS",
          "HTTP %s / %s" % (st, b.get("code")))

    st, b = http_call(BASE, "POST", "/api/auth/login/challenge", {"username": "  "})
    check("B19 空用户名 → 400 EMPTY_FIELDS",
          st == 400 and b.get("code") == "EMPTY_FIELDS", "HTTP %s / %s" % (st, b.get("code")))

    # 挑战**存在但无效** + 链值乱码：必须回"挑战无效"，而不是"链值畸形"。
    # 这条守的是顺序 —— 先验挑战再解析链值。反过来的话，攻击者可以拿乱码链值
    # 探出"这个账号的链记录长什么样"，而不必先弄到一张合法挑战。
    st, b = http_call(BASE, "POST", "/api/auth/login",
                      {"username": USERNAME, "otpCode": "not-base64!!",
                       "challengeToken": "not-a-real-challenge"})
    check("B20 挑战无效优先于链值畸形（顺序：先验挑战、再解析链值）",
          st == 401 and b.get("code") == "OTP_CHALLENGE_INVALID",
          "HTTP %s / %s" % (st, b.get("code")))


if __name__ == "__main__":
    sys.exit(main())
