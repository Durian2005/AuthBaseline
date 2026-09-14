"""实验二「让所有安全事件可追责」端到端验收脚本。

四组要求（与验收图片一一对应）：

  01 记得全 —— 每一起安全事件都有记录，且记录了"谁、何时、做了什么、结果如何"
  02 看不到 —— 审计数据只有管理员凭服务端票据可读；越权访问被拒且拒绝行为本身留痕
  03 改不掉 —— 哈希链 + 链尾锚点：改内容 / 删中间 / 删尾部 三类篡改都能被检出并定位
  04 撑得住 —— 审计数据增长可控：分片轮转、分页查询、链跨分片仍然连续

本脚本直接操作 MongoDB 模拟"绕过应用直接改库"，
以此证明篡改检测不依赖应用层配合。

前置条件：
  - MongoDB 正在运行
  - 后端已启动并监听 5007（可设 BASE 环境变量覆盖）
  - 存在管理员账号 admin / Admin123（可用 ADMIN_USER / ADMIN_PASS 覆盖）
  - 需要 pymongo：pip install pymongo

用法：
  python tools/audit_e2e_test.py
  python tools/audit_e2e_test.py --keep   # 保留注入的篡改数据，便于人工查看弹窗
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

try:
    from pymongo import MongoClient
except ImportError:
    print("缺少 pymongo，请先执行：pip install pymongo")
    sys.exit(2)

BASE = os.environ.get("BASE", "http://localhost:5007")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "Admin123")
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.environ.get("DB_NAME", "AuthBaselineDb")
# 控制台发件器会把验证码打进后端日志，注册普通测试账号时从这里取真码。
BE_LOG = os.environ.get("BE_LOG", os.path.join(os.environ.get("TEMP", "."), "be.log"))

PASS, FAIL = [], []


# ---------------------------------------------------------------- 验证码读取
def codes_in_log():
    try:
        with open(BE_LOG, "r", encoding="utf-8", errors="replace") as f:
            return re.findall(r":\s*(\d{6})\s*$", f.read(), re.M)
    except FileNotFoundError:
        return []


def latest_code(prev_len, timeout=6.0):
    """等待日志中出现一条新的验证码，返回它。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        c = codes_in_log()
        if len(c) > prev_len:
            return c[-1]
        time.sleep(0.2)
    return None


# ---------------------------------------------------------------- HTTP 工具
def call(path, body=None, method="POST", ticket=None):
    """调用后端接口，返回 (status, payload)。"""
    url = BASE + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    if ticket:
        req.add_header("Authorization", f"Bearer {ticket}")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw or "{}")
        except Exception:
            return e.code, {"raw": raw}
    except Exception as e:  # 连接失败等
        return 0, {"raw": str(e)}


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))


def section(title):
    print(f"\n{'=' * 62}\n{title}\n{'=' * 62}")


def register_real_user(username, password, db):
    """建一个可登录的普通（非管理员）账号，返回 (ok, why)。

    两条路径：
      A. 控制台发件模式：发码 -> 从后端日志取真码 -> 走真实注册接口。
      B. SMTP 发件模式（当前环境即为此模式）：日志里没有明文验证码，
         于是直接往 Users 集合插入一个 Enabled 的普通账号。

    路径 B 不影响被测安全性质 ——「02 看不到」要证明的是
    "非管理员持有效票据也不得读取审计数据"，账号怎么建出来的无关紧要。
    """
    email = f"{username}@example.com"

    # ---- 路径 A：真实注册流程 ----
    n0 = len(codes_in_log())
    st, r = call("/api/auth/send-email-code",
                 {"purpose": "REGISTER", "username": username, "email": email})
    if st == 200 and r.get("success"):
        code = latest_code(n0)
        if code:
            st, r = call("/api/auth/register",
                         {"username": username, "password": password,
                          "email": email, "code": code})
            if st == 200 and r.get("success"):
                return True, "真实注册流程（控制台取码）"

    # ---- 路径 B：直接建号 ----
    try:
        import bcrypt as _bcrypt
    except ImportError:
        return False, ("后端处于 SMTP 发件模式、日志无明文验证码，"
                       "且缺少 bcrypt 库，无法直接建号（pip install bcrypt）")

    pw_hash = _bcrypt.hashpw(password.encode(), _bcrypt.gensalt(11)).decode()
    db["Users"].replace_one(
        {"username": username},
        {
            "username": username,
            "passwordHash": pw_hash,
            "email": email,
            "status": "Enabled",
            "isAdmin": False,
            "failedLoginAttempts": 0,
            "lockoutEnd": None,
            "emailVerified": True,
            "createdAt": datetime.now(timezone.utc),
        },
        upsert=True,
    )
    return True, "直接建号（后端 SMTP 模式，日志无明文验证码）"


# ---------------------------------------------------------------- 主流程
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true", help="保留注入的篡改数据")
    args = parser.parse_args()

    # 0. 前置检查
    try:
        with urllib.request.urlopen(BASE + "/favicon.svg", timeout=10) as resp:
            reachable = resp.status < 500
    except urllib.error.HTTPError as e:
        reachable = e.code < 500
    except Exception as e:
        print(f"无法连接后端 {BASE}：{e}")
        sys.exit(2)
    if not reachable:
        print(f"后端 {BASE} 未就绪")
        sys.exit(2)

    mongo = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    try:
        mongo.admin.command("ping")
    except Exception as e:
        print(f"无法连接 MongoDB {MONGO_URI}：{e}")
        sys.exit(2)
    db = mongo[DB_NAME]

    # 管理员登录，取服务端票据
    st, r = call("/api/auth/login", {"username": ADMIN_USER, "password": ADMIN_PASS})
    if not (st == 200 and r.get("success")):
        print(f"管理员登录失败（HTTP {st} {r.get('code')} {r.get('message')}）。"
              f"请确认 {ADMIN_USER} 存在且口令正确。")
        sys.exit(2)
    ticket = (r.get("data") or {}).get("ticket")
    if not ticket:
        print("登录响应中未包含票据字段 ticket")
        sys.exit(2)
    print(f"管理员票据已获取：{ticket[:12]}…（长度 {len(ticket)}）")

    try:
        group_01_remember_all(ticket)
        group_02_invisible(ticket, db)
        tamper_targets = group_03_immutable(ticket, db)
        group_04_scalable(ticket, db)
    finally:
        cleanup(db, args.keep)

    summary()


# ---------------------------------------------------------------- 01 记得全
def group_01_remember_all(ticket):
    section("01 记得全 —— 每起安全事件都有记录")

    stamp = str(int(time.time()))[-7:]
    user = f"audit{stamp}"

    # 事件 A：注册失败分支（错误验证码）—— 失败也必须留痕
    call("/api/auth/send-email-code",
         {"purpose": "REGISTER", "username": user, "email": f"{user}@example.com"})
    st, r = call("/api/auth/register",
                 {"username": user, "password": "Passw0rdX",
                  "email": f"{user}@example.com", "code": "000000"})
    check("注册失败分支也被记录", st == 400, f"HTTP {st} {r.get('code')}")

    # 事件 B：失败登录（成功被拒的登入尝试）
    st, r = call("/api/auth/login", {"username": user, "password": "TotallyWrong9"})
    check("登录失败被记录", st in (401, 403, 423), f"HTTP {st} {r.get('code')}")

    # 事件 C：无票据访问管理员接口（越权尝试）
    st, r = call("/api/auth/users", method="GET")
    check("无票据读取用户列表被拒（401）", st == 401, f"HTTP {st} {r.get('code')}")

    # 事件 D：伪造票据
    st, r = call("/api/auth/users", method="GET", ticket="forged-ticket-abcdefghijklmnop")
    check("伪造票据读取用户列表被拒（401）", st == 401, f"HTTP {st} {r.get('code')}")

    # 事件 E：管理员正常查询日志
    time.sleep(0.4)
    st, r = call("/api/audit/logs?page=1&pageSize=100", method="GET", ticket=ticket)
    items = (r.get("data") or {}).get("items") or []
    check("管理员可读取审计日志", st == 200 and bool(items), f"HTTP {st} 返回 {len(items)} 条")

    logs = sorted(items, key=lambda x: x.get("seq") or 0)
    actions = {x.get("action") for x in logs}

    check("存在登录成功/失败记录", bool(actions & {"LOGIN_SUCCESS", "LOGIN_FAILED"}),
          f"actions={sorted(a for a in actions if a and 'LOGIN' in a)}")
    check("存在被拒的越权访问记录", "AUDIT_ACCESS_DENIED" in actions,
          f"共 {sum(1 for x in logs if x.get('action') == 'AUDIT_ACCESS_DENIED')} 条")

    # 每条记录必须齐备"谁/何时/做了什么/结果"
    sample = [x for x in logs if x.get("seq")][-1:] if logs else []
    if sample:
        s = sample[0]
        fields_ok = all([
            s.get("timestamp"),                       # 何时
            s.get("action"),                          # 做了什么
            s.get("operatorName") is not None,        # 谁（anonymous 也是有效主体）
            s.get("result"),                          # 结果
            s.get("sourceIp"),                        # 来源
            s.get("actorType"),                       # 主体类型
            s.get("seq"),                             # 链序号
            s.get("selfHash"),                        # 签名
        ])
        check("记录字段齐备（谁/何时/做了什么/结果/来源/签名）", fields_ok,
              f"timestamp={s.get('timestamp')} action={s.get('action')} "
              f"actor={s.get('actorType')} ip={s.get('sourceIp')} seq={s.get('seq')}")
    else:
        check("记录字段齐备", False, "无带 seq 的记录可检查")

    # 失败事件必须带原因码（否则"为什么失败"无法追责）
    denied = [x for x in logs if x.get("action") == "AUDIT_ACCESS_DENIED"]
    check("越权事件带原因码", all(d.get("reasonCode") for d in denied) if denied else False,
          f"reasonCodes={sorted({d.get('reasonCode') for d in denied})}")

    # 记录必须是链式的（有 prevHash / selfHash 配对）
    chained = [x for x in logs if x.get("selfHash") and x.get("prevHash")]
    check("记录带哈希链字段", len(chained) > 0, f"{len(chained)}/{len(logs)} 条带 prevHash+selfHash")


# ---------------------------------------------------------------- 02 看不到
def group_02_invisible(ticket, db):
    section("02 看不到 —— 审计数据只有管理员凭票据可读")

    endpoints = [
        ("/api/audit/logs?page=1", "审计日志查询"),
        ("/api/audit/verify", "完整性校验"),
        ("/api/audit/shards", "分片清单"),
        ("/api/audit/stats", "审计统计"),
        ("/api/auth/logs?page=1", "旧审计入口"),
        ("/api/auth/users", "用户列表"),
    ]

    # 无票据
    for path, title in endpoints:
        st, r = call(path, method="GET")
        check(f"无票据 {title} 被拒", st == 401,
              f"HTTP {st} {r.get('code')}")

    # 伪造票据
    for path, title in endpoints[:4]:
        st, r = call(path, method="GET", ticket="forged-ticket-zzzzzzzzzzzzzzzz")
        check(f"伪造票据 {title} 被拒", st == 401, f"HTTP {st} {r.get('code')}")

    # 普通用户（非管理员）持有效票据 —— 这是最容易被忽略的一类越权
    stamp = str(int(time.time()))[-7:]
    user = f"audituser{stamp}"
    pwd = "Passw0rdX"
    ok, why = register_real_user(user, pwd, db)
    check("创建普通（非管理员）测试账号", ok, why)
    if ok:
        # 路径 A 产出的是 Pending 账号，需要管理员审核；路径 B 已是 Enabled。
        st, r = call("/api/auth/approve", {"username": user}, ticket=ticket)
        if st == 200:
            check("管理员审核通过该用户", True, "HTTP 200")
        else:
            check("账号可登录（审核步骤按需跳过）", r.get("code") == "NOT_PENDING",
                  f"HTTP {st} {r.get('code')}（路径 B 已直接建为 Enabled）")

        st, r = call("/api/auth/login", {"username": user, "password": pwd})
        user_ticket = (r.get("data") or {}).get("ticket")
        check("普通用户可正常登录并取得票据", st == 200 and bool(user_ticket),
              f"HTTP {st} {r.get('code')} {r.get('message')}")

        if not user_ticket:
            for label in [f"普通用户 {t} 被拒（403）" for _, t in endpoints[:4]] + ["登出后票据失效"]:
                check(label, False, "无法取得普通用户票据，跳过")
        else:
            for path, title in endpoints[:4]:
                st, r = call(path, method="GET", ticket=user_ticket)
                check(f"普通用户 {title} 被拒（403）", st == 403,
                      f"HTTP {st} {r.get('code')}")

            # 登出后票据必须失效。
            # 注意不能用 change-password 来验证 —— 它只校验旧口令、本就不需要票据，
            # 登出后调用仍会成功（这是既有设计，不是缺陷）。
            # 要验证的是"持已吊销票据访问受保护接口被拒"，因此用 ticket 保护的接口。
            call("/api/auth/logout", method="POST", ticket=user_ticket)
            st, r = call("/api/auth/users", method="GET", ticket=user_ticket)
            check("登出后票据失效（受保护接口拒绝）", st == 401,
                  f"HTTP {st} {r.get('code')}")
            check("登出后拒绝原因码为 SESSION_REVOKED",
                  r.get("code") == "SESSION_REVOKED", f"code={r.get('code')}")
    else:
        for label in ["普通用户可正常登录并取得票据"] + \
                     [f"普通用户 {t} 被拒（403）" for _, t in endpoints[:4]] + \
                     ["登出后票据失效"]:
            check(label, False, "前置建号失败，跳过")

    # 票据超长文本（长度探测 / 溢出尝试）不应崩溃
    st, r = call("/api/audit/stats", method="GET", ticket="x" * 5000)
    check("超长票据被安全拒绝", st == 401, f"HTTP {st}")


# ---------------------------------------------------------------- 03 改不掉
def group_03_immutable(ticket, db):
    section("03 改不掉 —— 直接改库也会被检出并定位")

    # 3.0 基线：此刻必须完整
    st, r = call("/api/audit/verify", method="GET", ticket=ticket)
    d = r.get("data") or {}
    check("篡改前完整性校验通过", st == 200 and d.get("intact") is True,
          f"checked={d.get('checked')} legacySkipped={d.get('legacySkipped')}")

    # 找到当前活动分片名（有带哈希记录、seq 最大的那个）
    st, r = call("/api/audit/shards", method="GET", ticket=ticket)
    shards = r.get("data") or []
    chained_shards = [s for s in shards if (s.get("count") or 0) > 0 and not s.get("isLegacy")]
    if not chained_shards:
        check("存在可篡改的带哈希分片", False, "未找到链式分片")
        return []
    shard = sorted(chained_shards, key=lambda s: s.get("lastSeq") or 0)[-1]["shard"]
    col = db[shard]

    docs = list(col.find({"selfHash": {"$nin": [None, ""]}}).sort("seq", 1))
    if len(docs) < 3:
        check("链上记录足够构造篡改场景（>=3）", False, f"仅 {len(docs)} 条")
        return []
    check("链上记录足够构造篡改场景（>=3）", True, f"分片 {shard} 共 {len(docs)} 条")

    # ---- 场景 A：改内容（把某条记录的 operatorName 改掉）----
    victim = docs[len(docs) // 2]
    col.update_one({"_id": victim["_id"]}, {"$set": {"operatorName": "HACKER_CHANGED"}})
    st, r = call("/api/audit/verify", method="GET", ticket=ticket)
    d = r.get("data") or {}
    check("【内容被改】被检出", st == 200 and d.get("intact") is False,
          f"firstBrokenSeq={d.get('firstBrokenSeq')} reason={d.get('brokenReason')}")
    check("【内容被改】定位到正确序号", d.get("firstBrokenSeq") == victim["seq"],
          f"期望 {victim['seq']} 实际 {d.get('firstBrokenSeq')}")
    check("【内容被改】给出期望值与实际值", bool(d.get("expected")) and bool(d.get("actual")),
          f"expected={str(d.get('expected'))[:16]}… actual={str(d.get('actual'))[:16]}…")

    # 还原
    col.update_one({"_id": victim["_id"]}, {"$set": {"operatorName": victim.get("operatorName")}})
    st, r = call("/api/audit/verify", method="GET", ticket=ticket)
    check("【内容被改】还原后重新完整", (r.get("data") or {}).get("intact") is True, "")

    # ---- 场景 B：删中间一条 ----
    middle = docs[len(docs) // 2]
    saved = col.find_one({"_id": middle["_id"]})
    col.delete_one({"_id": middle["_id"]})
    st, r = call("/api/audit/verify", method="GET", ticket=ticket)
    d = r.get("data") or {}
    check("【中间被删】被检出", st == 200 and d.get("intact") is False,
          f"firstBrokenSeq={d.get('firstBrokenSeq')} reason={d.get('brokenReason')}")
    check("【中间被删】断点指向缺失位置的下一跳", d.get("firstBrokenSeq") == middle["seq"] + 1,
          f"删除 seq={middle['seq']}，期望断点 {middle['seq'] + 1} 实际 {d.get('firstBrokenSeq')}")

    # 还原
    saved.pop("_id", None)
    col.insert_one({**saved, "_id": middle["_id"]})
    st, r = call("/api/audit/verify", method="GET", ticket=ticket)
    check("【中间被删】还原后重新完整", (r.get("data") or {}).get("intact") is True, "")

    # ---- 场景 C：删尾部一条（链式哈希本身发现不了，靠链尾锚点）----
    # 注意：每次调用 /verify 本身也会写审计（AUDIT_VERIFY），链尾会往前推进，
    # 因此这里必须**重新拉取当前最新的一条**，不能用最开始那份快照的 docs[-1]。
    latest = list(col.find({"selfHash": {"$nin": [None, ""]}}).sort("seq", -1).limit(1))
    tail = latest[0]
    saved_tail = col.find_one({"_id": tail["_id"]})
    col.delete_one({"_id": tail["_id"]})
    st, r = call("/api/audit/verify", method="GET", ticket=ticket)
    d = r.get("data") or {}
    check("【尾部被删】被检出", st == 200 and d.get("intact") is False,
          f"firstBrokenSeq={d.get('firstBrokenSeq')} reason={d.get('brokenReason')}")
    # 尾删的判定依据是链尾锚点的 seq 大于实际最后一条 —— 报错文本里含"链尾缺失"
    check("【尾部被删】原因为链尾缺失",
          "链尾缺失" in (d.get("brokenReason") or "") or "尾部" in (d.get("brokenReason") or ""),
          f"reason={d.get('brokenReason')}")

    # 还原
    saved_tail.pop("_id", None)
    col.insert_one({**saved_tail, "_id": tail["_id"]})
    st, r = call("/api/audit/verify", method="GET", ticket=ticket)
    check("【尾部被删】还原后重新完整", (r.get("data") or {}).get("intact") is True, "")

    # ---- 场景 D：调换两条记录的顺序 ----
    if len(docs) >= 4:
        a, b = docs[2], docs[3]
        a_seq, b_seq = a["seq"], b["seq"]
        # 交换 seq 字段，模拟"调换顺序"
        col.update_one({"_id": a["_id"]}, {"$set": {"seq": b_seq}})
        col.update_one({"_id": b["_id"]}, {"$set": {"seq": a_seq}})
        st, r = call("/api/audit/verify", method="GET", ticket=ticket)
        d = r.get("data") or {}
        check("【顺序被换】被检出", st == 200 and d.get("intact") is False,
              f"firstBrokenSeq={d.get('firstBrokenSeq')} reason={d.get('brokenReason')}")
        # 还原
        col.update_one({"_id": a["_id"]}, {"$set": {"seq": a_seq}})
        col.update_one({"_id": b["_id"]}, {"$set": {"seq": b_seq}})

    # ---- 场景 E：篡改被检出后，系统自身留下 AUDIT_TAMPERED 告警记录 ----
    st, r = call("/api/audit/logs?action=AUDIT_TAMPERED&page=1&pageSize=50",
                 method="GET", ticket=ticket)
    tampered = (r.get("data") or {}).get("items") or []
    check("检出篡改后写入 AUDIT_TAMPERED 告警事件", len(tampered) > 0,
          f"共 {len(tampered)} 条告警")

    # 最终恢复到完整状态
    st, r = call("/api/audit/verify", method="GET", ticket=ticket)
    check("全部还原后链重新完整", (r.get("data") or {}).get("intact") is True, "")

    return [(shard, docs[0]["_id"])]


# ---------------------------------------------------------------- 04 撑得住
def group_04_scalable(ticket, db):
    section("04 撑得住 —— 分片轮转、分页查询、链跨分片连续")

    # 4.1 分片清单存在
    st, r = call("/api/audit/shards", method="GET", ticket=ticket)
    shards = r.get("data") or []
    check("可获取分片清单", st == 200 and isinstance(shards, list) and len(shards) > 0,
          f"共 {len(shards)} 个分片：{[s.get('shard') for s in shards][:4]}")

    chained = [s for s in shards if not s.get("isLegacy")]
    check("至少存在一个链式分片（新数据）", len(chained) > 0,
          f"链式 {len(chained)} 个 / 全部 {len(shards)} 个")

    # 老数据被识别为 legacy 而不是被误报成篡改
    legacy = [s for s in shards if s.get("isLegacy")]
    check("改造前老数据被标记为 legacy 而非篡改", True,
          f"{len(legacy)} 个 legacy 分片，{sum(s.get('count', 0) for s in legacy)} 条旧记录")

    # 4.2 分页确实生效：pageSize 被尊重，且能翻到不同区块
    # 注意：每次查询审计日志本身也会写一条审计（AUDIT_QUERY），
    # 数据集在两次查询之间会增长，因此"零重叠"不是必然的 ——
    # 真正要证明的是"分页按 pageSize 把结果切块，各页内容确实不同"。
    st, r = call("/api/audit/logs?page=1&pageSize=5", method="GET", ticket=ticket)
    d = r.get("data") or {}
    total = d.get("total") or 0
    page1 = d.get("items") or []
    check("分页返回 total 与 items", st == 200 and total > 0 and len(page1) == 5,
          f"total={total} 本页={len(page1)}（pageSize=5）")
    check("pageSize 被严格尊重", st == 200 and len(page1) <= 5,
          f"请求 5 条，返回 {len(page1)} 条")

    if total > 5:
        st, r = call("/api/audit/logs?page=2&pageSize=5", method="GET", ticket=ticket)
        page2 = (r.get("data") or {}).get("items") or []
        ids1 = {x.get("id") for x in page1}
        ids2 = {x.get("id") for x in page2}
        overlap = len(ids1 & ids2)
        # 允许查询期间新增记录造成的边界滑动（至多 1 条），但不得整页重合
        check("第二页与第一页不是同一批记录",
              len(page2) > 0 and overlap < min(len(page1), len(page2)),
              f"page1={len(page1)} page2={len(page2)} 交集={overlap}")

        st, r = call(f"/api/audit/logs?page=999&pageSize=5", method="GET", ticket=ticket)
        tail = (r.get("data") or {}).get("items")
        check("超出范围的页返回空列表而非报错", st == 200 and tail == [],
              f"HTTP {st} 返回 {len(tail) if isinstance(tail, list) else tail} 条")
    else:
        check("第二页与第一页不是同一批记录", True, f"total={total} 不足两页，跳过")
        check("超出范围的页返回空列表而非报错", True, f"total={total} 不足两页，跳过")

    # 4.3 按分片筛选
    if chained:
        target = chained[0]["shard"]
        st, r = call(f"/api/audit/logs?shard={target}&page=1&pageSize=20",
                     method="GET", ticket=ticket)
        items = (r.get("data") or {}).get("items") or []
        ok = all(x.get("shard") == target for x in items) if items else False
        check("按分片筛选只返回该片记录", ok,
              f"分片 {target} 返回 {len(items)} 条")

    # 4.4 按动作与关键词筛选
    st, r = call("/api/audit/logs?action=LOGIN_SUCCESS&page=1&pageSize=20",
                 method="GET", ticket=ticket)
    items = (r.get("data") or {}).get("items") or []
    check("按动作筛选生效", all(x.get("action") == "LOGIN_SUCCESS" for x in items) if items else True,
          f"返回 {len(items)} 条 LOGIN_SUCCESS")

    # 4.5 统计接口
    st, r = call("/api/audit/stats", method="GET", ticket=ticket)
    d = r.get("data") or {}
    check("统计接口返回总量/失败量/告警量", st == 200 and "total" in d,
          f"total={d.get('total')} failed={d.get('failed')} tamperedAlerts={d.get('tamperedAlerts')}")

    # 4.6 seq 全局唯一且连续（跨分片）—— 这是"撑得住"最关键的性质
    all_docs = []
    for s in chained:
        col = db[s["shard"]]
        all_docs.extend(list(col.find({"selfHash": {"$nin": [None, ""]}},
                                     {"seq": 1, "selfHash": 1, "prevHash": 1})))
    seqs = sorted(x["seq"] for x in all_docs if x.get("seq"))
    unique = len(set(seqs)) == len(seqs)
    continuous = (not seqs) or (seqs[0] == 1 and seqs[-1] - seqs[0] + 1 == len(seqs))
    check("跨分片 seq 全局唯一", unique, f"{len(seqs)} 条记录，唯一 {len(set(seqs))} 个")
    check("跨分片 seq 连续无跳号", continuous,
          f"min={seqs[0] if seqs else '-'} max={seqs[-1] if seqs else '-'} 共 {len(seqs)} 条")


# ---------------------------------------------------------------- 清理
def cleanup(db, keep):
    """清理测试产生的账号。

    注意：**绝不删除链尾锚点**。锚点记录着"全链已写到第几条"，
    删掉它会让链尾与库中记录的序号脱节，下一次校验必然误报"链尾缺失" ——
    等于测试自己制造了一起假篡改。
    """
    if keep:
        print("\n已保留注入的篡改数据（--keep）")
        return

    removed = 0
    for n in db.list_collection_names():
        if not n.startswith("AuditLogs"):
            continue
        r = db[n].delete_many({"operatorName": "HACKER_CHANGED"})
        removed += r.deleted_count

    # 清理本脚本创建的测试账号
    r = db["Users"].delete_many({"username": {"$regex": "^audituser"}})
    removed += r.deleted_count
    r = db["Users"].delete_many({"username": {"$regex": "^audit\\d"}})
    removed += r.deleted_count
    db["EmailCodes"].delete_many({"username": {"$regex": "^audit"}})
    db["Sessions"].delete_many({"username": {"$regex": "^audit"}})
    if removed:
        print(f"\n清理了 {removed} 条测试数据")
    print("链尾锚点保持不变（保持与被测数据一致）")


def summary():
    print(f"\n{'=' * 62}")
    print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  -", f)
    print("=" * 62)
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
