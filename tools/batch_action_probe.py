# -*- coding: utf-8 -*-
"""批量处置接口（POST /api/auth/batch）的端到端验证。

用法：
  python tools/batch_action_probe.py <exe路径> <端口> [数据库名]

为什么必须同一进程内跑完：调用方 shell 退出后子进程会被回收，
分步执行拿不到活着的后端。

这个接口的核心承诺是"批量只是循环，不改业务语义"，所以验证也按这个承诺展开：

  ① **逐条鉴权**：一批里大部分可处置，不代表整批可处置。
     每个目标仍各自过 CanBeManagedBy（含自我豁免），无权的那条单独失败。
  ② **部分成功是正常结果**：成功 N / 未处理 M 同时出现在一次响应里，
     且每条都带自己的 code —— 只回一句"操作失败"等于没回答。
  ③ **审计粒度不变**：每个目标各记一条，与单条操作逐字一致；
     不存在"一条批量汇总"把 N 个账号的处置压成一行。
  ④ **入口预检**：操作者本身没有该动作的权限时，一个目标都不进循环，
     否则一次误点会往审计链里刷进 N 条同样的拒绝记录，淹没真正的越权尝试。
  ⑤ **去重与归一**：`" u1 "` 与 `"U1"` 是同一个目标，不能处置两次。

判定：所有断言通过 + 审计链完整 → PASS。
"""
import sys
import time

from _probe_common import ProbeDb, resolve_probe_db, start_backend, http_call

EXE = sys.argv[1]
PORT = int(sys.argv[2])
DB = resolve_probe_db("AuthBaselineBatchProbe")
BASE = "http://127.0.0.1:%d" % PORT

KEEP = "--keep" in sys.argv

print("exe    :", EXE)
print("端口   :", PORT)
print("测试库 :", DB)

probe_db = ProbeDb(DB)

if probe_db.drop_if_exists():
    print("已清理旧测试库")

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    mark = "OK  " if cond else "FAIL"
    print("  [%s] %s%s" % (mark, name, ("  — " + str(detail)) if detail else ""))


def call(method, path, body=None, ticket=None, timeout=90):
    return http_call(BASE, method, path, body=body, ticket=ticket, timeout=timeout)


def login(username, password):
    st, b = call("POST", "/api/auth/login", {"username": username, "password": password})
    data = b.get("data") or {}
    return st, data.get("ticket"), data


def batch(ticket, action, usernames, **extra):
    body = {"action": action, "usernames": usernames}
    body.update(extra)
    return call("POST", "/api/auth/batch", body, ticket=ticket)


def items_of(b):
    """批量响应里的逐条明细。成功在 data.items，全失败也在 data.items（400 也照给）。"""
    return (b.get("data") or {}).get("items") or []


def item_map(b):
    return {i.get("username"): i for i in items_of(b)}


def user_doc(name):
    return probe_db["Users"].find_one({"username": name}) or {}


# ---------- 启动 ----------
print("\n[1] 启动后端（全新库，自动播种 admin/Admin123）...")
proc = start_backend(EXE, PORT, DB)

ready = False
for _ in range(60):
    st, _ = call("GET", "/")
    if st != 0:
        ready = True
        break
    time.sleep(0.5)
if not ready:
    print("  !! 60 秒未就绪，放弃")
    proc.kill()
    sys.exit(1)
print("  就绪 (PID=%d)" % proc.pid)

# ---------- 2. 造数据 ----------
print("\n[2] 准备账号：1 个用户管理员 / 1 个审计管理员 / 3 个普通用户")
st, admin_tk, admin_info = login("admin", "Admin123")
check("admin 登录成功", st == 200 and bool(admin_tk), "HTTP %s" % st)

for name, pwd, role in (
    ("ops01", "Ops12345", "UserAdmin"),
    ("auditor01", "Audit12345", "AuditAdmin"),
    ("u1", "User12345", "User"),
    ("u2", "User12345", "User"),
    ("u3", "User12345", "User"),
    ("u4", "User12345", "User"),
):
    st, b = call("POST", "/api/auth/create-account",
                 {"username": name, "password": pwd, "role": role,
                  "operatorPassword": "Admin123"}, ticket=admin_tk)
    check("创建 %s（%s）" % (name, role), st == 200, "HTTP %s / %s" % (st, b.get("code")))

st, ops_tk, ops_info = login("ops01", "Ops12345")
check("ops01（用户管理员）登录成功", st == 200 and bool(ops_tk), "HTTP %s" % st)
st, auditor_tk, _ = login("auditor01", "Audit12345")
check("auditor01（审计管理员）登录成功", st == 200 and bool(auditor_tk), "HTTP %s" % st)

# ---------- 3. 入口校验 ----------
print("\n[3] 入口校验：无票据 / 假票据 / 空目标 / 未知动作 / 超量")
st, b = batch(None, "freeze", ["u1"])
check("无票据 → 401 NO_TICKET", st == 401 and b.get("code") == "NO_TICKET",
      "HTTP %s / %s" % (st, b.get("code")))

st, b = batch("deadbeef", "freeze", ["u1"])
check("假票据 → 401 SESSION_INVALID", st == 401 and b.get("code") == "SESSION_INVALID",
      "HTTP %s / %s" % (st, b.get("code")))

st, b = batch(admin_tk, "freeze", [])
check("空目标 → 400 EMPTY_FIELDS", st == 400 and b.get("code") == "EMPTY_FIELDS",
      "HTTP %s / %s" % (st, b.get("code")))

st, b = batch(admin_tk, "explode", ["u1"])
check("未知动作 → 400 BATCH_UNKNOWN_ACTION",
      st == 400 and b.get("code") == "BATCH_UNKNOWN_ACTION", "HTTP %s / %s" % (st, b.get("code")))

# 201 个不存在的目标：只为验证上限，不会真的处置到任何账号
st, b = batch(admin_tk, "unlock", ["ghost%03d" % i for i in range(201)])
check("单次超过 200 个目标 → 400 BATCH_TOO_MANY",
      st == 400 and b.get("code") == "BATCH_TOO_MANY", "HTTP %s / %s" % (st, b.get("code")))

# ---------- 4. 正常批量：两条都成功 ----------
print("\n[4] admin 批量冻结 u1/u2：逐条执行，两条都成功")
st, b = batch(admin_tk, "freeze", ["u1", "u2"], reason="批量探针：验证冻结")
check("批量冻结 → 200", st == 200, "HTTP %s / %s" % (st, b.get("code")))
check("业务码 = OK（全部成功）", b.get("code") == "OK", b.get("code"))
summary = b.get("data") or {}
check("汇总 total=2 / ok=2 / failed=0",
      (summary.get("total"), summary.get("ok"), summary.get("failed")) == (2, 2, 0),
      "total=%s ok=%s failed=%s" % (summary.get("total"), summary.get("ok"), summary.get("failed")))
check("明细逐条返回（每目标一条）", len(items_of(b)) == 2,
      " / ".join("%s:%s" % (i.get("username"), i.get("code")) for i in items_of(b)))
check("u1 库内 status=Disabled", user_doc("u1").get("status") == "Disabled", user_doc("u1").get("status"))
check("u2 库内 status=Disabled", user_doc("u2").get("status") == "Disabled", user_doc("u2").get("status"))

# ---------- 5. 审计粒度：每目标一条 ----------
cols = [n for n in probe_db.list_collection_names() if n.startswith("AuditLogs")]


def count(action, target=None, result=None, reason=None):
    q = {"action": action}
    if target:
        q["target"] = target
    if result:
        q["result"] = result
    if reason:
        q["reasonCode"] = reason
    return sum(probe_db[n].count_documents(q) for n in cols)


print("\n[5] 审计粒度：批量不做汇总，每个目标各留一条")
check("DORMANT_FREEZE 对 u1 有审计（≥1 条）", count("DORMANT_FREEZE", "u1") >= 1,
      "%d 条" % count("DORMANT_FREEZE", "u1"))
check("DORMANT_FREEZE 对 u2 有审计（≥1 条）", count("DORMANT_FREEZE", "u2") >= 1,
      "%d 条" % count("DORMANT_FREEZE", "u2"))
check("不存在「一条批量汇总」形式的审计（Action 里没有 BATCH*）",
      sum(probe_db[n].count_documents({"action": {"$regex": "^BATCH"}}) for n in cols) == 0)

# ---------- 6. 批量里混入自己 / 受保护角色 ----------
print("\n[6] 批量里混入自己：只拒那一条，其余照做")
st, b = batch(admin_tk, "freeze", ["u3", "admin"])
check("批量含自己 → 仍是 200（部分成功）", st == 200, "HTTP %s / %s" % (st, b.get("code")))
check("业务码 = BATCH_PARTIAL", b.get("code") == "BATCH_PARTIAL", b.get("code"))
m = item_map(b)
check("u3 那条成功", (m.get("u3") or {}).get("success") is True, m.get("u3"))
# 冻结这条路上，admin 先被"管理角色不参与沉睡治理"拦住，轮不到自我豁免 ——
# 两者都是拒绝，但原因码不同，断言必须写真实的那一个，否则测试会奖励错误实现。
check("admin 那条被拒，原因是受保护角色（DORMANT_PROTECTED_ROLE）",
      (m.get("admin") or {}).get("success") is False
      and (m.get("admin") or {}).get("code") == "DORMANT_PROTECTED_ROLE",
      (m.get("admin") or {}).get("message"))
check("admin 库内仍是 Enabled（没被自己冻结）",
      user_doc("admin").get("status") == "Enabled", user_doc("admin").get("status"))
check("汇总：成功 1 / 未处理 1",
      ((b.get("data") or {}).get("ok"), (b.get("data") or {}).get("failed")) == (1, 1),
      "ok=%s failed=%s" % ((b.get("data") or {}).get("ok"), (b.get("data") or {}).get("failed")))

print("\n[6b] 自我豁免：用户管理员把「自己」和「普通用户」放进同一批")
st, b = batch(ops_tk, "delete", ["ops01", "u4"])
check("批量含自己 → 200（部分成功）", st == 200, "HTTP %s / %s" % (st, b.get("code")))
m = item_map(b)
check("自己那条被自我豁免拦下（FORBIDDEN_TARGET）",
      (m.get("ops01") or {}).get("code") == "FORBIDDEN_TARGET",
      (m.get("ops01") or {}).get("message"))
check("普通用户那条照常注销", (m.get("u4") or {}).get("success") is True, m.get("u4"))
check("ops01 库内仍存在（没有把自己注销掉）", bool(user_doc("ops01")))
check("u4 库内已删除", not user_doc("u4"))

# ---------- 7. 全部失败：400 + 明细照给 ----------
print("\n[7] 全部没做成：HTTP 400，但逐条原因照给")
st, b = batch(admin_tk, "unlock", ["ghost1", "ghost2"])
check("全失败 → 400 BATCH_ALL_FAILED",
      st == 400 and b.get("code") == "BATCH_ALL_FAILED", "HTTP %s / %s" % (st, b.get("code")))
check("即使全失败，明细仍是 2 条（不能只回一句\"失败\"）", len(items_of(b)) == 2,
      " / ".join("%s:%s" % (i.get("username"), i.get("code")) for i in items_of(b)))
check("每条的原因码是 NOT_FOUND",
      all(i.get("code") == "NOT_FOUND" for i in items_of(b)),
      " / ".join(str(i.get("code")) for i in items_of(b)))

# 正常账号「解锁」也不算成功：本来没被锁 —— 语义上属"未处理"，不是报错
st, b = batch(admin_tk, "unlock", ["u1", "u2"])
check("对正常账号批量解锁 → 成功 2（冻结中，确实可解）", st == 200 and b.get("code") == "OK",
      "HTTP %s / %s" % (st, b.get("code")))
check("解冻后 u1 库内 status=Enabled", user_doc("u1").get("status") == "Enabled",
      user_doc("u1").get("status"))

st, b = batch(admin_tk, "unlock", ["u1"])
check("对已启用账号再解锁 → 全部未处理（NOT_LOCKED）",
      st == 400 and b.get("code") == "BATCH_ALL_FAILED"
      and (items_of(b) or [{}])[0].get("code") == "NOT_LOCKED",
      "HTTP %s / %s" % (st, (items_of(b) or [{}])[0].get("code")))

# ---------- 8. 逐条权限：用户管理员够不到审计管理员 ----------
print("\n[8] 逐条权限：UserAdmin 批量注销，够不到的单独失败")
st, b = batch(ops_tk, "delete", ["auditor01", "u2"])
check("ops01 批量注销 [审计管理员, 普通用户] → 200（部分成功）", st == 200,
      "HTTP %s / %s" % (st, b.get("code")))
m = item_map(b)
check("审计管理员那条被拒（FORBIDDEN_TARGET）",
      (m.get("auditor01") or {}).get("code") == "FORBIDDEN_TARGET",
      (m.get("auditor01") or {}).get("message"))
check("普通用户那条成功删除", (m.get("u2") or {}).get("success") is True, m.get("u2"))
check("auditor01 库内仍存在", bool(user_doc("auditor01")), user_doc("auditor01").get("status"))
check("u2 库内已删除", not user_doc("u2"))
check("越权拒绝已留痕（DELETE_USER / FORBIDDEN_TARGET / auditor01）",
      count("DELETE_USER", "auditor01", reason="FORBIDDEN_TARGET") >= 1,
      "%d 条" % count("DELETE_USER", "auditor01", reason="FORBIDDEN_TARGET"))

# ---------- 9. 入口预检：改角色只有 Admin 能做 ----------
print("\n[9] 入口预检：UserAdmin 发起批量改角色 → 整批拒绝，一个目标都不进循环")
before = sum(probe_db[n].count_documents({"action": "SET_ROLE"}) for n in cols)
st, b = batch(ops_tk, "set-role", ["u1", "u3"], role="User", operatorPassword="Ops12345")
# 用户管理员"能管用户"但"不能任免角色"，后端为此单独给了 FORBIDDEN_ROLE
# （而不是笼统的 NOT_ADMIN）—— 好让"低阶管理员试图提权"在审计里能被一眼捞出。
check("ops01 批量改角色 → 403 FORBIDDEN_ROLE（低阶管理员试图提权）",
      st == 403 and b.get("code") == "FORBIDDEN_ROLE",
      "HTTP %s / %s" % (st, b.get("code")))
check("被拒响应里没有逐条明细（说明没进循环）", not items_of(b), "items=%d" % len(items_of(b)))
after = sum(probe_db[n].count_documents({"action": "SET_ROLE"}) for n in cols)
check("审计只增加 1 条拒绝记录（不是每个目标各一条）", after - before == 1,
      "新增 %d 条" % (after - before))
check("u1 角色未被改动", user_doc("u1").get("role") == "User", user_doc("u1").get("role"))

# ---------- 10. admin 改角色 + 去重归一 ----------
print("\n[10] Admin 批量改角色；同样的目标写两遍只处置一次")
st, b = batch(admin_tk, "set-role", ["u3"], role="AuditAdmin", operatorPassword="Admin123")
check("admin 批量把 u3 改成审计管理员 → 成功",
      st == 200 and b.get("code") == "OK", "HTTP %s / %s" % (st, b.get("code")))
check("u3 库内 role=AuditAdmin", user_doc("u3").get("role") == "AuditAdmin",
      user_doc("u3").get("role"))

st, b = batch(admin_tk, "set-role", ["u1"], role="User", operatorPassword="wrong-password")
check("操作者口令错误 → 该条失败（不减权、不改角色）",
      st == 400 and (items_of(b) or [{}])[0].get("success") is False,
      "HTTP %s / %s" % (st, (items_of(b) or [{}])[0].get("code")))
check("u1 角色仍是 User", user_doc("u1").get("role") == "User", user_doc("u1").get("role"))

st, b = batch(admin_tk, "freeze", [" u1 ", "U1"], reason="去重验证")
summary = b.get("data") or {}
check("「 u1 」与「U1」归一后只处置一次（total=1）", summary.get("total") == 1,
      "total=%s items=%s" % (summary.get("total"),
                             [i.get("username") for i in items_of(b)]))
check("该目标确实被冻结", user_doc("u1").get("status") == "Disabled", user_doc("u1").get("status"))

# ---------- 11. 审计链完整性 ----------
print("\n[11] 审计链完整性（由审计管理员调校验接口，独立复算）")
st, b = call("GET", "/api/audit/verify", ticket=auditor_tk)
data = b.get("data") or {}
check("verify 接口可调用", st == 200, "HTTP %s / %s" % (st, b.get("code")))
check("哈希链完整（未发现断裂）", data.get("intact") is True,
      "checked=%s detail=%s" % (data.get("checked"), b.get("message")))

# ---------- 收尾 ----------
proc.kill()
proc.wait(timeout=10)

print("\n" + "=" * 64)
print("  通过 %d 项，失败 %d 项" % (len(PASSED), len(FAILED)))
if FAILED:
    print("  失败清单：")
    for f in FAILED:
        print("    -", f)
print("  结论：%s" % ("PASS ✅ 批量处置语义与单条一致" if not FAILED else "FAIL ❌"))

if FAILED or KEEP:
    print("  测试库保留：%s（%s）" % (DB, "有失败项，留现场排查" if FAILED else "--keep 指定"))
else:
    probe_db.drop()
    print("  测试库已清理：%s" % DB)
print("=" * 64)
sys.exit(1 if FAILED else 0)
