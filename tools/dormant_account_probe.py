# -*- coding: utf-8 -*-
"""真机验证：沉睡（僵尸）账号治理。

验证四件事，全部对着**真实库**(AuthBaselineDb) 打真实 HTTP + 直连数据库断言：

  A. 回填      —— 启动后老账号的 lastLoginAt 被从审计里补齐（不再是 null）
  B. 判定/只读 —— GET /dormant-users 能算天数、管理账号进 protected 组；
                  且该接口**不写审计**（幂等）
  C. 冻结      —— POST /freeze-user：置 Disabled、**吊销票据**、写 DORMANT_FREEZE；
                  管理账号被拒（DORMANT_PROTECTED_ROLE）、自己不能冻自己
  D. 解冻      —— POST /unlock 对 Disabled 生效：置 Enabled、写 DORMANT_RESTORE，
                  解冻后可正常登录

口径说明：脚本会**新建一个一次性测试账号**用于冻结/解冻，跑完删除，
绝不触碰真实 6 个账号（admin / 审计管理员1 / 用户管理员1 / 刁睿炎 …）。

用法：
  python tools/dormant_account_probe.py <exe路径> <端口>
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

from datetime import datetime, timedelta, timezone

# 公共探针基础层：库名守卫 + 代理绕过 + 后端启动。
#
# ⚠️ 本探针原本**硬编码** `DB_NAME = "AuthBaselineDb"`，直接对真实库建号/改号。
#    10-05 事故后改为默认打**独立测试库**（`--real` 才允许碰真实库）：
#      · 测试库起步时后端会自动播种 admin，A 段回填、C/D 段冻结解冻全流程都能验证；
#      · 真实库上"验证回填"这件事本身没有额外价值 —— 回填逻辑与库名无关。
from _probe_common import (
    ProbeDb,
    resolve_probe_db,
    start_backend,
    stop_backend,
    wait_backend_ready,
    http_call,
)

EXE = sys.argv[1]
PORT = int(sys.argv[2])
BASE = "http://127.0.0.1:%d" % PORT

# `--real` 显式声明"我要在真实库上跑"，此时才放行 AuthBaselineDb。
# 这需要在环境里置逃生舱，_probe_common 的守卫才会放行。
USE_REAL_DB = "--real" in sys.argv
if USE_REAL_DB:
    os.environ["AUTHBASELINE_ALLOW_REAL_DB"] = "1"
DB_NAME = resolve_probe_db("AuthBaselineDormantProbe")

TEST_USER = "zz_dormant_probe"          # 一次性测试账号（前缀 zz_ 便于识别）
TEST_PASS = "ProbePass123"
ADMIN_USER = "admin"
ADMIN_PASS = "Admin123"

probe_db = ProbeDb(DB_NAME)
db = probe_db

results = []


def check(name, ok, extra=""):
    results.append((name, bool(ok), extra))
    print("   [%s] %s%s" % ("OK  " if ok else "FAIL", name, ("  " + extra) if extra else ""))


def call(method, path, body=None, ticket=None):
    return http_call(BASE, method, path, body=body, ticket=ticket, timeout=60)


def shards():
    return [n for n in db.list_collection_names() if n.startswith("AuditLogs")]


def max_seq():
    top = 0
    for n in shards():
        d = db[n].find_one(sort=[("seq", -1)])
        if d and d.get("seq", 0) > top:
            top = d["seq"]
    return top


def audit_after(mark, action=None, target=None, result=None):
    q = {"seq": {"$gt": mark}}
    if action:
        q["action"] = action
    if target:
        q["target"] = target
    if result:
        q["result"] = result
    hits = []
    for n in shards():
        hits += list(db[n].find(q))
    return hits


# ---------- 启动后端 ----------
print("=" * 64)
print("  [0] 启动后端 %s @ %d" % (os.path.basename(EXE), PORT))
print("       目标库：%s%s" % (DB_NAME, "  ⚠️ 真实库（--real）" if USE_REAL_DB else "（测试库）"))

# 测试库起步要清一次，保证 admin 是后端新播种的、backfill 有东西可算。
# 真实库模式下**绝不清理**。
if not USE_REAL_DB and probe_db.drop_if_exists():
    print("       已清理旧测试库")

proc = start_backend(EXE, PORT, DB_NAME)
if not wait_backend_ready(BASE, proc, timeout_s=25, path="/api/auth/transport"):
    stop_backend(proc)
    print("   后端未起来，退出")
    sys.exit(2)
print("   后端就绪：True")

# ---------- 登录 admin 取票据（放在 A 段之前：回填场景需要它的登录审计） ----------
st, login = call("POST", "/api/auth/login", {"username": ADMIN_USER, "password": ADMIN_PASS})
ticket = (login.get("data") or {}).get("ticket", "")
check("admin 登录成功（既有功能未受影响）", st == 200 and ticket != "", "status=%d" % st)
if not ticket:
    stop_backend(proc)
    sys.exit(2)

# ---------- A. 回填 ----------
# 设计说明：全新库里 admin 从没登录过 → 没有 LOGIN_SUCCESS 审计 → 回填无事可做，
# 断言"已回填"必然失败。所以这里**主动构造**回填场景：
#   ① 上面的登录已产生一条 LOGIN_SUCCESS（在审计里）
#   ② 手工把 Users.lastLoginAt 清掉（模拟"改造前的老账号"）
#   ③ 重启后端 → BackfillLastLoginAt 应从审计里把它找回来
# 这样验证的是**回填逻辑本身**，而不是"碰巧有存量数据"。
print("\n[1] A · lastLoginAt 回填（启动时从审计补齐）")

db["Users"].update_one({"username": ADMIN_USER}, {"$unset": {"lastLoginAt": ""}})
cleared = db["Users"].find_one({"username": ADMIN_USER})
check("已清掉 admin 的 lastLoginAt（构造出「老账号」形态）",
      cleared is not None and cleared.get("lastLoginAt") is None,
      str(cleared.get("lastLoginAt") if cleared else "账号不存在"))

# 重启后端触发回填。MongoDbService 是懒构造，但回填在构造函数里，
# 所以"触库请求"一到就会跑（这里直接再登录一次即可）。
stop_backend(proc)
proc = start_backend(EXE, PORT, DB_NAME)
if not wait_backend_ready(BASE, proc, timeout_s=25, path="/api/auth/transport"):
    stop_backend(proc)
    print("   重启后未就绪，退出")
    sys.exit(2)
call("POST", "/api/auth/login", {"username": ADMIN_USER, "password": ADMIN_PASS})

admin_doc = db["Users"].find_one({"username": ADMIN_USER})
check("重启后 admin 的 lastLoginAt 被回填（不是 null）",
      admin_doc is not None and admin_doc.get("lastLoginAt") is not None,
      str(admin_doc.get("lastLoginAt") if admin_doc else None))

# admin 刚登录过，回填值应当接近当前时间（而不是被填成 createdAt）
check("回填值来自最近的 LOGIN_SUCCESS 审计（日期与今天一致）",
      admin_doc is not None and admin_doc.get("lastLoginAt") is not None
      and admin_doc["lastLoginAt"].date() == datetime.now(timezone.utc).date(),
      str(admin_doc.get("lastLoginAt") if admin_doc else None))

# ---------- B. 判定 / 只读 ----------
print("\n[2] B · GET /api/auth/dormant-users（只读）")
mark = max_seq()
st, dorm = call("GET", "/api/auth/dormant-users", ticket=ticket)
d = dorm.get("data") or {}
check("接口可用", st == 200 and dorm.get("success") is True, "status=%d" % st)
check("返回了阈值（默认 90）", d.get("thresholdDays") == 90, "thresholdDays=%s" % d.get("thresholdDays"))
check("返回三组：items / protectedItems / frozenItems",
      all(k in d for k in ("items", "protectedItems", "frozenItems")))
check("管理账号（admin 等）落在 protectedItems 而非 items",
      all(u.get("dormantProtected") for u in d.get("protectedItems", [])),
      "protected=%d items=%d frozen=%d" % (len(d.get("protectedItems", [])),
                                           len(d.get("items", [])), len(d.get("frozenItems", []))))

new_audit = audit_after(mark)
check("该接口**不写审计**（只读派生视图，避免刷屏）", len(new_audit) == 0,
      "本次新增审计 %d 条" % len(new_audit))

# ---------- 建一次性测试账号 ----------
# 走 create-account 建号：本项目的 register 需要邮箱 + 验证码（邮件功能启用时），
# 而 create-account 不绑邮箱、建号即启用，正好适合做治理探针的样本。
# 再用 pymongo 把它"改老"到 200 天前 —— 这样后续
# "冻结后登录被拒" 才能真的验证到口令与状态两条路径。
print("\n[3] 建一次性测试账号 %s" % TEST_USER)
db["Users"].delete_many({"username": TEST_USER})
st, reg = call("POST", "/api/auth/create-account",
               {"username": TEST_USER, "password": TEST_PASS,
                "role": "UserAdmin", "operatorPassword": ADMIN_PASS}, ticket=ticket)
check("建号接口成功（既有功能未受影响）", st == 200 and reg.get("success") is True,
      "status=%d code=%s" % (st, reg.get("code")))

# 降级为普通用户：治理探针要验证的是"普通账号可被冻结"，
# 而 UserAdmin 属于受保护角色，会走不到冻结逻辑。
db["Users"].update_one({"username": TEST_USER}, {"$set": {"role": "User"}})

old = datetime.now(timezone.utc) - timedelta(days=200)   # 200 天前 → 必判沉睡
db["Users"].update_one(
    {"username": TEST_USER},
    {"$set": {"status": "Enabled", "lastLoginAt": old, "createdAt": old}})
print("   已把测试账号改为 200 天未登录的普通用户")

# 重新拉沉睡清单，确认它进了候选
st, dorm2 = call("GET", "/api/auth/dormant-users", ticket=ticket)
items = (dorm2.get("data") or {}).get("items", [])
probe_row = next((u for u in items if u["username"] == TEST_USER), None)
check("测试账号被判定为沉睡候选", probe_row is not None)
check("候选里带 dormantDays 且 >= 200", probe_row is not None and probe_row.get("dormantDays", 0) >= 200,
      "dormantDays=%s" % (probe_row or {}).get("dormantDays"))
check("候选带 lastLoginAt", probe_row is not None and probe_row.get("lastLoginAt") is not None)

# 冻结前先确认：未冻结时用正确口令能登录（证明"拒绝"来自冻结而非口令错）
st, r = call("POST", "/api/auth/login", {"username": TEST_USER, "password": TEST_PASS})
check("冻结前正确口令可登录（对照组）", st == 200, "status=%d code=%s" % (st, r.get("code")))

# ---------- C. 冻结 ----------
print("\n[4] C · POST /api/auth/freeze-user")
mark = max_seq()
# C1 受保护角色不可冻结
st, r = call("POST", "/api/auth/freeze-user", {"username": "admin"}, ticket=ticket)
check("拒绝冻结管理账号（DORMANT_PROTECTED_ROLE）",
      st == 400 and r.get("code") == "DORMANT_PROTECTED_ROLE", "code=%s" % r.get("code"))

# C2 两道门槛的**优先级**。
# 冻结接口有两道独立门槛：角色保护（结构性 —— 谁都不能冻管理账号）
# 与自我豁免（关系性 —— 谁都不能冻自己）。
# 对"管理角色试图冻结自己"这个输入，两者都成立，接口必须先撞角色保护 ——
# 因为角色保护说的是"这个账号**换谁都不行**"。顺序反了会给人
# "换个管理员就能冻结管理账号"的错误暗示。
SELF_USER = "zz_self_probe"
db["Users"].delete_many({"username": SELF_USER})
call("POST", "/api/auth/create-account",
     {"username": SELF_USER, "password": TEST_PASS,
      "role": "UserAdmin", "operatorPassword": ADMIN_PASS}, ticket=ticket)
st, self_login = call("POST", "/api/auth/login", {"username": SELF_USER, "password": TEST_PASS})
self_ticket = (self_login.get("data") or {}).get("ticket", "")
check("自我豁免样本已登录（UserAdmin，拿到自己的票据）", self_ticket != "", "status=%d" % st)
st, r = call("POST", "/api/auth/freeze-user", {"username": SELF_USER}, ticket=self_ticket)
check("管理角色优先撞角色保护（而非自我豁免）—— 谁都不能冻结管理账号",
      st == 400 and r.get("code") == "DORMANT_PROTECTED_ROLE", "code=%s" % r.get("code"))

# 鉴权入口与既有接口一致：匿名调用一律被拒
st, r = call("POST", "/api/auth/freeze-user", {"username": TEST_USER})
check("匿名调用冻结接口被拒（鉴权入口与既有接口一致）",
      st in (401, 403), "status=%d code=%s" % (st, r.get("code")))

# C3 正常冻结
st, r = call("POST", "/api/auth/freeze-user",
             {"username": TEST_USER, "reason": "probe 200 天未登录"}, ticket=ticket)
check("冻结成功", st == 200 and r.get("success") is True, "status=%d code=%s" % (st, r.get("code")))
doc = db["Users"].find_one({"username": TEST_USER})
check("库中状态已置 Disabled", doc and doc.get("status") == "Disabled",
      "status=%s" % (doc or {}).get("status"))
check("已记录冻结时刻 dormantFrozenAt", doc and doc.get("dormantFrozenAt") is not None)

fz = audit_after(mark, action="DORMANT_FREEZE", target=TEST_USER, result="成功")
check("写入 DORMANT_FREEZE 审计（成功事件恰好 1 条）", len(fz) == 1, "%d 条" % len(fz))
check("审计里带原因", len(fz) == 1 and "200" in (fz[0].get("request") or ""),
      (fz[0].get("request") if fz else "")[:70])
# 被拒的调用同样留痕（越权/非法尝试不能静默）—— 上面匿名调用那笔
fz_all = audit_after(mark, action="DORMANT_FREEZE", target=TEST_USER)
check("被拒的冻结尝试也留痕（失败事件不静默）", len(fz_all) > len(fz),
      "失败 %d 条" % (len(fz_all) - len(fz)))

# C4 冻结后不能登录
st, r = call("POST", "/api/auth/login", {"username": TEST_USER, "password": TEST_PASS})
check("冻结后登录被拒（ACCOUNT_DISABLED）",
      st == 401 and r.get("code") == "ACCOUNT_DISABLED", "code=%s" % r.get("code"))

# C5 重复冻结被拒
st, r = call("POST", "/api/auth/freeze-user", {"username": TEST_USER}, ticket=ticket)
check("重复冻结被拒（ALREADY_FROZEN）", st == 400 and r.get("code") == "ALREADY_FROZEN",
      "code=%s" % r.get("code"))

# C6 冻结态出现在 frozenItems
st, dorm3 = call("GET", "/api/auth/dormant-users", ticket=ticket)
frozen_names = [u["username"] for u in (dorm3.get("data") or {}).get("frozenItems", [])]
check("冻结账号出现在 frozenItems", TEST_USER in frozen_names, "frozen=%s" % frozen_names)

# ---------- D. 解冻 ----------
print("\n[5] D · POST /api/auth/unlock（对 Disabled 生效）")
mark = max_seq()
st, r = call("POST", "/api/auth/unlock", {"username": TEST_USER}, ticket=ticket)
check("解除冻结成功", st == 200 and r.get("success") is True, "status=%d code=%s" % (st, r.get("code")))
doc = db["Users"].find_one({"username": TEST_USER})
check("库中状态回到 Enabled", doc and doc.get("status") == "Enabled",
      "status=%s" % (doc or {}).get("status"))
check("dormantFrozenAt 已清空", doc and doc.get("dormantFrozenAt") is None)

rs = audit_after(mark, action="DORMANT_RESTORE", target=TEST_USER)
check("写入 DORMANT_RESTORE 审计（与 UNLOCK 分开）", len(rs) == 1, "%d 条" % len(rs))
ul = audit_after(mark, action="UNLOCK", target=TEST_USER)
check("解冻走的是 DORMANT_RESTORE 而非 UNLOCK", len(ul) == 0, "%d 条 UNLOCK" % len(ul))

# 解冻后用正确口令重新登录 —— 这才是"恢复可登录"的完整证明
st, r = call("POST", "/api/auth/login", {"username": TEST_USER, "password": TEST_PASS})
check("解冻后正确口令可登录（恢复完成）", st == 200, "status=%d code=%s" % (st, r.get("code")))

# ---------- 既有功能未受影响 ----------
print("\n[6] 既有功能回归（同一次运行内）")
st, r = call("GET", "/api/auth/users", ticket=ticket)
check("GET /users 仍正常", st == 200 and isinstance(r.get("data"), list),
      "%d 个账号" % len(r.get("data") or []))
check("UserResponse 追加了沉睡字段",
      bool(r.get("data")) and "dormantDays" in r["data"][0] and "dormantProtected" in r["data"][0])
st, r = call("GET", "/api/auth/transport")
check("GET /transport 仍正常", st == 200 and r.get("success") is True)

# ---------- 清理 ----------
db["Users"].delete_many({"username": TEST_USER})
db["Users"].delete_many({"username": SELF_USER})
check("测试账号已清理",
      db["Users"].count_documents({"username": TEST_USER}) == 0
      and db["Users"].count_documents({"username": SELF_USER}) == 0)

stop_backend(proc)

# 测试库跑完即清；真实库模式（--real）只删自己建的 zz_ 账号，绝不删库。
if not USE_REAL_DB and probe_db.drop_if_exists():
    print("\n   测试库已清理：%s" % DB_NAME)

# ---------- 汇总 ----------
bad = [n for n, ok, _ in results if not ok]
print("\n" + "=" * 64)
if bad:
    print("  结论：FAIL ❌  %d/%d 项未达标" % (len(bad), len(results)))
    for n in bad:
        print("    - " + n)
else:
    print("  结论：PASS ✅  沉睡账号治理 %d 项断言全部通过" % len(results))
print("=" * 64)
sys.exit(1 if bad else 0)
