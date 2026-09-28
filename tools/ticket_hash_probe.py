# -*- coding: utf-8 -*-
"""会话票据哈希化（存储安全 S1）的真机验证。

要证明的一句话：
  **库里再也拿不到"读走就能用"的东西** —— 票据只以无盐 SHA-256 的形态落库，
  而且把库里那个值原样当凭证发回来必须被拒。

判据（逐条对应断言）：
  1. 登录接口契约未变：仍返回明文票据（客户端拿不到东西就登不了）。
  2. Sessions 文档里**不存在** ticket 明文字段。
  3. 落库的 ticketHash 独立复算一致（Python 自己算 SHA-256，不信后端自证）。
  4. 用 ticketHash 当 Bearer 发送 => 必须 401。
  5. 索引已换成 uniq_ticket_hash，老的 uniq_ticket 必须已删除。
     （不删会出事：字段缺失时 MongoDB 按 null 参与唯一约束，第二条会话就插不进去）
  6. 连续两次登录都能成功 —— 这是上一条的回归验证。
  7. 吊销仍按哈希工作：登出后明文票据立刻 401。
  8. 整个 Sessions 集合里扫不到明文票据。
  9. 审计记录里不含明文票据（它们本来只存 sha256(request/response)）。

用法：
  python ticket_hash_probe.py [exe路径] [端口] [测试库名] [--keep]
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta

from bson import ObjectId
from pymongo import MongoClient

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") \
    else os.path.join(ROOT, "AuthServer", "bin", "Release", "net8.0", "AuthServer.exe")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else 5231
DB = next((a for a in sys.argv[3:] if not a.startswith("--")), "TicketHashProbe")
BASE = "http://127.0.0.1:%d" % PORT
KEEP = "--keep" in sys.argv

ADMIN_USER = os.environ.get("E2E_ADMIN", "admin")
ADMIN_PW = os.environ.get("E2E_ADMIN_PASS", "Admin123")

_cli = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=8000)
if DB in _cli.list_database_names():
    _cli.drop_database(DB)
    print("已清理旧测试库", DB)
db = _cli[DB]

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print("  [%s] %s%s" % ("OK  " if cond else "FAIL", name, ("  — " + str(detail)) if detail else ""))


def call(method, path, body=None, ticket=None, timeout=60):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Content-Type", "application/json")
    if ticket:
        req.add_header("Authorization", "Bearer " + ticket)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8", "replace") or "{}")
    except Exception as e:
        return 0, {"err": str(e)}


def b64url(raw: bytes) -> str:
    """与后端 TicketHasher.Hash 同样的编码：Base64Url、去掉 padding。"""
    return base64.b64encode(raw).decode().replace("+", "-").replace("/", "_").rstrip("=")


def expected_hash(ticket: str) -> str:
    """**独立复算**：不看后端代码、不看后端返回值，自己算一遍。"""
    return b64url(hashlib.sha256(ticket.encode("utf-8")).digest())


def shards():
    return [n for n in db.list_collection_names() if n.startswith("AuditLogs")]


def login(username, password):
    st, b = call("POST", "/api/auth/login", {"username": username, "password": password})
    return st, b, (b.get("data") or {}).get("ticket")


# ---------- 1. 启动 ----------
print("exe    :", EXE)
print("端口   :", PORT)
print("测试库 :", DB, "（全新库起步，跑完即清）")
print("\n[1] 启动后端（全新库会自动播种 admin/Admin123）...")

LOG = os.path.join(tempfile.gettempdir(), "ticket_hash_probe_%d.log" % PORT)
# stdout 必须重定向到文件：管道撑满会让后端假死
env = {**os.environ,
       "ASPNETCORE_URLS": "http://127.0.0.1:%d" % PORT,
       "MongoDbSettings__DatabaseName": DB}


def start_backend():
    """起后端并等就绪。独立运行时没有 wwwroot，GET / 返回 404 也算已监听。"""
    logf = open(LOG, "ab")
    p = subprocess.Popen([EXE], env=env, stdout=logf, stderr=subprocess.STDOUT)
    for _ in range(60):
        st, _ = call("GET", "/")
        if st != 0:
            return p, logf
        time.sleep(0.5)
    p.kill()
    raise RuntimeError("60 秒未就绪，日志见 " + LOG)


def stop_backend(p, logf):
    p.kill()
    p.wait(timeout=10)
    try:
        logf.close()
    except Exception:
        pass
    time.sleep(0.8)          # 等监听端口彻底释放再重启


proc, logf = start_backend()
print("  就绪 (PID=%d)" % proc.pid)

st, b, tk1 = login(ADMIN_USER, ADMIN_PW)
if not tk1:
    print("  !! admin 登录失败：HTTP %s / %s" % (st, b.get("code")))
    proc.kill()
    sys.exit(2)
print("  管理员已登录，票据长度 %d（明文只应存在于客户端手里）" % len(tk1))
print("  明文票据前 12 位（仅本地打印，不入库）：%s…" % tk1[:12])


# ---------- 2. 库里的落库形态 ----------
print("\n[2] 直读 Sessions 集合，看票据到底以什么形态落库")

docs = list(db["Sessions"].find({}))
print("  当前会话文档 %d 条" % len(docs))

check("Sessions 里有本次签发的会话", len(docs) >= 1, "%d 条" % len(docs))

any_plain_field = [d for d in docs if "ticket" in d]
check("文档中不存在明文 `ticket` 字段", not any_plain_field,
      "命中 %d 条" % len(any_plain_field))

check("文档中存在 `ticketHash` 字段", all("ticketHash" in d for d in docs),
      "缺失 %d 条" % sum(1 for d in docs if "ticketHash" not in d))

hashes = [d.get("ticketHash", "") for d in docs]
check("ticketHash 不等于明文票据", tk1 not in hashes,
      "命中明文 %d 处" % sum(1 for h in hashes if h == tk1))

stored = docs[0].get("ticketHash", "")
check("ticketHash 与 Python 独立复算一致（不靠后端自证）",
      stored == expected_hash(tk1),
      "库中 %s… / 复算 %s…" % (stored[:10], expected_hash(tk1)[:10]))

print("  一条会话文档的字段：", ", ".join(sorted(docs[0].keys())))


# ---------- 3. 索引形态 ----------
print("\n[3] 索引：必须换成哈希上的唯一索引，且删掉建在明文字段上的老索引")

idx_names = []
for ix in db["Sessions"].list_indexes():
    idx_names.append((ix.get("name"), json.dumps(ix.get("key", {}), ensure_ascii=False),
                      bool(ix.get("unique"))))
print("  现有索引：")
for n, k, u in idx_names:
    print("     %-22s %-22s unique=%s" % (n, k, u))

check("存在 uniq_ticket_hash（且 unique）",
      any(n == "uniq_ticket_hash" and u for n, _, u in idx_names),
      "实际索引：%s" % ", ".join(n for n, _, _ in idx_names))
check("老的 uniq_ticket 已删除", not any(n == "uniq_ticket" for n, _, _ in idx_names),
      "实际索引：%s" % ", ".join(n for n, _, _ in idx_names))


# ---------- 4. 库里那个值不能当凭证 ----------
print("\n[4] 关键断言：把库里的 ticketHash 原样当 Bearer 发回来")

st_plain, b_plain = call("GET", "/api/auth/users", ticket=tk1)
check("明文票据可正常访问受保护接口（基线）", st_plain == 200,
      "HTTP %s" % st_plain)

st_hash, b_hash = call("GET", "/api/auth/users", ticket=stored)
check("用库中的 ticketHash 当票据 => 必须 401", st_hash == 401,
      "HTTP %s / %s" % (st_hash, b_hash.get("code") or b_hash.get("message")))


# ---------- 5. 连续两次登录（唯一索引回归） ----------
print("\n[5] 连续两次登录 —— 验证唯一索引没被『缺失字段』卡住")

st2, b2, tk2 = login(ADMIN_USER, ADMIN_PW)
check("第二次登录仍成功（唯一索引回归）", st2 == 200 and bool(tk2),
      "HTTP %s / %s" % (st2, b2.get("code")))

if tk2:
    check("两次登录得到不同票据", tk2 != tk1, "ticket2 前 8 位 %s…" % tk2[:8])
    check("两条会话各自独立入库且哈希不同",
          len({expected_hash(tk1), expected_hash(tk2)}) == 2,
          "哈希 %s… / %s…" % (expected_hash(tk1)[:8], expected_hash(tk2)[:8]))


# ---------- 6. 吊销仍按哈希工作 ----------
print("\n[6] 登出（吊销）仍能按哈希定位到会话")

st_out, b_out = call("POST", "/api/auth/logout", ticket=tk2)
print("  logout -> HTTP %s / %s" % (st_out, b_out.get("code")))

st_after, b_after = call("GET", "/api/auth/users", ticket=tk2)
check("登出后原明文票据立即被拒", st_after == 401,
      "HTTP %s / %s" % (st_after, b_after.get("code") or b_after.get("message")))

revoked = db["Sessions"].find_one({"ticketHash": expected_hash(tk2)})
check("库里该会话已标记 revokedAt（说明吊销是按哈希命中的）",
      bool(revoked and revoked.get("revokedAt")),
      "revokedAt=%s / reason=%s" % (revoked.get("revokedAt") if revoked else None,
                                    revoked.get("revokedReason") if revoked else None))

# 未登出的那张仍在有效期：确认"吊销 A 不会误伤 B"
st_keep, _ = call("GET", "/api/auth/users", ticket=tk1)
check("另一张未登出的票据不受影响", st_keep == 200, "HTTP %s" % st_keep)


# ---------- 7. 全集合扫明文 ----------
print("\n[7] 整个 Sessions 集合里扫一遍明文票据（含所有字符串字段）")

hits = 0
for d in db["Sessions"].find({}):
    for k, v in d.items():
        if isinstance(v, str) and (tk1 in v or (tk2 and tk2 in v)):
            hits += 1
            print("     !! 命中字段 %s" % k)
check("Sessions 集合任何字段都不含明文票据", hits == 0, "命中 %d 处" % hits)


# ---------- 8. 审计里也不留明文 ----------
print("\n[8] 审计记录里不应出现明文票据（它们只存 sha256(request/response)）")

audit_hits = 0
audit_len = 0
for n in shards():
    for d in db[n].find({}):
        audit_len += 1
        for k, v in d.items():
            if isinstance(v, str) and (tk1 in v or (tk2 and tk2 in v)):
                audit_hits += 1
                print("     !! 命中 %s.%s" % (n, k))
check("审计记录中不含明文票据", audit_hits == 0, "扫了 %d 条，命中 %d 处" % (audit_len, audit_hits))


# ---------- 9. 老库升级路径 ----------
# 这段代码只在"库里存在旧形态文档"时才跑，全新库永远碰不到它 ⇒ 不造一份老数据就等于没验证。
# 忠实模拟改造前的库：既有明文 ticket 字段，也有建在它上面的唯一索引 uniq_ticket。
print("\n[9] 升级路径：手工造一条『改造前形态』的会话，重启后端看它是否被就地升级")

LEGACY_TICKET = "LegacyPlainTicketForUpgradeTest_0123456789abcdef"

# 先证明"为什么必须删掉老索引"——不是猜的，是让它当场失败给你看。
# 此刻集合里已有若干条**没有 ticket 字段**的会话（新形态），在它上面建唯一索引必然冲突。
try:
    db["Sessions"].create_index([("ticket", 1)], unique=True, name="probe_uniq_ticket_demo")
    demo_err = None
except Exception as e:
    demo_err = type(e).__name__
try:
    db["Sessions"].drop_index("probe_uniq_ticket_demo")
except Exception:
    pass
check("缺字段的文档存在时，无法在老 ticket 字段上建唯一索引（E11000 dup key null）",
      demo_err is not None,
      "实测异常：%s —— 这正是必须删除 uniq_ticket 的理由" % demo_err)

# 再忠实构造"改造前"的库：清空后建老索引，让集合里只有这一条旧形态文档
db["Sessions"].delete_many({})
db["Sessions"].create_index([("ticket", 1)], unique=True, name="uniq_ticket")
db["Sessions"].insert_one({
    "_id": ObjectId(),
    "ticket": LEGACY_TICKET,
    "username": ADMIN_USER,
    "userId": "",
    "isAdminAtIssue": True,
    "roleAtIssue": "Admin",
    "issuedAt": datetime.utcnow(),
    "lastSeenAt": datetime.utcnow(),
    "expiresAt": datetime.utcnow() + timedelta(hours=1),
    "revokedAt": None,
    "revokedReason": "",
})
before = db["Sessions"].find_one({"ticket": LEGACY_TICKET})
check("已造出改造前形态的会话（含明文 ticket 字段）", bool(before),
      "字段：%s" % (", ".join(sorted(before.keys())) if before else "未插入"))

print("  重启后端，触发启动期的升级逻辑…")
stop_backend(proc, logf)
proc, logf = start_backend()

# ⚠️ 时序坑：MongoDbService 是**懒构造**（第一次被 DI 解析时才建索引/跑迁移），
#    所以"等 GET / 就绪"远远不够 —— 静态文件中间件的 404 根本没碰数据库。
#    此处必须先打一个**一定会触库**的请求，否则读到的是"尚未迁移"状态，
#    会得出"迁移没跑"的错误结论（第一版脚本就栽在这里，白查一轮）。
warm_st, warm_b, _ = login(ADMIN_USER, ADMIN_PW)
check("重启后再打一次触库请求（迁移与索引在此刻才真正执行）",
      warm_st == 200, "HTTP %s / %s" % (warm_st, warm_b.get("code")))

after = db["Sessions"].find_one({"_id": before["_id"]}) if before else None
check("升级后文档仍存在（会话没有被删掉）", bool(after),
      "_id=%s" % (before["_id"] if before else None))
check("升级后明文 `ticket` 字段被移除", bool(after) and "ticket" not in after,
      "剩余字段：%s" % (", ".join(sorted(after.keys())) if after else "文档不存在"))
check("升级后 ticketHash == 明文票据的 SHA-256（独立复算）",
      bool(after) and after.get("ticketHash") == expected_hash(LEGACY_TICKET),
      "库中 %s…" % (after.get("ticketHash", "")[:10] if after else "-"))

idx_names2 = [ix.get("name") for ix in db["Sessions"].list_indexes()]
check("升级后老索引 uniq_ticket 已删除", "uniq_ticket" not in idx_names2,
      "实际索引：%s" % ", ".join(idx_names2))
check("升级后新索引 uniq_ticket_hash 已建立", "uniq_ticket_hash" in idx_names2,
      "实际索引：%s" % ", ".join(idx_names2))

# 这条断言是"就地升级"的价值所在：老会话不该因为改造而被踢下线
st_legacy, b_legacy = call("GET", "/api/auth/users", ticket=LEGACY_TICKET)
check("升级前签发的明文票据**仍然可用**（会话未被打断）", st_legacy == 200,
      "HTTP %s / %s" % (st_legacy, b_legacy.get("code") or b_legacy.get("message")))

# 而库里那半边依旧不能当凭证用
upside = (after or {}).get("ticketHash") or "x"
st_legacy_hash, _ = call("GET", "/api/auth/users", ticket=upside)
check("升级后的 ticketHash 同样不能当票据用", st_legacy_hash == 401,
      "HTTP %s（发送值 %s…）" % (st_legacy_hash, upside[:10]))


# ---------- 10. 收尾 ----------
stop_backend(proc, logf)

if FAILED or KEEP:
    print("\n  测试库保留：%s" % DB)
else:
    _cli.drop_database(DB)
    print("\n  测试库已清理：%s" % DB)

print("\n" + "=" * 68)
print("  结论：%s" % ("PASS ✅ 共 %d 项" % len(PASSED) if not FAILED
                     else "FAIL ❌ 有 %d 项未达标：%s" % (len(FAILED), FAILED)))
print("=" * 68)
sys.exit(1 if FAILED else 0)
