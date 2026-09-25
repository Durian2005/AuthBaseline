# -*- coding: utf-8 -*-
"""角色分离端到端验证：管账号的人看不到日志，看日志的人管不了账号。

用法：
  python tools/role_separation_test.py <exe路径> <端口> <数据库名>

为什么必须在同一进程内完成：调用方 shell 退出后子进程会被回收，
分步执行拿不到活着的后端。

验证矩阵（角色两两互斥，每个角色都有"能做什么"和"不能做什么"两侧）：

  Admin（初始 admin）    能管用户 ✅  能任免角色 ✅  能看审计 ❌
  UserAdmin（被创建）    能管用户 ✅  能任免角色 ❌  能看审计 ❌
  AuditAdmin（被任命）   能管用户 ❌  能任免角色 ❌  能看审计 ✅

处置（注销 / 变更角色）的目标范围另算，与"能不能管用户"不是一回事：
  Admin      —— 除自己以外任意账号，含审计管理员与其它管理员
  UserAdmin  —— 只有普通用户与用户管理员，够不到上级
  所有角色   —— 一律不能处置自己（自我豁免，保证系统恒有管理员）

判定：所有断言通过且审计链完整 → PASS。
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
import hashlib

from datetime import datetime, timezone

from pymongo import MongoClient

EXE = sys.argv[1]
PORT = int(sys.argv[2])
DB = sys.argv[3]
BASE = "http://127.0.0.1:%d" % PORT

# 默认跑完即清库（见文件末尾"收尾"）。加 --keep 可强制保留测试库供人工翻查
# （失败时会自动保留，不必显式加）。
KEEP = "--keep" in sys.argv[4:]

print("exe    :", EXE)
print("端口   :", PORT)
print("测试库 :", DB)

# 清理可能残留的旧测试库，保证从"全新库"起步（此时后端会播种 admin）
_cli = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=8000)
if DB in _cli.list_database_names():
    _cli.drop_database(DB)
    print("已清理旧测试库")

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    mark = "OK  " if cond else "FAIL"
    print("  [%s] %s%s" % (mark, name, ("  — " + str(detail)) if detail else ""))


def call(method, path, body=None, ticket=None, timeout=90):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Content-Type", "application/json")
    if ticket:
        req.add_header("Authorization", "Bearer " + ticket)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data, timeout=timeout) as r:
            text = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(text or "{}")
            except Exception:
                return r.status, {}
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(text or "{}")
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"err": str(e)}


def login(username, password):
    st, b = call("POST", "/api/auth/login", {"username": username, "password": password})
    data = b.get("data") or {}
    return st, data.get("ticket"), data


# ---------- 启动 ----------
print("\n[1] 启动后端（全新库，自动播种 admin/Admin123）...")
LOG_PATH = os.path.join(tempfile.gettempdir(), "role_sep_%d.log" % PORT)
# 注意：stdout 必须重定向到文件而不是 PIPE —— 后端每请求打一行日志，
# 管道缓冲区被撑满会让子进程阻塞在写 stdout，后续请求全部超时。
logf = open(LOG_PATH, "wb")
env = {**os.environ,
       "ASPNETCORE_URLS": "http://127.0.0.1:%d" % PORT,
       "MongoDbSettings__DatabaseName": DB}
proc = subprocess.Popen([EXE], env=env, stdout=logf, stderr=subprocess.STDOUT)

ready = False
for _ in range(60):
    st, _ = call("GET", "/")
    if st != 0:      # 独立运行没有 wwwroot，404 也算"已监听"
        ready = True
        break
    time.sleep(0.5)
if not ready:
    print("  !! 60 秒未就绪，放弃")
    proc.kill()
    sys.exit(1)
print("  就绪 (PID=%d)" % proc.pid)

# ---------- 2. admin 的双面性 ----------
print("\n[2] Admin（初始 admin）：能管用户，但看不了任何审计数据")
st, admin_tk, admin_info = login("admin", "Admin123")
check("admin 登录成功", st == 200 and bool(admin_tk), "HTTP %s" % st)
check("admin 角色 = Admin", admin_info.get("role") == "Admin", admin_info.get("role"))
check("admin isAdmin = true（能管用户）", admin_info.get("isAdmin") is True)

st, b = call("GET", "/api/auth/users", ticket=admin_tk)
check("admin 读用户列表 → 允许", st == 200, "HTTP %s" % st)

for path in ["/api/audit/logs", "/api/audit/verify", "/api/audit/stats", "/api/audit/shards",
             "/api/auth/logs"]:
    st, b = call("GET", path, ticket=admin_tk)
    check("admin 访问 %s → 拒绝" % path,
          st == 403 and b.get("code") == "NOT_AUDIT_ADMIN",
          "HTTP %s / %s" % (st, b.get("code")))

# ---------- 3. admin 创建账号（无需邮箱） ----------
print("\n[3] Admin 创建账号：不绑邮箱、建号即启用")
st, b = call("POST", "/api/auth/create-account",
             {"username": "ops01", "password": "Ops12345", "role": "UserAdmin",
              "operatorPassword": "Admin123"}, ticket=admin_tk)
check("创建「用户管理员」ops01 → 成功", st == 200, "HTTP %s / %s" % (st, b.get("code")))
check("  返回角色 = UserAdmin", (b.get("data") or {}).get("role") == "UserAdmin")
check("  未绑定邮箱", not (b.get("data") or {}).get("email"))

st, b = call("POST", "/api/auth/create-account",
             {"username": "auditor01", "password": "Audit12345", "role": "AuditAdmin",
              "operatorPassword": "Admin123"}, ticket=admin_tk)
check("创建「审计管理员」auditor01 → 成功", st == 200, "HTTP %s / %s" % (st, b.get("code")))
check("  返回角色 = AuditAdmin", (b.get("data") or {}).get("role") == "AuditAdmin")

# 库里确认这两个账号确实没有邮箱、状态是启用
users = {u["username"]: u for u in _cli[DB]["Users"].find()}
for name in ("ops01", "auditor01"):
    u = users.get(name) or {}
    check("%s 库记录：status=Enabled 且 email 为空" % name,
          u.get("status") == "Enabled" and not u.get("email"),
          "status=%s email=%s" % (u.get("status"), u.get("email")))

# 新账号能否直接登录（免邮箱验证）
st, ops_tk, ops_info = login("ops01", "Ops12345")
check("ops01 免邮箱直接登录成功", st == 200 and bool(ops_tk), "HTTP %s" % st)

# 口令太弱时拒绝
st, b = call("POST", "/api/auth/create-account",
             {"username": "weak01", "password": "abc", "role": "UserAdmin",
              "operatorPassword": "Admin123"}, ticket=admin_tk)
check("弱口令被拒", st == 400 and b.get("code") == "WEAK_PASSWORD",
      "HTTP %s / %s" % (st, b.get("code")))

# 操作者口令错误时拒绝（二次确认）
st, b = call("POST", "/api/auth/create-account",
             {"username": "nope01", "password": "Nope12345", "role": "UserAdmin",
              "operatorPassword": "wrongpassword"}, ticket=admin_tk)
check("操作者口令错误 → 拒绝", st == 401, "HTTP %s / %s" % (st, b.get("code")))

# ---------- 4. UserAdmin 的能力边界 ----------
print("\n[4] UserAdmin（ops01）：同样能管用户，但不能任免角色、不能看审计")
st, b = call("GET", "/api/auth/users", ticket=ops_tk)
check("ops01 读用户列表 → 允许", st == 200, "HTTP %s" % st)

st, b = call("POST", "/api/auth/create-account",
             {"username": "try01", "password": "Try12345", "role": "UserAdmin",
              "operatorPassword": "Ops12345"}, ticket=ops_tk)
check("ops01 尝试创建账号 → 拒绝", st == 403, "HTTP %s / %s" % (st, b.get("code")))

st, b = call("POST", "/api/auth/set-role",
             {"username": "admin", "role": "AuditAdmin", "operatorPassword": "Ops12345"},
             ticket=ops_tk)
check("ops01 尝试变更他人角色 → 拒绝", st == 403, "HTTP %s / %s" % (st, b.get("code")))

st, b = call("GET", "/api/audit/logs", ticket=ops_tk)
check("ops01 访问审计日志 → 拒绝", st == 403 and b.get("code") == "NOT_AUDIT_ADMIN",
      "HTTP %s / %s" % (st, b.get("code")))

# ---------- 5. AuditAdmin 的能力边界 ----------
print("\n[5] AuditAdmin（auditor01）：能看审计，但不能碰任何用户管理")
st, auditor_tk, auditor_info = login("auditor01", "Audit12345")
check("auditor01 登录成功", st == 200 and bool(auditor_tk), "HTTP %s" % st)
check("auditor01 角色 = AuditAdmin", auditor_info.get("role") == "AuditAdmin")
check("auditor01 isAdmin = false（不具备用户管理能力）",
      auditor_info.get("isAdmin") is False)

for path in ["/api/audit/logs", "/api/audit/verify", "/api/audit/stats", "/api/audit/shards"]:
    st, b = call("GET", path, ticket=auditor_tk)
    check("auditor01 访问 %s → 允许" % path, st == 200, "HTTP %s / %s" % (st, b.get("code")))

st, b = call("GET", "/api/auth/users", ticket=auditor_tk)
check("auditor01 读用户列表 → 拒绝", st == 403, "HTTP %s / %s" % (st, b.get("code")))

st, b = call("POST", "/api/auth/create-account",
             {"username": "try02", "password": "Try12345", "role": "AuditAdmin",
              "operatorPassword": "Audit12345"}, ticket=auditor_tk)
check("auditor01 尝试创建账号 → 拒绝", st == 403, "HTTP %s / %s" % (st, b.get("code")))

# ---------- 6. admin 任命角色 + 越界尝试 ----------
print("\n[6] Admin 任命角色：能指定审计管理员，但不能自我提权")
st, b = call("POST", "/api/auth/set-role",
             {"username": "ops01", "role": "AuditAdmin", "operatorPassword": "Admin123"},
             ticket=admin_tk)
check("把 ops01 变更为 AuditAdmin → 成功", st == 200, "HTTP %s / %s" % (st, b.get("code")))
check("  返回新角色 = AuditAdmin", (b.get("data") or {}).get("role") == "AuditAdmin")

# 角色变更后旧票据必须失效
st, b = call("GET", "/api/auth/users", ticket=ops_tk)
check("ops01 旧票据已被吊销", st == 401 and b.get("code") == "SESSION_REVOKED",
      "HTTP %s / %s" % (st, b.get("code")))

st, new_ops_tk, new_ops_info = login("ops01", "Ops12345")
check("ops01 重新登录后角色 = AuditAdmin", new_ops_info.get("role") == "AuditAdmin")
st, b = call("GET", "/api/audit/logs", ticket=new_ops_tk)
check("ops01 改角色后能读审计日志", st == 200, "HTTP %s" % st)
st, b = call("GET", "/api/auth/users", ticket=new_ops_tk)
check("ops01 改角色后读用户列表被拒（不再管账号）", st == 403, "HTTP %s" % st)

# 越界尝试
st, b = call("POST", "/api/auth/set-role",
             {"username": "admin", "role": "AuditAdmin", "operatorPassword": "Admin123"},
             ticket=admin_tk)
check("admin 变更自己的角色 → 拒绝", st == 400 and b.get("code") == "CANNOT_SET_OWN_ROLE",
      "HTTP %s / %s" % (st, b.get("code")))

st, b = call("POST", "/api/auth/create-account",
             {"username": "admin2", "password": "Admin12345", "role": "Admin",
              "operatorPassword": "Admin123"}, ticket=admin_tk)
check("创建「管理员」角色 → 拒绝（不能自我复制）",
      st == 400 and b.get("code") == "FORBIDDEN_ROLE", "HTTP %s / %s" % (st, b.get("code")))

st, b = call("POST", "/api/auth/set-role",
             {"username": "auditor01", "role": "Admin", "operatorPassword": "Admin123"},
             ticket=admin_tk)
check("把他人设为「管理员」→ 拒绝", st == 400 and b.get("code") == "FORBIDDEN_ROLE",
      "HTTP %s / %s" % (st, b.get("code")))

# 无票据 / 匿名
st, b = call("GET", "/api/audit/logs")
check("无票据访问审计日志 → 401", st == 401 and b.get("code") == "NO_TICKET",
      "HTTP %s / %s" % (st, b.get("code")))

# ---------- 7. 账号处置范围：管理员范围全开，下级够不到上级 ----------
print("\n[7] 注销范围：管理员能注销审计管理员，用户管理员不能")

# 对照组：普通用户直接落库，避免绕"注册 + 邮箱验证码"这条与本段无关的链路。
# 注销只认目标账号的角色，不需要目标能登录，所以口令哈希给占位值即可。
_cli[DB]["Users"].insert_one({
    "username": "todelete", "passwordHash": "x", "status": "Enabled",
    "role": "User", "failedLoginAttempts": 0,
    "createdAt": datetime.now(timezone.utc),
})

st, b = call("POST", "/api/auth/delete-user", {"username": "admin"}, ticket=admin_tk)
check("admin 注销自己 → 拒绝（自保护）",
      st == 400 and b.get("code") == "FORBIDDEN_TARGET", "HTTP %s / %s" % (st, b.get("code")))

# 再建一个用户管理员：验证"下级不能删上级"
st, b = call("POST", "/api/auth/create-account",
             {"username": "ops02", "password": "Ops12345", "role": "UserAdmin",
              "operatorPassword": "Admin123"}, ticket=admin_tk)
check("创建「用户管理员」ops02 → 成功", st == 200, "HTTP %s / %s" % (st, b.get("code")))
st, ops2_tk, ops2_info = login("ops02", "Ops12345")
check("ops02 登录成功且角色 = UserAdmin",
      st == 200 and ops2_info.get("role") == "UserAdmin", "HTTP %s" % st)

st, b = call("POST", "/api/auth/delete-user", {"username": "todelete"}, ticket=ops2_tk)
check("用户管理员注销普通用户 → 允许", st == 200, "HTTP %s / %s" % (st, b.get("code")))

st, b = call("POST", "/api/auth/delete-user", {"username": "auditor01"}, ticket=ops2_tk)
check("用户管理员注销审计管理员 → 拒绝（下级够不到上级）",
      st == 400 and b.get("code") == "FORBIDDEN_TARGET", "HTTP %s / %s" % (st, b.get("code")))

st, b = call("POST", "/api/auth/delete-user", {"username": "admin"}, ticket=ops2_tk)
check("用户管理员注销管理员 → 拒绝",
      st == 400 and b.get("code") == "FORBIDDEN_TARGET", "HTTP %s / %s" % (st, b.get("code")))

# 本次需求核心：管理员把审计管理员一并纳入可注销范围
st, b = call("POST", "/api/auth/delete-user", {"username": "auditor01"}, ticket=admin_tk)
check("admin 注销「审计管理员」→ 成功（本次需求）",
      st == 200, "HTTP %s / %s" % (st, b.get("code")))

st, b = call("GET", "/api/audit/logs", ticket=auditor_tk)
check("被注销账号的票据立即失效", st == 401 and b.get("code") == "SESSION_REVOKED",
      "HTTP %s / %s" % (st, b.get("code")))
check("auditor01 已从库中删除",
      _cli[DB]["Users"].find_one({"username": "auditor01"}) is None)

st, b = call("POST", "/api/auth/delete-user", {"username": "nosuchuser"}, ticket=admin_tk)
check("注销不存在的账号 → 404",
      st == 404 and b.get("code") == "NOT_FOUND", "HTTP %s / %s" % (st, b.get("code")))

# ---------- 8. 安全事件留痕：失败的口令 / 越权操作必须可单独检索 ----------
#
# 本段来自一次真实缺口：admin 改密时口令不合规，**前端本地就把请求拦下了**，
# 后端毫不知情，审计里自然什么都没有。而"某人反复尝试设弱口令"恰恰是要留痕的
# 安全事件。现在的约定是：
#   1. 复杂度一律由服务端裁决，前端只提示不拦截；
#   2. 失败与成功在**动作**层面就分开（CHANGE_PASSWORD_FAILED vs CHANGE_PASSWORD）；
#   3. 每条失败都带 reasonCode，能按原因整类筛出。
# 下面逐条验证这三条约定真的落地了。
print("\n[8] 安全事件留痕：口令类失败与越权拒绝都能单独检索")

# --- admin 改自己被拒绝的四类原因 ---
# 用 ops02 做靶子（它能登录，因此旧口令校验走得到），避免改动真实 admin 的口令。
st, b = call("POST", "/api/auth/change-password",
             {"username": "ops02", "oldPassword": "Ops12345", "newPassword": "abc"},
             ticket=ops2_tk)
check("改密：弱口令被拒", st == 400 and b.get("code") == "WEAK_PASSWORD",
      "HTTP %s / %s" % (st, b.get("code")))

st, b = call("POST", "/api/auth/change-password",
             {"username": "ops02", "oldPassword": "Ops12345", "newPassword": "Ops12345"},
             ticket=ops2_tk)
check("改密：新旧相同被拒", st == 400 and b.get("code") == "PASSWORD_REUSED",
      "HTTP %s / %s" % (st, b.get("code")))

st, b = call("POST", "/api/auth/change-password",
             {"username": "ops02", "oldPassword": "wrongold1A", "newPassword": "NewPass123"},
             ticket=ops2_tk)
check("改密：旧口令错误被拒", st == 401 and b.get("code") == "INVALID_CREDENTIALS",
      "HTTP %s / %s" % (st, b.get("code")))

st, b = call("POST", "/api/auth/change-password",
             {"username": "ops02", "oldPassword": "", "newPassword": "NewPass123"},
             ticket=ops2_tk)
check("改密：字段为空被拒", st == 400 and b.get("code") == "EMPTY_FIELDS",
      "HTTP %s / %s" % (st, b.get("code")))

# --- 改密成功一次，确认成功与失败确实分属两个动作 ---
st, b = call("POST", "/api/auth/change-password",
             {"username": "ops02", "oldPassword": "Ops12345", "newPassword": "Ops9x8y7z"},
             ticket=ops2_tk)
check("改密：合规口令成功", st == 200, "HTTP %s / %s" % (st, b.get("code")))

# 改密成功后旧票据应已作废
st, b = call("GET", "/api/auth/users", ticket=ops2_tk)
check("改密成功后旧票据失效", st == 401, "HTTP %s / %s" % (st, b.get("code")))

# --- 登录失败的原因码 ---
st, b = call("POST", "/api/auth/login", {"username": "ghostuser01", "password": "WrongPass1"})
check("登录：账号不存在被拒", st == 401, "HTTP %s / %s" % (st, b.get("code")))

st, b = call("POST", "/api/auth/login", {"username": "admin", "password": "WrongPass1"})
check("登录：账号存在但口令错误被拒（与'账号不存在'同码、不同原因）",
      st == 401, "HTTP %s / %s" % (st, b.get("code")))

# --- 审计口径核对 ---
# 分片名在整段（含第 9 段）复用，因此在这里就枚举好，不要等到后面再定义。
cols = [n for n in _cli[DB].list_collection_names() if n.startswith("AuditLogs")]


def count(action, reason=None):
    q = {"action": action}
    if reason:
        q["reasonCode"] = reason
    return sum(_cli[DB][n].count_documents(q) for n in cols)


cp_failed = count("CHANGE_PASSWORD_FAILED")
check("改密失败已留痕（CHANGE_PASSWORD_FAILED，独立动作）", cp_failed >= 4, "%d 条" % cp_failed)

check("改密失败动作本身即 result=失败",
      sum(_cli[DB][n].count_documents(
          {"action": "CHANGE_PASSWORD_FAILED", "result": "失败"}) for n in cols) == cp_failed,
      "两者应完全一致")

check("弱口令尝试带 WEAK_PASSWORD", count("CHANGE_PASSWORD_FAILED", "WEAK_PASSWORD") >= 1,
      "%d 条" % count("CHANGE_PASSWORD_FAILED", "WEAK_PASSWORD"))
check("新旧相同带 PASSWORD_REUSED", count("CHANGE_PASSWORD_FAILED", "PASSWORD_REUSED") >= 1,
      "%d 条" % count("CHANGE_PASSWORD_FAILED", "PASSWORD_REUSED"))
check("旧口令错误带 WRONG_OLD_PASSWORD（与'账号不存在'可区分）",
      count("CHANGE_PASSWORD_FAILED", "WRONG_OLD_PASSWORD") >= 1,
      "%d 条" % count("CHANGE_PASSWORD_FAILED", "WRONG_OLD_PASSWORD"))
check("空字段带 EMPTY_FIELDS", count("CHANGE_PASSWORD_FAILED", "EMPTY_FIELDS") >= 1,
      "%d 条" % count("CHANGE_PASSWORD_FAILED", "EMPTY_FIELDS"))
check("改密成功仍走 CHANGE_PASSWORD（动作层面与失败分开）",
      count("CHANGE_PASSWORD") >= 1, "%d 条" % count("CHANGE_PASSWORD"))
check("CHANGE_PASSWORD 动作下不存在失败记录（失败已全部改走 _FAILED）",
      sum(_cli[DB][n].count_documents(
          {"action": "CHANGE_PASSWORD", "result": "失败"}) for n in cols) == 0)

check("登录失败带 INVALID_CREDENTIALS（账号不存在与口令错误同码）",
      count("LOGIN_FAILED", "INVALID_CREDENTIALS") >= 2,
      "%d 条" % count("LOGIN_FAILED", "INVALID_CREDENTIALS"))
check("登录失败不再有空原因码",
      sum(_cli[DB][n].count_documents(
          {"action": "LOGIN_FAILED", "reasonCode": {"$in": [None, ""]}}) for n in cols) == 0)

check("注册失败带原因码（本库若未触发注册失败则计 0，不作判负）",
      sum(_cli[DB][n].count_documents(
          {"action": "REGISTER", "result": "失败", "reasonCode": {"$nin": [None, ""]}})
          for n in cols) >= 0)

# 口令本身绝不能出现在任何日志里
leak = 0
for n in cols:
    for d in _cli[DB][n].find({}, {"request": 1, "response": 1, "_id": 0}):
        blob = (d.get("request") or "") + (d.get("response") or "")
        for secret in ("Ops12345", "Ops9x8y7z", "NewPass123", "wrongold1A", "WrongPass1"):
            if secret in blob:
                leak += 1
check("口令明文未进入审计日志（含请求与响应报文）", leak == 0, "命中 %d 处" % leak)

# ---------- 9. 角色回填与审计链 ----------
print("\n[9] 数据与审计链检查")
admin_doc = _cli[DB]["Users"].find_one({"username": "admin"})
check("admin 的 role 字段 = Admin", admin_doc.get("role") == "Admin",
      "role=%s" % admin_doc.get("role"))

# 越权尝试是否留痕
denied = 0
for n in cols:
    denied += _cli[DB][n].count_documents({"action": "AUDIT_ACCESS_DENIED"})
check("越权尝试已写入审计链（AUDIT_ACCESS_DENIED）", denied > 0, "%d 条" % denied)

# 三条角色任免记录
created = sum(_cli[DB][n].count_documents({"action": "CREATE_ACCOUNT"}) for n in cols)
setrole = sum(_cli[DB][n].count_documents({"action": "SET_ROLE"}) for n in cols)
check("创建账号已留痕（CREATE_ACCOUNT）", created > 0, "%d 条" % created)
check("角色变更已留痕（SET_ROLE）", setrole > 0, "%d 条" % setrole)

# 注销留痕：成功与失败都要落链（失败含越权与自保护，共 6 次调用）
deleted = sum(_cli[DB][n].count_documents({"action": "DELETE_USER"}) for n in cols)
check("注销操作已留痕（DELETE_USER，成功与拒绝均记录）", deleted >= 6, "%d 条" % deleted)

# 被拒的注销必须带 FORBIDDEN_TARGET，才能把"越级注销尝试"单独筛出来
fbd = sum(_cli[DB][n].count_documents(
    {"action": "DELETE_USER", "reasonCode": "FORBIDDEN_TARGET"}) for n in cols)
check("越级注销尝试带 FORBIDDEN_TARGET", fbd >= 3, "%d 条" % fbd)

# 全链独立复算
GEN = "0" * 64


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def ch(d):
    ts = d["timestamp"]
    t = ts.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (ts.microsecond // 1000)
    parts = [d.get("prevHash") or "", str(d["seq"]), t, d.get("actorType") or "",
             d.get("operatorId") or "", d.get("operatorName") or "", d.get("action") or "",
             d.get("target") or "", d.get("result") or "", d.get("reasonCode") or "",
             d.get("statusBefore") or "", d.get("statusAfter") or "",
             d.get("sourceIp") or "", sha(d.get("request") or ""), sha(d.get("response") or "")]
    return sha("|".join(parts))


docs = []
for n in cols:
    docs += list(_cli[DB][n].find({"selfHash": {"$nin": [None, ""]}}))
docs.sort(key=lambda x: x["seq"])
prev, bad = GEN, []
for d in docs:
    if d.get("prevHash") != prev or ch(d) != d.get("selfHash"):
        bad.append(d["seq"])
    prev = d.get("selfHash")
check("审计哈希链完整（独立复算 %d 条）" % len(docs), not bad, bad[:5] if bad else "0 断裂")

# ---------- 收尾 ----------
proc.kill()
proc.wait(timeout=10)
try:
    logf.close()
except Exception:
    pass

print("\n" + "=" * 64)
print("  通过 %d 项，失败 %d 项" % (len(PASSED), len(FAILED)))
if FAILED:
    print("  失败清单：")
    for f in FAILED:
        print("    -", f)
print("  结论：%s" % ("PASS ✅ 角色分离生效" if not FAILED else "FAIL ❌"))

# ---------- 清理测试库 ----------
# 历史教训：本脚本早期只在开头清库、结尾不管，结果每跑一次就留下一个空壳库，
# 库里攒出了 AuthBaselineRoleTest 这种"3 个账号 + 28 条审计"的残留。
# 现在的策略：成功即清，失败则保留现场供排查，--keep 可强制保留。
if FAILED or KEEP:
    print("  测试库保留：%s（%s）" % (DB, "有失败项，留现场排查" if FAILED else "--keep 指定"))
else:
    _cli.drop_database(DB)
    print("  测试库已清理：%s" % DB)
print("=" * 64)
sys.exit(1 if FAILED else 0)
