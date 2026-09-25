# -*- coding: utf-8 -*-
"""真机验证：admin 改密失败（弱口令）到底有没有进审计日志。

背景：用户提出的原型问题是"admin 修改密码不符合要求导致失败，这有没有
记录到日志里"。修复前有两处缺口：
  1. 前端用 isPasswordStrong 做提交门禁，弱口令请求**根本没发出去**，
     后端毫不知情，审计里什么都没有；
  2. 后端即便落痕也不带 reasonCode，无法把"反复弱口令尝试"单独筛出来。

本脚本对着**真实库**(AuthBaselineDb) 打真实的 HTTP 请求，然后直接查库，
用"日志里到底有没有这条"来回答，而不是看代码推断。它会产生真实审计记录
（这正是要验证的东西），因此不改动任何账号口令 —— 全部走失败分支。

用法：
  python tools/password_event_probe.py <exe路径> <端口>
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from pymongo import MongoClient

EXE = sys.argv[1]
PORT = int(sys.argv[2])
BASE = "http://127.0.0.1:%d" % PORT
DB_NAME = "AuthBaselineDb"          # 刻意用真实库，不打测试库
PROBE_USER = "admin"                # 用 admin，对应用户问题里的"admin 管理员"

cli = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=8000)
db = cli[DB_NAME]


def call(method, path, body=None, ticket=None):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Content-Type", "application/json")
    if ticket:
        req.add_header("Authorization", "Bearer " + ticket)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data, timeout=60) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8", "replace") or "{}")
    except Exception as e:
        return 0, {"err": str(e)}


def shards():
    return [n for n in db.list_collection_names() if n.startswith("AuditLogs")]


def count(action=None, reason=None, seq_gt=None, target=None):
    q = {}
    if action:
        q["action"] = action
    if reason:
        q["reasonCode"] = reason
    if target:
        q["target"] = target
    if seq_gt is not None:
        q["seq"] = {"$gt": seq_gt}
    return sum(db[n].count_documents(q) for n in shards())


def max_seq():
    best = 0
    for n in shards():
        d = db[n].find_one(sort=[("seq", -1)])
        if d and d.get("seq", 0) > best:
            best = d["seq"]
    return best


print("exe    :", EXE)
print("端口   :", PORT)
print("真实库 :", DB_NAME, "（本次不做任何清理，记录就是验证产物）")

# ---------- 启动 ----------
print("\n[1] 启动后端（真实库）...")
LOG = os.path.join(tempfile.gettempdir(), "pw_probe_%d.log" % PORT)
logf = open(LOG, "wb")
env = {**os.environ, "ASPNETCORE_URLS": "http://127.0.0.1:%d" % PORT}
proc = subprocess.Popen([EXE], env=env, stdout=logf, stderr=subprocess.STDOUT)

ready = False
for _ in range(60):
    st, _ = call("GET", "/")
    if st != 0:
        ready = True
        break
    time.sleep(0.5)
if not ready:
    print("  !! 未就绪")
    proc.kill()
    sys.exit(1)
print("  就绪 (PID=%d)" % proc.pid)

mark = max_seq()
print("  起始链尾 seq = %d" % mark)

# ---------- 登录 admin ----------
st, b = call("POST", "/api/auth/login", {"username": PROBE_USER, "password": "Admin123"})
tk = (b.get("data") or {}).get("ticket")
print("\n[2] admin 登录 -> HTTP %s，票据 %s" % (st, "已获得" if tk else "未获得"))
if not tk:
    print("  !! 无法登录真实库的 admin，中止（不影响已改动代码）")
    proc.kill()
    sys.exit(2)

# ---------- 场景一：弱口令改密 ----------
print("\n[3] 场景一：改密时新口令不符合复杂度要求（abc）")
st, b = call("POST", "/api/auth/change-password",
             {"username": PROBE_USER, "oldPassword": "Admin123", "newPassword": "abc"},
             ticket=tk)
print("   响应：HTTP %s / %s / %s" % (st, b.get("code"), b.get("message")))

# ---------- 场景二：旧口令错误 ----------
print("\n[4] 场景二：旧口令错误（不改动任何口令）")
st, b = call("POST", "/api/auth/change-password",
             {"username": PROBE_USER, "oldPassword": "totallyWrong1", "newPassword": "NewPass123"},
             ticket=tk)
print("   响应：HTTP %s / %s / %s" % (st, b.get("code"), b.get("message")))

# ---------- 场景三：新旧口令相同 ----------
print("\n[5] 场景三：新旧口令相同")
st, b = call("POST", "/api/auth/change-password",
             {"username": PROBE_USER, "oldPassword": "Admin123", "newPassword": "Admin123"},
             ticket=tk)
print("   响应：HTTP %s / %s / %s" % (st, b.get("code"), b.get("message")))

# ---------- 场景四：登录口令错误 ----------
print("\n[6] 场景四：登录时口令错误")
st, b = call("POST", "/api/auth/login", {"username": PROBE_USER, "password": "WrongPass1"})
print("   响应：HTTP %s / %s / %s" % (st, b.get("code"), b.get("message")))

# ---------- 查库核对 ----------
print("\n[7] 查真实库：本次新增的审计记录")
new_logs = []
for n in shards():
    new_logs += list(db[n].find({"seq": {"$gt": mark}}))
new_logs.sort(key=lambda d: d["seq"])

print("   共新增 %d 条：" % len(new_logs))
for d in new_logs:
    print("     seq=%-5s %-26s result=%-4s reason=%-22s target=%s"
          % (d["seq"], d["action"], d.get("result"), d.get("reasonCode") or "-", d.get("target")))

print("\n[8] 结论核对")
CHECKS = [
    ("弱口令改密已入日志（CHANGE_PASSWORD_FAILED + WEAK_PASSWORD）",
     count("CHANGE_PASSWORD_FAILED", "WEAK_PASSWORD", seq_gt=mark) >= 1),
    ("旧口令错误已入日志（+ WRONG_OLD_PASSWORD）",
     count("CHANGE_PASSWORD_FAILED", "WRONG_OLD_PASSWORD", seq_gt=mark) >= 1),
    ("新旧相同已入日志（+ PASSWORD_REUSED）",
     count("CHANGE_PASSWORD_FAILED", "PASSWORD_REUSED", seq_gt=mark) >= 1),
    ("登录失败已入日志（LOGIN_FAILED + INVALID_CREDENTIALS）",
     count("LOGIN_FAILED", "INVALID_CREDENTIALS", seq_gt=mark) >= 1),
    ("上述失败全部挂在 admin 名下（可定位到具体操作者）",
     count("CHANGE_PASSWORD_FAILED", target=PROBE_USER, seq_gt=mark) >= 3),
    ("成功动作 CHANGE_PASSWORD 下无失败记录（失败已分流）",
     sum(db[n].count_documents({"action": "CHANGE_PASSWORD", "result": "失败"}) for n in shards()) == 0),
]
bad = 0
for name, ok in CHECKS:
    print("   [%s] %s" % ("OK  " if ok else "FAIL", name))
    if not ok:
        bad += 1

# 口令明文绝不入库
leak = 0
for d in new_logs:
    blob = (d.get("request") or "") + (d.get("response") or "")
    for s in ("Admin123", "totallyWrong1", "NewPass123", "WrongPass1", '"abc"'):
        if s in blob:
            leak += 1
print("   [%s] 本次新增记录中无口令明文（命中 %d 处）" % ("OK  " if leak == 0 else "FAIL", leak))
if leak:
    bad += 1

# 后端进程里的 admin 口令未被改动：仍能用原口令登录
st2, b2 = call("POST", "/api/auth/login", {"username": PROBE_USER, "password": "Admin123"})
ok2 = st2 == 200
print("   [%s] admin 原口令仍然有效（本次只触发失败分支，未真正改密）" % ("OK  " if ok2 else "FAIL"))
if not ok2:
    bad += 1

proc.kill()
proc.wait(timeout=10)
try:
    logf.close()
except Exception:
    pass

print("\n" + "=" * 64)
print("  结论：%s" % ("PASS ✅ 改密/登录失败均已写入真实审计库" if bad == 0 else "FAIL ❌ 有 %d 项未达标" % bad))
print("=" * 64)
sys.exit(1 if bad else 0)
