# -*- coding: utf-8 -*-
"""竞态复现/回归测试：并发「写审计日志」与「完整性校验」风暴。

用法：
  python tools/race_storm_test.py <exe路径> <端口> <数据库名> [持续秒数]

流程：
  1. 用独立数据库名启动指定 exe（新库会自动播种 admin/Admin123）
  2. 登录拿票据
  3. 双线程风暴：
     - 线程 W：连续调 /api/audit/logs（每次写一条 AUDIT_QUERY 审计记录）
     - 线程 V：连续调 /api/audit/verify（每次全链校验并写 AUDIT_VERIFY）
  4. 统计测试期间产生的：
     - AUDIT_TAMPERED 总数（其中"链尾缺失"= 竞态误报的直接证据）
     - AUDIT_VERIFY 失败数
  5. （可选 --tamper）真实篡改回归：改库一条记录 → 校验必须报"内容与签名不符"
     → 原样恢复 → 校验必须恢复 intact。确保修复没有把真告警也干掉。

判定：
  旧代码：预期出现若干"链尾缺失"误报
  新代码：必须 0 条"链尾缺失"，且真实篡改仍能检出
"""
import json
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

import os
import tempfile
from pymongo import MongoClient

EXE = sys.argv[1]
PORT = int(sys.argv[2])
DB = sys.argv[3]
DURATION = int(sys.argv[4]) if len(sys.argv) > 4 else 30
DO_TAMPER = "--tamper" in sys.argv
BASE = "http://127.0.0.1:%d" % PORT

print("exe      :", EXE)
print("端口     :", PORT)
print("测试库   :", DB)
print("持续     :", DURATION, "秒")
print("篡改回归 :", "是" if DO_TAMPER else "否")


def call(method, path, body=None, ticket=None, timeout=90):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Content-Type", "application/json")
    if ticket:
        req.add_header("Authorization", "Bearer " + ticket)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace") or "{}")
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"err": str(e)}


# ---------- 1. 启动 ----------
print("\n[1] 启动被测进程 ...")
env = {
    "ASPNETCORE_URLS": "http://127.0.0.1:%d" % PORT,
    "MongoDbSettings__DatabaseName": DB,
}
import os
full_env = {**os.environ, **env}
# 注意：stdout 必须重定向到文件，不能用 PIPE。
# 后端每处理一个请求都会往 stdout 打一行日志，风暴期间数百条请求会把
# 64KB 管道缓冲区撑满 —— 子进程阻塞在写 stdout，后续请求全部超时。
# （曾踩过：表现为篡改回归段 HTTP 0 "timed out"，实为管道堵死。）
LOG_PATH = os.path.join(tempfile.gettempdir(), "race_storm_%d.log" % PORT)
logf = open(LOG_PATH, "wb")
proc = subprocess.Popen([EXE], env=full_env, stdout=logf, stderr=subprocess.STDOUT)

t0 = datetime.now(timezone.utc)

# 等服务就绪
# 注意：独立运行（非桌面端托管）时没有 wwwroot，GET / 返回 404 ——
# 只要有任何 HTTP 响应（含 404）就说明服务已监听；0 才是连不上。
ready = False
for i in range(60):
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

# ---------- 2. 登录 ----------
st, body = call("POST", "/api/auth/login", {"username": "admin", "password": "Admin123"})
if st != 200 or not body.get("data", {}).get("ticket"):
    print("  !! 登录失败:", json.dumps(body, ensure_ascii=False)[:200])
    proc.kill()
    sys.exit(1)
ticket = body["data"]["ticket"]
print("  登录 OK，票据已取")

# 基线：校验一次，确认起始 intact
st, b = call("GET", "/api/audit/verify", ticket=ticket)
print("  起始校验: intact=%s checked=%s" % (b.get("data", {}).get("intact"), b.get("data", {}).get("checked")))

# ---------- 3. 风暴 ----------
print("\n[2] 风暴 %d 秒：写线程(/api/audit/logs) × 校验线程(/api/audit/verify) ..." % DURATION)
stop_at = time.time() + DURATION
stats = {"W": [0, 0], "V": [0, 0]}  # [成功, 失败]


def writer():
    while time.time() < stop_at:
        st, _ = call("GET", "/api/audit/logs?page=1&pageSize=1", ticket=ticket)
        stats["W"][0 if st == 200 else 1] += 1
        time.sleep(0.05)  # ~20 次/秒，每次都会写一条 AUDIT_QUERY


def verifier():
    while time.time() < stop_at:
        st, _ = call("GET", "/api/audit/verify", ticket=ticket)
        stats["V"][0 if st == 200 else 1] += 1
        # 校验本身较慢（全链读+哈希），不额外 sleep，背靠背打满


tw = threading.Thread(target=writer)
tv = threading.Thread(target=verifier)
tw.start(); tv.start(); tw.join(); tv.join()
print("  写线程  : %d 成功 / %d 失败" % tuple(stats["W"]))
print("  校验线程: %d 成功 / %d 失败" % tuple(stats["V"]))

# ---------- 4. 统计误报 ----------
print("\n[3] 统计测试库中的告警 ...")
cli = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=8000)
db = cli[DB]
cols = [n for n in db.list_collection_names() if n.startswith("AuditLogs")]
t1 = datetime.now(timezone.utc)

tampered, tail_missing, other_break = [], 0, 0
verify_fail = 0
total_records = 0
for n in cols:
    total_records += db[n].count_documents({})
    for d in db[n].find({"action": "AUDIT_TAMPERED", "timestamp": {"$gte": t0}}):
        tampered.append(d)
        # 注意：response 是 JSON 字符串且中文被转义（\u94FE\u5C3E…），
        # 必须先 json.loads 再匹配原文，直接 find 子串永远不中。
        try:
            resp = json.loads(d.get("response") or "{}").get("BrokenReason", "")
        except Exception:
            resp = d.get("response") or ""
        if "链尾缺失" in resp:
            tail_missing += 1
        else:
            other_break += 1
    verify_fail += db[n].count_documents(
        {"action": "AUDIT_VERIFY", "result": "失败", "timestamp": {"$gte": t0}})

print("  测试期间写入记录总数 : %d" % total_records)
print("  AUDIT_TAMPERED       : %d 条" % len(tampered))
print("    ├─ 链尾缺失(误报)  : %d 条   ← 修复后必须为 0" % tail_missing)
print("    └─ 其他断裂        : %d 条" % other_break)
print("  AUDIT_VERIFY 失败    : %d 条" % verify_fail)
if tampered:
    for d in tampered[:5]:
        print("    样例 seq=%s target=%s" % (d.get("seq"), d.get("target")))

# ---------- 5. 真实篡改回归 ----------
if DO_TAMPER:
    print("\n[4] 真实篡改回归（确保修复没有干掉真告警）...")
    col = db[cols[0]] if cols else None
    if col is None:
        print("  !! 无审计集合，跳过")
    else:
        victim = col.find_one({"seq": {"$gt": 5, "$lt": 50}, "selfHash": {"$nin": [None, ""]}})
        if victim is None:
            print("  !! 找不到合适的被改对象，跳过")
        else:
            vseq = victim["seq"]
            orig = victim.get("operatorName")
            # 5.1 改内容（模拟攻击者直接改库）
            col.update_one({"_id": victim["_id"]}, {"$set": {"operatorName": "HACKED"}})
            st, b = call("GET", "/api/audit/verify", ticket=ticket)
            intact = b.get("data") or {}
            if "intact" not in intact:
                print("  !! verify 响应异常: HTTP %s  %s" % (st, json.dumps(b, ensure_ascii=False)[:300]))
            intact = intact.get("intact")
            reason = (b.get("data") or {}).get("brokenReason") or ""
            detected = (intact is False) and ("签名不符" in reason)
            print("  改库 seq=%s 后校验: intact=%s  检出内容篡改=%s" % (vseq, intact, "✅" if detected else "❌"))
            print("    原因:", reason[:80])
            # 5.2 原样恢复
            col.update_one({"_id": victim["_id"]}, {"$set": {"operatorName": orig}})
            st, b = call("GET", "/api/audit/verify", ticket=ticket)
            intact2 = (b.get("data") or {}).get("intact")
            if intact2 is None:
                print("  !! 恢复后 verify 响应异常: HTTP %s  %s" % (st, json.dumps(b, ensure_ascii=False)[:300]))
            print("  恢复后校验      : intact=%s  %s" % (intact2, "✅ 链恢复完整" if intact2 else "❌ 仍报断裂"))

# ---------- 6. 收尾 ----------
print("\n[5] 停止被测进程 ...")
proc.kill()
proc.wait(timeout=10)
try:
    logf.close()
except Exception:
    pass
print("  已停止 (PID=%d)   日志: %s" % (proc.pid, LOG_PATH))

print("\n" + "=" * 60)
verdict = "PASS ✅" if tail_missing == 0 else "FAIL ❌（仍出现链尾缺失误报）"
print(" 结论：%s   链尾缺失误报 = %d" % (verdict, tail_missing))
print("=" * 60)
