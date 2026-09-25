# -*- coding: utf-8 -*-
"""只读查询：篡改告警痕迹（字段名用 camelCase，与 .NET 驱动实际存储一致）。

注意：MongoDB 官方 .NET 驱动默认按 camelCase 序列化属性名，
所以代码里写的 Action/Seq/Result 在库里是 action/seq/result。
上一版按 PascalCase 查，全部命中 0 条 —— 属于查询写错，不是数据缺失。

只做 find / aggregate，不做任何写入。
"""
from pymongo import MongoClient

cli = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=8000)
db = cli["AuthBaselineDb"]
cols = [n for n in db.list_collection_names() if n.startswith("AuditLogs")]

head = db["AuditChainHeads"].find_one({"_id": "head"})
print("=== 链尾锚点 ===")
print("  seq        =", head.get("seq"))
print("  totalCount =", head.get("totalCount"))
print("  lastHash   =", head.get("lastHash"))
print("  shard      =", head.get("shard"))
print("  updatedAt  =", head.get("updatedAt"), "(UTC)")


def show(title, query, limit=40, sortdir=1):
    print()
    print("=" * 70)
    print(" " + title)
    print("=" * 70)
    rows, total = [], 0
    for n in cols:
        total += db[n].count_documents(query)
        rows += list(db[n].find(query))
    rows.sort(key=lambda x: x.get("seq") or 0, reverse=(sortdir < 0))
    print("命中 %d 条" % total)
    if not rows:
        print("  （无）")
        return
    for d in rows[:limit]:
        print("  --- seq %s | %s | %s" % (d.get("seq"), d.get("timestamp"), d.get("shard")))
        print("      操作者 :", d.get("operatorName"), "/", d.get("operatorId"))
        print("      动作   :", d.get("action"))
        print("      结果   :", d.get("result"), "| 原因码:", d.get("reasonCode"))
        print("      状态   :", d.get("statusBefore"), "→", d.get("statusAfter"))
        print("      目标   :", d.get("target"))
        print("      请求   :", str(d.get("request"))[:220])
        print("      响应   :", str(d.get("response"))[:320])


show("AUDIT_TAMPERED —— 检出篡改时写的告警", {"action": "AUDIT_TAMPERED"})
show("AUDIT_VERIFY —— 每次完整性校验写一条", {"action": "AUDIT_VERIFY"}, limit=30, sortdir=-1)
show("AUDIT_VERIFY 中结果=失败（当时链是断的）",
     {"action": "AUDIT_VERIFY", "result": "失败"}, limit=30, sortdir=-1)

print()
print("=" * 70)
print(" 各动作计数")
print("=" * 70)
allacts = set()
for n in cols:
    allacts |= set(db[n].distinct("action"))
for a in sorted(allacts):
    c = sum(db[n].count_documents({"action": a}) for n in cols)
    print("  %-24s %d 条" % (a, c))

print()
print("=" * 70)
print(" 最新 15 条（按 seq 倒序）")
print("=" * 70)
rows = []
for n in cols:
    rows += list(db[n].find())
rows.sort(key=lambda x: x.get("seq") or 0, reverse=True)
print("  库中最大 seq = %s（锚点 seq = %s）" % (rows[0].get("seq") if rows else None, head.get("seq")))
print("  库中最小 seq = %s" % (rows[-1].get("seq") if rows else None))
for d in rows[:15]:
    print("  seq=%-5s %-20s %-22s %-6s %s"
          % (d.get("seq"), str(d.get("timestamp"))[:19], d.get("action"),
             d.get("result"), d.get("operatorName")))
