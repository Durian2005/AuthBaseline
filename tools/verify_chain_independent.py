# -*- coding: utf-8 -*-
"""独立复算哈希链 —— 用 Python 从零重算，不依赖后端代码。

目的：确认「改库 → 告警 → 改回」之后，链的当前状态，以及篡改告警记录
是否真的固化在链上。

哈希输入（与 AuditService.ComputeHash 一致，字段顺序固定）：
  prevHash|seq|timestamp(yyyy-MM-ddTHH:mm:ss.fffZ)|actorType|operatorId|
  operatorName|action|target|result|reasonCode|statusBefore|statusAfter|
  sourceIp|sha256(request)|sha256(response)
整体再做一次 SHA256，小写十六进制。

只读，不做任何写入。
"""
import hashlib
from collections import OrderedDict
from datetime import timezone
from pymongo import MongoClient

GENESIS = "0" * 64


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def compute_hash(d: dict) -> str:
    ts = d.get("timestamp")
    if ts is not None:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        ts = ts.astimezone(timezone.utc)
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (ts.microsecond // 1000)
    else:
        ts_str = ""
    parts = [
        d.get("prevHash") or "",
        str(d.get("seq") if d.get("seq") is not None else ""),
        ts_str,
        d.get("actorType") or "",
        d.get("operatorId") or "",
        d.get("operatorName") or "",
        d.get("action") or "",
        d.get("target") or "",
        d.get("result") or "",
        d.get("reasonCode") or "",
        d.get("statusBefore") or "",
        d.get("statusAfter") or "",
        d.get("sourceIp") or "",
        sha256_hex(d.get("request") or ""),
        sha256_hex(d.get("response") or ""),
    ]
    return sha256_hex("|".join(parts))


cli = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=8000)
db = cli["AuthBaselineDb"]
cols = [n for n in db.list_collection_names() if n.startswith("AuditLogs")]

docs = []
for n in cols:
    docs += list(db[n].find({"selfHash": {"$nin": [None, ""]}}))
docs.sort(key=lambda x: x["seq"])

print("=== 参与链校验的记录 ===")
print("  总数        :", len(docs))
print("  seq 范围    : %s ~ %s" % (docs[0]["seq"], docs[-1]["seq"]))
print("  分片        :", sorted({d["shard"] for d in docs}))

head = db["AuditChainHeads"].find_one({"_id": "head"})
print("  锚点 seq    : %s (totalCount=%s)" % (head.get("seq"), head.get("totalCount")))

# ---- 逐条复算 ----
print()
print("=== 逐条复算结果 ===")
expected_prev = GENESIS
broken = []
for d in docs:
    ok_link = (d.get("prevHash") == expected_prev)
    ok_hash = (compute_hash(d) == d.get("selfHash"))
    if not ok_link or not ok_hash:
        broken.append((d["seq"], ok_link, ok_hash))
    expected_prev = d.get("selfHash")

if not broken:
    print("  ✅ 链完整：%d 条记录 prevHash 与 selfHash 全部复算一致" % len(docs))
else:
    print("  ❌ 发现 %d 处断裂：" % len(broken))
    for seq, l, h in broken[:10]:
        print("     seq=%s  链接正确=%s  哈希正确=%s" % (seq, l, h))

print()
print("  链首是否从 1 开始 :", docs[0]["seq"] == 1)
print("  链尾是否等于锚点   :", docs[-1]["seq"] == head.get("seq"))

# ---- 篡改告警的固化情况 ----
tampered = [d for d in docs if d.get("action") == "AUDIT_TAMPERED"]
print()
print("=" * 70)
print(" 篡改告警 (AUDIT_TAMPERED) 固化情况")
print("=" * 70)
print("  总数            :", len(tampered))
print("  全部在链上      :", all(compute_hash(d) == d.get("selfHash") for d in tampered))
print("  seq 范围        : %s ~ %s" % (tampered[0]["seq"], tampered[-1]["seq"]))

# 按断裂点分组，识别"篡改事件轮次"
groups = OrderedDict()
for d in tampered:
    key = d.get("target") or "?"
    groups.setdefault(key, []).append(d)

print()
print("  按断裂位置分组（同一位置多次告警 = 巡检每 30 秒都在写）：")
for k, v in sorted(groups.items(), key=lambda kv: kv[1][0]["seq"]):
    print("    %-14s 告警 %2d 次   首次 seq=%-5s %s   末次 seq=%-5s %s"
          % (k, len(v), v[0]["seq"], str(v[0]["timestamp"])[:19],
             v[-1]["seq"], str(v[-1]["timestamp"])[:19]))

# ---- 最后一轮"改了又改回"的时间线 ----
print()
print("=" * 70)
print(" 最后一轮完整时间线（改了 → 告警 → 改回 → 恢复）")
print("=" * 70)
last_tampered_seq = tampered[-1]["seq"]
window = [d for d in docs if last_tampered_seq - 12 <= d["seq"] <= last_tampered_seq + 12]
for d in window:
    mark = ""
    if d["action"] == "AUDIT_TAMPERED":
        mark = "  ← 篡改告警"
    elif d["action"] == "AUDIT_VERIFY":
        mark = "  ← 完整性校验 %s" % ("通过(链已恢复)" if d.get("result") == "成功" else "失败(链仍断)")
    print("  seq=%-5s %s  %-16s %-6s %s%s"
          % (d["seq"], str(d["timestamp"])[:19], d["action"], d.get("result"),
             d.get("operatorName"), mark))

# ---- 相邻 AUDIT_TAMPERED 的时间间隔 ----
print()
print("  相邻两次篡改告警的时间间隔（秒）—— 验证是否按 30 秒巡检节奏写入：")
gaps = []
for a, b in zip(tampered, tampered[1:]):
    if a.get("target") == b.get("target"):
        gaps.append((b["timestamp"] - a["timestamp"]).total_seconds())
if gaps:
    from collections import Counter
    c = Counter(round(g) for g in gaps)
    for gap, n in sorted(c.items()):
        print("    %4ds 出现 %d 次" % (gap, n))
    print("  平均间隔 = %.1f 秒" % (sum(gaps) / len(gaps)))
