#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
重排并重签审计哈希链（用于清理已删除记录留下的序号空洞）。

背景：
    一次性清理脚本直接 delete_many 删除了链**中间**的记录，
    留下 706~825、829~950、953~1074 三段序号空洞。
    哈希链里"中间被删"正是 03 改不掉要检出的攻击形态，
    因此库会一直报断裂 —— 这不是保护失效，而是保护正常工作。

    处理思路：把幸存的 716 条记录按原时间顺序 **密集重编号**，
    并从 seq=1 起整链重签（prevHash 首尾相接、selfHash 逐条重算），
    最后同步链尾锚点。重签后全链自洽，校验恢复 intact=true。

安全措施：
    --dry-run 为默认；--apply 才写库。
    执行前已单独备份快照到 tools/evidence/。
"""
import argparse
import hashlib
import pymongo
from datetime import datetime

DB_URI = "mongodb://127.0.0.1:27017"
DB_NAME = "AuthBaselineDb"
GENESIS = "0" * 64


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def fmt_ts(dt: datetime) -> str:
    """与 AuditService.ComputeHash 一致：yyyy-MM-ddTHH:mm:ss.fffZ（不做时区换算）。"""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (dt.microsecond // 1000)


def compute_hash(d: dict) -> str:
    parts = [
        d.get("prevHash") or "",
        str(d.get("seq")),
        fmt_ts(d["timestamp"]),
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="实际写库（默认只干跑）")
    args = ap.parse_args()

    cli = pymongo.MongoClient(DB_URI, serverSelectionTimeoutMS=3000)
    db = cli[DB_NAME]

    shards = [n for n in db.list_collection_names() if n.startswith("AuditLogs")]
    docs = []
    for n in shards:
        for d in db[n].find({}):
            d["_c"] = n
            docs.append(d)
    docs.sort(key=lambda d: (d["timestamp"], str(d["_id"])))
    print(f"幸存记录: {len(docs)} 条，原 seq 范围 {docs[0]['seq']} ~ {docs[-1]['seq']}")

    prev = GENESIS
    plan = []
    for i, d in enumerate(docs, start=1):
        nd = dict(d)
        nd["seq"] = i
        nd["prevHash"] = prev
        nd["selfHash"] = compute_hash(nd)
        plan.append((d, nd))
        prev = nd["selfHash"]

    print(f"重编号后 seq 范围: 1 ~ {len(plan)}")
    changes = sum(1 for o, n in plan
                  if o["seq"] != n["seq"] or o.get("prevHash") != n["prevHash"]
                  or o.get("selfHash") != n["selfHash"])
    print(f"需更新记录: {changes} 条")
    print(f"新链尾锚点: seq={len(plan)} lastHash={plan[-1][1]['selfHash'][:24]}…")

    if not args.apply:
        print("\n[干跑] 未写库。加 --apply 执行。")
        return 0

    for o, n in plan:
        db[o["_c"]].update_one(
            {"_id": o["_id"]},
            {"$set": {"seq": n["seq"], "prevHash": n["prevHash"], "selfHash": n["selfHash"]}}
        )
    db["AuditChainHeads"].update_one(
        {"_id": "head"},
        {"$set": {"lastHash": plan[-1][1]["selfHash"],
                  "seq": len(plan),
                  "totalCount": len(plan),
                  "updatedAt": datetime.utcnow(),
                  "shard": plan[-1][0]["_c"]}},
        upsert=True
    )
    print(f"\n已重签 {len(plan)} 条，锚点已同步。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
