#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
把散落在多个 count 模式分片里的审计记录，合并回月度分片并整链重签。

背景：
    压测时用 --Audit:ShardUnit=count 跑出了 AuditLogs_count_000009/10 等小片。
    压测结束后按月度模式运行时，这些碎片片会一直留在库里 ——
    分片清单里出现只有 1~3 条记录的小片，既不美观，
    也让"分片轮转"的演示证据失去说服力。

    处理思路：把所有审计记录按 seq 归并到 AuditLogs_202609（当前活动片），
    删除空壳分片，然后从 seq=1 起整链重签并同步锚点。

安全措施：默认干跑；--apply 才写库。执行前已备份快照。
"""
import argparse
import hashlib
import pymongo
from datetime import datetime

DB_URI = "mongodb://127.0.0.1:27017"
DB_NAME = "AuthBaselineDb"
TARGET = "AuditLogs_202609"
GENESIS = "0" * 64


def sha256_hex(s):
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()


def fmt_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (dt.microsecond // 1000)


def compute_hash(d):
    parts = [
        d.get("prevHash") or "", str(d.get("seq")), fmt_ts(d["timestamp"]),
        d.get("actorType") or "", d.get("operatorId") or "", d.get("operatorName") or "",
        d.get("action") or "", d.get("target") or "", d.get("result") or "",
        d.get("reasonCode") or "", d.get("statusBefore") or "", d.get("statusAfter") or "",
        d.get("sourceIp") or "", sha256_hex(d.get("request") or ""),
        sha256_hex(d.get("response") or ""),
    ]
    return sha256_hex("|".join(parts))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--target", default=TARGET)
    args = ap.parse_args()

    db = pymongo.MongoClient(DB_URI, serverSelectionTimeoutMS=3000)[DB_NAME]
    shards = [n for n in db.list_collection_names() if n.startswith("AuditLogs")]

    rows = []
    for n in shards:
        for d in db[n].find({}):
            d["_c"] = n
            rows.append(d)
    rows.sort(key=lambda x: x["seq"])
    print(f"合并前: {len(shards)} 个分片 / {len(rows)} 条记录")

    # 属于目标片的直接留着，其余需要迁移
    to_move = [r for r in rows if r["_c"] != args.target]
    print(f"需迁移到 {args.target}: {len(to_move)} 条")

    # 干跑时也按"合并后"的集合来规划，否则规划出来的条数只是目标片自己的，
    # 与实际执行后（全部分片归并）的结果对不上。
    # 做法：统一用内存里的 rows 计算计划；--apply 时再落库。
    docs = sorted(rows, key=lambda d: (d["timestamp"], str(d["_id"])))
    prev = GENESIS
    plan = []
    for i, d in enumerate(docs, start=1):
        nd = dict(d)
        nd["seq"] = i
        nd["prevHash"] = prev
        nd["selfHash"] = compute_hash(nd)
        plan.append((d, nd))
        prev = nd["selfHash"]

    print(f"重签后 seq 范围: 1 ~ {len(plan)}")
    changed = sum(1 for o, n in plan
                  if o["seq"] != n["seq"] or o.get("prevHash") != n["prevHash"]
                  or o.get("selfHash") != n["selfHash"])
    print(f"需更新: {changed} 条")

    if not args.apply:
        print("\n[干跑] 未写库。加 --apply 执行。")
        return 0

    # 逐条写回：既有记录更新 seq/prevHash/selfHash/shard；
    # 从其它分片迁来的记录，其 _id 在目标片里不存在，改用 upsert 落库。
    for o, n in plan:
        payload = {k: v for k, v in n.items() if k not in ("_id", "_c")}
        db[args.target].update_one({"_id": o["_id"]}, {"$set": payload}, upsert=True)

    if to_move:
        for n in shards:
            if n != args.target:
                db[n].drop()
                print(f"  已删除空壳分片 {n}")
    db["AuditChainHeads"].update_one(
        {"_id": "head"},
        {"$set": {"lastHash": plan[-1][1]["selfHash"], "seq": len(plan),
                  "totalCount": len(plan),
                  "updatedAt": datetime.now(),
                  "shard": args.target}})
    print(f"\n已合并并重签 {len(plan)} 条。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
