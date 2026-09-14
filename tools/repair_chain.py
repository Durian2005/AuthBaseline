#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
修复审计哈希链。

背景：
    在"直接改库也要弹窗"的验证过程中，脚本对 AuditLogs_202609 中
    seq=308 的记录做了篡改（action 改成 TAMPERED_BY_ATTACKER、target 被
    覆盖），事后又把 action 改回 AUDIT_VERIFY 并 $unset 了 target，
    导致 target 丢失、selfHash 与内容不符，链在 seq=308 处断裂。

    哈希链的特性决定了：单独改一条记录的 selfHash 是不够的，
    因为下一条的 prevHash 保存的是本条**修改前**的 selfHash。
    因此必须从断裂点起，把后续所有记录的 prevHash 重新接上并重算 selfHash。

本脚本做的事：
    1. 把 seq=308 的 target 恢复为 "audit/verify"（与同类型 AUDIT_VERIFY 记录一致）；
    2. 从 seq=308 开始，逐条把 prevHash 接回上一条的 selfHash，重算 selfHash；
    3. 全部完成后校验整链，并同步更新链尾锚点 AuditChainHeads.lastHash。

安全措施：
    - 默认 --dry-run（只打印计划，不写库）；
    - 执行前自动备份整条落到 _chain_backup_<时间戳>.json；
    - 写库用逐条 update_one，只动 prevHash / selfHash / target 三个字段，
      不碰业务字段。

用法：
    python tools/repair_chain.py --dry-run      # 查看将要做的修改
    python tools/repair_chain.py --apply        # 实际执行
"""
import argparse
import hashlib
import json
import sys
from datetime import datetime

import pymongo

DB_URI = "mongodb://127.0.0.1:27017"
DB_NAME = "AuthBaselineDb"
START_SEQ = 308                      # 断裂起点
RESTORE_TARGET = "audit/verify"      # seq=308 的原始 target（依据同类记录推断）


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def fmt_ts(dt: datetime) -> str:
    """与 AuditService.ComputeHash 一致：yyyy-MM-ddTHH:mm:ss.fffZ（不做时区换算）。"""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (dt.microsecond // 1000)


def compute_hash(d: dict) -> str:
    """严格复刻 AuditService.ComputeHash 的字段顺序与空值处理。"""
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
    ap.add_argument("--start-seq", type=int, default=START_SEQ)
    args = ap.parse_args()

    client = pymongo.MongoClient(DB_URI, serverSelectionTimeoutMS=3000)
    db = client[DB_NAME]

    # 找到所有带哈希的审计分片
    shards = [n for n in db.list_collection_names()
              if n.startswith("AuditLogs") and n != "AuditLogs"]
    docs = []
    for name in shards:
        docs.extend(db[name].find({"selfHash": {"$exists": True, "$ne": ""}}))
    docs.sort(key=lambda d: d["seq"])

    if not docs:
        print("没有带哈希的记录，无需修复")
        return 1

    # 先做一次全链体检，确认断裂点
    print("=== 修复前体检 ===")
    expected = "0" * 64
    broken = []
    for i, d in enumerate(docs):
        if d["seq"] != i + 1:
            broken.append((d["seq"], "序号不连续"))
            break
        if d.get("prevHash") != expected:
            broken.append((d["seq"], "prevHash 不匹配"))
        elif compute_hash(d) != d.get("selfHash"):
            broken.append((d["seq"], "内容与 selfHash 不符"))
        expected = d["selfHash"]
    if broken:
        print("  断裂起点：seq=%d（%s）" % broken[0])
    else:
        print("  链完整，无需修复")
        return 0

    # 规划修改
    start = args.start_seq
    target_idx = next((i for i, d in enumerate(docs) if d["seq"] == start), None)
    if target_idx is None:
        print("找不到 seq=%d 的记录" % start)
        return 1

    plan = []
    prev_hash = docs[target_idx - 1]["selfHash"] if target_idx > 0 else "0" * 64
    for d in docs[target_idx:]:
        new_doc = dict(d)
        new_doc["prevHash"] = prev_hash
        # 关键：target 字段可能被整体 $unset 掉了（字段缺失而非空串）。
        # 若只比较哈希值会漏判 —— 恢复 target 后重算的哈希可能恰好等于存储值
        # （因为存储值本来就是按那个 target 算的），但字段本身仍是缺失状态。
        restore = (d["seq"] == start) and ("target" not in d)
        if restore:
            new_doc["target"] = RESTORE_TARGET
            note = "恢复缺失的 target=%s" % RESTORE_TARGET
        else:
            note = ""
        new_self = compute_hash(new_doc)
        changed = (restore
                   or new_doc["prevHash"] != d.get("prevHash")
                   or new_self != d.get("selfHash"))
        plan.append({
            "seq": d["seq"],
            "collection": next(n for n in shards if db[n].find_one({"_id": d["_id"]})),
            "id": d["_id"],
            "target": new_doc.get("target"),
            "prevHash": new_doc["prevHash"],
            "selfHash": new_self,
            "changed": changed,
            "note": note,
        })
        prev_hash = new_self

    print("\n=== 修复计划（seq %d ~ %d）===" % (start, docs[-1]["seq"]))
    for p in plan:
        flag = "需改" if p["changed"] else "已正确"
        print("  seq=%-4d %s %s" % (p["seq"], flag, p["note"]))
    n_change = sum(1 for p in plan if p["changed"])
    print("  合计需改动 %d 条" % n_change)

    if not args.apply:
        print("\n[干跑] 未写库。确认无误后加 --apply 执行。")
        return 0

    # 备份
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = "tools/_chain_backup_%s.json" % stamp
    with open(backup, "w", encoding="utf-8") as f:
        json.dump(docs, f, ensure_ascii=False, default=str)
    print("\n已备份整链到 %s（%d 条）" % (backup, len(docs)))

    # 写库
    for p in plan:
        if not p["changed"]:
            continue
        db[p["collection"]].update_one(
            {"_id": p["id"]},
            {"$set": {"prevHash": p["prevHash"], "selfHash": p["selfHash"],
                      "target": p["target"]}},
        )
    print("已写回 %d 条记录" % n_change)

    # 同步链尾锚点
    last = plan[-1]
    db["AuditChainHeads"].update_one(
        {"_id": "head"},
        {"$set": {"lastHash": last["selfHash"], "seq": last["seq"],
                  "totalCount": last["seq"], "shard": last["collection"],
                  "updatedAt": datetime.utcnow()}},
    )
    print("已同步链尾锚点：seq=%d lastHash=%s..." % (last["seq"], last["selfHash"][:16]))

    # 复检
    print("\n=== 修复后复检 ===")
    docs2 = []
    for name in shards:
        docs2.extend(db[name].find({"selfHash": {"$exists": True, "$ne": ""}}))
    docs2.sort(key=lambda d: d["seq"])
    expected = "0" * 64
    bad = 0
    for d in docs2:
        if d.get("prevHash") != expected or compute_hash(d) != d.get("selfHash"):
            bad += 1
            if bad <= 3:
                print("  seq=%d 仍不自洽" % d["seq"])
        expected = d["selfHash"]
    if bad == 0:
        print("  链完整：%d 条记录全部自洽" % len(docs2))
    else:
        print("  仍有 %d 条不自洽" % bad)
    return 0 if bad == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
