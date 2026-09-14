# -*- coding: utf-8 -*-
"""只读勘察：列出 AuthBaselineDb 的全部集合、文档数、以及用户/链头等关键内容。
不修改任何数据，仅供清理前确认范围。
"""
import json
import sys

from pymongo import MongoClient

URI = "mongodb://localhost:27017"
DBNAME = "AuthBaselineDb"


def main():
    cli = MongoClient(URI, serverSelectionTimeoutMS=5000)
    try:
        cli.admin.command("ping")
    except Exception as exc:  # noqa: BLE001
        print("无法连接 MongoDB:", exc)
        return 1

    print("== 该实例下的数据库 ==")
    for name in cli.list_database_names():
        print("  -", name)

    db = cli[DBNAME]
    colls = sorted(db.list_collection_names())
    print("\n== %s 集合清单 ==" % DBNAME)
    if not colls:
        print("  (空)")
    for name in colls:
        print("  %-24s %6d 条" % (name, db[name].estimated_document_count()))

    # 用户表：看全部字段（口令哈希只显示前缀，便于判断是否保留）
    if "Users" in colls:
        print("\n== Users 全部账号 ==")
        for d in db["Users"].find({}):
            brief = {}
            for k, v in d.items():
                if k == "_id":
                    brief[k] = str(v)
                elif isinstance(v, str) and len(v) > 24:
                    brief[k] = v[:18] + "…(%d)" % len(v)
                else:
                    brief[k] = v
            print("  " + json.dumps(brief, ensure_ascii=False, default=str))

    # 链头锚点：清日志时必须同步处理，否则新日志的 prevHash 会指向不存在的记录
    if "AuditChainHeads" in colls:
        print("\n== AuditChainHeads（链尾锚点） ==")
        for d in db["AuditChainHeads"].find({}):
            brief = {k: (v[:18] + "…" if isinstance(v, str) and len(v) > 24 else v)
                     for k, v in d.items()}
            print("  " + json.dumps(brief, ensure_ascii=False, default=str))

    # 审计分片：额外报告 seq 区间，确认清理后会回到怎样的状态
    print("\n== 审计日志分片 ==")
    for name in colls:
        if not name.startswith("AuditLogs"):
            continue
        c = db[name]
        n = c.estimated_document_count()
        if n == 0:
            print("  %-24s 0 条" % name)
            continue
        lo = c.find_one(sort=[("seq", 1)])
        hi = c.find_one(sort=[("seq", -1)])
        print("  %-24s %6d 条  seq %s ~ %s" % (name, n, lo.get("seq"), hi.get("seq")))

    return 0


if __name__ == "__main__":
    sys.exit(main())
