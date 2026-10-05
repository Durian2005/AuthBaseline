# -*- coding: utf-8 -*-
"""从 db_cleanup.py 生成的备份目录恢复数据。

⚠️ 这是**作用于真实库**的恢复脚本：它对每个集合先 `delete_many({})` 再插入，
   属于破坏性写入。2026-10-05 的事故后加了两道确认。

用法：
    python tools/db_restore.py tools/backup/db_20260914_231500 --i-know-this-is-the-real-db
"""
import json
import os
import sys

from pymongo import MongoClient

URI = "mongodb://localhost:27017"
DBNAME = "AuthBaselineDb"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    confirm = "--i-know-this-is-the-real-db" in sys.argv

    if len(args) < 1:
        print("用法: python tools/db_restore.py <备份目录> [--i-know-this-is-the-real-db]")
        return 2
    src = args[0]
    if not os.path.isdir(src):
        print("备份目录不存在:", src)
        return 2

    if not confirm:
        print("✗ 本脚本会把备份内容写回**真实库 %r**（先清空同名集合）。" % DBNAME)
        print("  确认请追加：--i-know-this-is-the-real-db")
        return 2

    cli = MongoClient(URI, serverSelectionTimeoutMS=5000)
    cli.admin.command("ping")
    db = cli[DBNAME]

    files = [f for f in sorted(os.listdir(src)) if f.endswith(".json") and not f.startswith("_")]
    print("将恢复 %d 个集合（先清空同名集合）：" % len(files))
    print("目标库：%s" % DBNAME)
    for f in files:
        name = f[:-5]
        docs = json.load(open(os.path.join(src, f), encoding="utf-8"))
        db[name].delete_many({})
        if docs:
            db[name].insert_many(docs)
        print("  %-22s %6d 条" % (name, len(docs)))

    print("\n恢复完成。当前状态：")
    for n in sorted(db.list_collection_names()):
        print("  %-22s %6d 条" % (n, db[n].count_documents({})))
    print("\n注意：JSON 中的时间字段已被序列化为字符串，不完全等同于原始 BSON 日期，")
    print("      仅用于误删后的内容找回，不要用于续写哈希链。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
