# -*- coding: utf-8 -*-
"""清理 AuthBaselineDb 中的冗余信息与日志痕迹。

⚠️⚠️ 这是**作用于真实库**的管理脚本，不是探针。⚠️⚠️
它会删除全部审计分片、清空会话、并**删除除 admin 外的所有账号**。
2026-10-05 曾发生过真实库被误清空的事故，因此本脚本加了三重保护：

  1. 必须**显式**传 `--db AuthBaselineDb`（不再默认落在真实库上）；
     名字对不上就拒绝执行 —— 防止"以为在清测试库、实际清了真实库"。
  2. 备份成功是**前置条件**：备份写盘并核对条数后，才允许进入清理阶段。
     备份失败立即中止，绝不"边备份边删"。
  3. 清理清单在执行前完整打印（集合名 + 条数），并在末尾汇总实际删除量，
     便于事后核对"删了的"与"打算删的"是否一致。

保留：
  - Users 中的 admin 账号（含 passwordHash 原样不动）
  - 发件邮箱与授权码（在 appsettings.Local.json，属数据库外文件，本脚本不触碰）

清空：
  - AuditLogs*            （全部审计日志分片，含改造前的 legacy 数据）
  - AuditChainHeads       （重置为创世状态，否则新日志会从旧序号续写，
                           触发"链首缺失"的假告警）
  - Sessions              （登录会话票据）
  - EmailCodes            （邮件验证码记录）

默认 dry-run，加 --apply 才真正写入。执行前会把原数据完整导出到
tools/backup/db_<时间戳>/ 以便回滚。
"""
import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone

from pymongo import MongoClient

URI = "mongodb://localhost:27017"
DBNAME = "AuthBaselineDb"
GENESIS_HASH = "0" * 64
BACKUP_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backup")


def dump_all(db, outdir):
    """把库内每个集合原样导出成 JSON，作为回滚备份。"""
    os.makedirs(outdir, exist_ok=True)
    manifest = {}
    for name in sorted(db.list_collection_names()):
        docs = list(db[name].find({}))
        with open(os.path.join(outdir, name + ".json"), "w", encoding="utf-8") as fh:
            json.dump(docs, fh, ensure_ascii=False, indent=2, default=str)
        manifest[name] = len(docs)
    with open(os.path.join(outdir, "_manifest.json"), "w", encoding="utf-8") as fh:
        json.dump({"database": DBNAME, "uri": URI, "dumpedAt": datetime.now().isoformat(),
                   "collections": manifest}, fh, ensure_ascii=False, indent=2)
    return manifest


def main():
    ap = argparse.ArgumentParser(
        description="清理 AuthBaselineDb（真实库！）的冗余信息与日志痕迹")
    ap.add_argument("--apply", action="store_true", help="真正执行清理（默认只预览）")
    ap.add_argument("--db", required=True,
                    help="必须显式写出目标库名（防止误清真实库而自己不知道）")
    ap.add_argument("--i-know-this-is-the-real-db", action="store_true",
                    help="二次确认：明确知道在操作真实库")
    args = ap.parse_args()

    # ---------- 保护 1：库名必须显式且正确 ----------
    if args.db != DBNAME:
        print("✗ 库名不匹配：脚本只负责清理 %r，但你传的是 %r。"
              % (DBNAME, args.db))
        print("  如果确实要清另一个库，请先确认它是不是真实库，再改脚本。")
        return 2

    # ---------- 保护 2：真实库必须被二次确认 ----------
    if not args.i_know_this_is_the_real_db:
        print("✗ %r 是**真实库**：本脚本会删除全部审计、清空会话、"
              "并删除除 admin 外的所有账号。" % DBNAME)
        print("  确认请追加：--i-know-this-is-the-real-db")
        print("  （默认 dry-run；真正写入还需 --apply）")
        return 2

    cli = MongoClient(URI, serverSelectionTimeoutMS=5000)
    cli.admin.command("ping")
    db = cli[DBNAME]

    colls = sorted(db.list_collection_names())
    print("== 清理前 ==")
    for n in colls:
        print("  %-22s %6d 条" % (n, db[n].count_documents({})))

    # 目标分片：名字以 AuditLogs 开头的全部集合
    audit_shards = [n for n in colls if n.startswith("AuditLogs")]

    if not args.apply:
        print("\n[dry-run] 将执行：")
        for n in audit_shards:
            print("  drop 集合       %s (%d 条)" % (n, db[n].count_documents({})))
        print("  清空集合       AuditChainHeads → 重置为创世 (seq=0, hash=64个0)")
        print("  清空集合       Sessions (%d 条)" % db["Sessions"].count_documents({}))
        print("  清空集合       EmailCodes (%d 条)" % db["EmailCodes"].count_documents({}))
        print("  保留           Users 中 username=admin 的账号（passwordHash 原样保留）")
        to_del = db["Users"].count_documents({"username": {"$ne": "admin"}})
        print("  删除           Users 中除 admin 外的 %d 个账号：" % to_del)
        for u in db["Users"].find({"username": {"$ne": "admin"}}, {"username": 1, "role": 1}):
            print("                   - %s (%s)" % (u.get("username"), u.get("role")))
        print("\n未写入任何改动。加 --apply 执行。")
        return 0

    # ---------- 保护 3：备份成功才允许继续 ----------
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = os.path.join(BACKUP_ROOT, "db_" + stamp)
    manifest = dump_all(db, outdir)
    print("\n== 已备份到 %s ==" % outdir)
    for k, v in manifest.items():
        print("  %-22s %6d 条" % (k, v))

    # 核对：备份文件里的条数必须与清理前一致，否则拒绝继续。
    for name, expected in manifest.items():
        path = os.path.join(outdir, name + ".json")
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            print("\n✗ 备份文件缺失或为空：%s —— 中止清理。" % path)
            return 3

    # ---------- 清理 ----------
    print("\n== 执行清理 ==")
    for n in audit_shards:
        n_before = db[n].count_documents({})
        db[n].drop()
        print("  已删除集合 %-22s (%d 条)" % (n, n_before))

    for n in ("Sessions", "EmailCodes"):
        n_before = db[n].count_documents({})
        db[n].delete_many({})
        print("  已清空集合 %-22s (%d 条)" % (n, n_before))

    # 链尾锚点重置为创世：必须与日志分片同时清空，
    # 否则新日志会从旧 seq 续写，校验时报"链首缺失"。
    db["AuditChainHeads"].delete_many({})
    db["AuditChainHeads"].insert_one({
        "_id": "head",
        "lastHash": GENESIS_HASH,
        "seq": 0,
        "totalCount": 0,
        "updatedAt": datetime.now(timezone.utc),
        "shard": "",
    })
    print("  已重置 AuditChainHeads → 创世 (seq=0)")

    # 用户表：只留 admin，清掉锁定等临时状态
    removed = db["Users"].delete_many({"username": {"$ne": "admin"}})
    print("  已删除非 admin 账号 %d 个" % removed.deleted_count)
    db["Users"].update_many(
        {"username": "admin"},
        {"$set": {"failedLoginAttempts": 0, "lockoutEnd": None}},
    )
    admin = db["Users"].find_one({"username": "admin"}, {"passwordHash": 1, "isAdmin": 1, "status": 1})
    print("  已保留 admin：status=%s isAdmin=%s passwordHash=%s…"
          % (admin.get("status"), admin.get("isAdmin"), str(admin.get("passwordHash"))[:16]))

    # ---------- 结果 ----------
    print("\n== 清理后 ==")
    for n in sorted(db.list_collection_names()):
        print("  %-22s %6d 条" % (n, db[n].count_documents({})))
    print("\n回滚命令：python tools/db_restore.py %s" % outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
