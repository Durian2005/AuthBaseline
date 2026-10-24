# -*- coding: utf-8 -*-
"""清理 FaceId（纯人脸登录）里**已作废**的模板 —— 即模型身份不符的那些。

⚠️⚠️ 这是**作用于真实库**的管理脚本，不是探针。默认 dry-run。⚠️⚠️

## 为什么需要它

阶段 2（ArcFace ∧ SFace）落地后，`modelId` 从
    cv:<主模型>:<指纹>:512
变成
    cv:<主模型>:<指纹>:512+<次模型>:<指纹>:128

按"换模型即作废"这条红线，旧模板**不会被读取**（`LoadFeaturesAsync` 把
`!Matches(modelId)` 计入 `foreign` 后跳过），但也**不会自动消失** ——
它们只是静静占位，让账号页显示成「已录入 18 张 / 可用 0 张」。

本脚本只做一件事：把 `modelId ≠ 当前期望身份` 的文档删掉。
不重建、不迁移（旧模板里根本没有第二组向量，无法迁移）、不碰 2FA。

## 三重保护（照 tools/db_cleanup.py 的既有风格）

1. **必须显式确认**：走 `_probe_common.require_real_db_optin()`，
   不给 `--i-know-this-is-the-real-db` 一律拦截。
2. **备份是前置条件**：先把待删文档原样导出并**回读核对条数**，
   对不上立即中止，绝不"边备份边删"。
3. **条件收窄到 modelId**：不是清空集合，而是 `modelId != expected`；
   并且删完要复核「2FA 的 FaceTemplates 条数不变」「Users 条数不变」。

还有一条**防呆**：如果两个权重文件不在（期望身份里出现 `missing`），
脚本**拒绝执行** —— 那种情况下"全部模板都算作废"是假象，
真跑下去会把一屋子还能用的模板全删掉。

## 用法

```bash
# 先看清单（不写库）
python tools/faceid_purge_stale_templates.py

# 确认后执行
python tools/faceid_purge_stale_templates.py --apply --i-know-this-is-the-real-db
```
"""
import argparse
import hashlib
import os
import sys
from datetime import datetime, timezone

from bson import json_util

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _probe_common import mongo_client, require_real_db_optin  # noqa: E402

URI = "mongodb://localhost:27017"
DEFAULT_DB = "AuthBaselineDb"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: 目标集合（**只**这个）。2FA 的 `FaceTemplates` 不在这里出现，是刻意的。
COLLECTION = "FaceIdTemplates"
#: 删完之后必须条数不变的集合（证明没误伤）。
UNTOUCHED = ["FaceTemplates", "Users"]

#: 与 FaceIdOptions 的默认值保持一致（脚本不读 appsettings：口径偏差比少改一处更危险）。
PRIMARY_DIM = 512
SECOND_DIM = 128


def fingerprint(path):
    """权重文件的 sha256 前 16 位大写十六进制（与 FaceIdModelIdentity.Fingerprint 逐字一致）。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16].upper()


def describe(path, dim):
    """单个模型的身份片段 `<文件名>:<指纹>:<维度>`（文件缺失时指纹位写 missing）。"""
    name = os.path.basename(path)
    if not os.path.exists(path):
        return "%s:missing:%d" % (name, dim)
    return "%s:%s:%d" % (name, fingerprint(path), dim)


def expected_model_id(model_dir):
    """复现 FaceIdModelIdentity 的组合串：`cv:<主>+<次>`。"""
    primary = describe(os.path.join(model_dir, "face_recognition_arcface_w600k_r50.onnx"), PRIMARY_DIM)
    second = describe(os.path.join(model_dir, "face_recognition_sface_2021dec.onnx"), SECOND_DIM)
    return "cv:%s+%s" % (primary, second)


def backup(docs, path):
    """原样导出待删文档（BSON 安全），随后回读核对条数。"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "collection": COLLECTION,
        "count": len(docs),
        "docs": docs,
    }
    with open(path, "w", encoding="utf-8") as f:
        f.write(json_util.dumps(payload, ensure_ascii=False, indent=1))

    with open(path, "r", encoding="utf-8") as f:
        back = json_util.loads(f.read())
    if len(back.get("docs") or []) != len(docs):
        raise SystemExit("[备份] ❌ 回读条数不符（写入 %d / 读回 %d），已中止"
                         % (len(docs), len(back.get("docs") or [])))
    print("[备份] ✅ %s（%d 条，回读核对通过）" % (path, len(docs)))


def main():
    ap = argparse.ArgumentParser(description="删除 FaceId 里模型身份不符的作废模板")
    ap.add_argument("--db", default=DEFAULT_DB, help="库名（默认 %s）" % DEFAULT_DB)
    ap.add_argument("--model-dir", default=os.path.join(ROOT, "AuthServer", "face-models"),
                    help="权重目录（算期望身份用）")
    ap.add_argument("--expect-model-id", default=None,
                    help="手工指定期望身份串（默认按权重指纹现算）")
    ap.add_argument("--apply", action="store_true", help="真正执行删除（默认只打印清单）")
    ap.add_argument("--i-know-this-is-the-real-db", action="store_true",
                    help="对真实库执行破坏性操作的显式确认")
    args = ap.parse_args()

    expected = args.expect_model_id or expected_model_id(args.model_dir)
    print("[身份] 期望 modelId = %s" % expected)

    if "missing" in expected:
        raise SystemExit(
            "[中止] 期望身份里有 `missing` —— 权重文件不在 %s。\n"
            "       这种情况下「全部模板都作废」是假象，删下去会误伤还能用的模板。\n"
            "       请先确认模型文件（或用 --expect-model-id 手工指定）。" % args.model_dir)

    # 门禁只卡**写**：dry-run 是只读的，拦它只会逼人去加参数、把确认变成肌肉记忆。
    if args.apply:
        require_real_db_optin(
            args.db,
            script="faceid_purge_stale_templates.py",
            operation="删除 %s 中 modelId 与当前双模型身份不符的模板（不可逆）" % COLLECTION,
        )

    client = mongo_client(URI)
    db = client[args.db]
    coll = db[COLLECTION]

    before_untouched = {name: db[name].count_documents({}) for name in UNTOUCHED}
    total = coll.count_documents({})

    stale = list(coll.find({"modelId": {"$ne": expected}}))
    alive = total - len(stale)
    print("\n[现状] %s 共 %d 条：可用 %d / 作废 %d" % (COLLECTION, total, alive, len(stale)))

    if not stale:
        print("[结果] 没有需要清理的模板。")
        return 0

    # 按账号汇总：谁录了几张、录于什么身份、什么时候录的
    by_user = {}
    for doc in stale:
        key = doc.get("username") or doc.get("userId") or "?"
        row = by_user.setdefault(key, {"n": 0, "modelId": set(), "version": set(), "first": None, "last": None})
        row["n"] += 1
        row["modelId"].add(doc.get("modelId"))
        row["version"].add(doc.get("version"))
        ts = doc.get("createdAt")
        if ts is not None:
            row["first"] = ts if row["first"] is None or ts < row["first"] else row["first"]
            row["last"] = ts if row["last"] is None or ts > row["last"] else row["last"]

    print("\n%-16s %4s %8s  %-12s %s" % ("账号", "张数", "version", "最近录入", "modelId"))
    print("-" * 100)
    for key in sorted(by_user):
        row = by_user[key]
        last = row["last"].strftime("%Y-%m-%d %H:%M") if row["last"] else "—"
        for mid in sorted(row["modelId"]):
            print("%-16s %4d %8s  %-12s %s"
                  % (key, row["n"], ",".join(str(v) for v in sorted(row["version"])), last, mid))
    print("-" * 100)
    print("合计：%d 个账号 / %d 条模板待删" % (len(by_user), len(stale)))

    if not args.apply:
        print("\n[dry-run] 未写库。确认无误后追加 --apply --i-know-this-is-the-real-db")
        return 0

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(ROOT, "tools", "backup", "faceid_templates_%s.json" % stamp)
    backup(stale, backup_path)

    ids = [doc["_id"] for doc in stale]
    result = coll.delete_many({"_id": {"$in": ids}})

    # ── 复核 ────────────────────────────────────────────────────────
    problems = []
    if result.deleted_count != len(ids):
        problems.append("删除条数 %d ≠ 计划 %d" % (result.deleted_count, len(ids)))
    if coll.count_documents({"modelId": {"$ne": expected}}) != 0:
        problems.append("仍有 modelId 不符的残留")
    for name in UNTOUCHED:
        now = db[name].count_documents({})
        if now != before_untouched[name]:
            problems.append("%s 条数变化 %d → %d（不该被碰）" % (name, before_untouched[name], now))

    print("\n[结果] 计划删 %d，实际删 %d；%s 剩余 %d 条（全部为当前身份）"
          % (len(ids), result.deleted_count, COLLECTION, coll.count_documents({})))
    print("[复核] " + ("、".join("%s %d 条未变" % (n, before_untouched[n]) for n in UNTOUCHED)
                       if not problems else "❌ " + "；".join(problems)))
    print("[回滚] 备份仅作审计留存：%s" % backup_path)
    print("       这些模板缺第二组向量，即使灌回库也不会被判为可用 —— 恢复没有意义，重录才是正解。")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
