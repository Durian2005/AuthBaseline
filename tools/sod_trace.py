# -*- coding: utf-8 -*-
"""职责分离（SoD）绕过线索的**独立复算**脚本 —— 不经过后端，直接查库。

为什么要有它
============
后端 `GET /api/audit/sod` 能算出归因链，但它的结论来自"被测系统自己"。
安全评审里这不够：如果被审的东西能说谎，让它自证清白没有意义。

本脚本把同一套规则用另一种实现、另一条数据通路（pymongo 直连）重算一遍：
  - 两边结论一致 ⇒ 说明结论来自数据本身，而不是后端某段代码的偏好；
  - 两边不一致 ⇒ 立刻暴露"规则实现有分歧"，这本身就是最值得查的问题。

它同时是给老师现场复核用的：不需要起服务、不需要登录，
一条命令就能列出"谁造了审计管理员、谁用它读了几次、什么时候封的口"。

判定规则（与 AuthServer/Services/SodAnalyzer.cs **逐条对应**）
============================================================
  R1 授予：成功的 CREATE_ACCOUNT / SET_ROLE，且角色是 AuditAdmin
           （优先读 request.Role；取不到时退到 statusAfter 的 "用户名·审计管理员" 形态）。
  R2 归属：该账号此后每次成功的 AUDIT_QUERY / AUDIT_VERIFY，
           在它自助改密（CHANGE_PASSWORD）或邮箱重置（RESET_PASSWORD）之前，
           都算"授予者的读取"。
  R3 封口：自助改密 / 重置成功的那一刻封口；封口前的读取仍归因。
  R4 观察：造了审计管理员但从未读过 ⇒ DORMANT（准备行为，单列而不是忽略）。
  R5 批量：同一管理员名下 ≥2 条链 ⇒ 批量制造审计身份。

用法
====
  python tools/sod_trace.py                          # 默认查 AuthBaselineDb（只读）
  python tools/sod_trace.py --db AuthBaselineSodProbe
  python tools/sod_trace.py --json                   # 机器可读（字段名与接口一致）
  python tools/sod_trace.py --strict                 # 存在 ATTRIBUTED 时退出码 1

为什么没有 `--i-know-this-is-the-real-db` 门禁
=============================================
`require_real_db_optin()` 守的是"**会写库**"的脚本，门禁落在真正落盘那一刻。
本脚本**只读**：不 insert、不 update、不 drop，连临时集合都不建。
对只读脚本加确认开关，只会训练人"无脑加参数"，反而削弱那套门禁的可信度。

⚠️ 能力边界（与后端接口口径一致，别说满）
  1. 只做事后归因，不阻止任何操作 —— 造审计管理员本身是合法行为。
  2. sidecar 与客户端同机 ⇒ 记录全来自 127.0.0.1 + 同一 WebView2 UA，
     来源指纹在本项目里几乎没有区分力，判定只能靠事件序列。
  3. 只能证明"口令由谁设定、读取发生在封口之前"，不能证明"当时敲键盘的是谁"。
"""
import argparse
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _probe_common import mongo_client  # noqa: E402

# ---- 与后端常量对齐（刻意写字面量：本脚本要能离开源码单独运行） ----
RESULT_SUCCESS = "成功"
ACT_CREATE = "CREATE_ACCOUNT"
ACT_SET_ROLE = "SET_ROLE"
ACT_LOGIN_OK = "LOGIN_SUCCESS"
ACT_CHANGE_PWD = "CHANGE_PASSWORD"
ACT_RESET_PWD = "RESET_PASSWORD"
ACT_READ = ("AUDIT_QUERY", "AUDIT_VERIFY")
AUDIT_ROLE_TOKEN = "AuditAdmin"
AUDIT_ROLE_LABEL = "审计管理员"

RISK_ATTRIBUTED = "ATTRIBUTED"
RISK_SEALED = "SEALED"
RISK_DORMANT = "DORMANT"


def _prop(raw, name):
    """从 JSON 字符串里按名取字段（大小写不敏感，解析失败返回 None）。

    审计的扩展信息只能塞进 request / response 这两个**字符串**列 ——
    哈希链的输入字段是固定的，不能加列。所以这里必须容忍空串与异形结构。
    """
    if not raw or not isinstance(raw, str):
        return None
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    for k, v in obj.items():
        if k.lower() == name.lower():
            return v
    return None


def _ts(doc):
    t = doc.get("timestamp")
    return t if isinstance(t, datetime) else datetime.min


def load_events(conn, db_name):
    """按分片取全部审计事件（与 MongoDbService.ListAuditShardNamesAsync 同口径）。"""
    db = conn[db_name]
    docs = []
    for name in sorted(db.list_collection_names()):
        if not name.startswith("AuditLogs"):
            continue
        docs.extend(db[name].find())
    docs.sort(key=lambda d: (d.get("seq") or 0, _ts(d)))
    return docs


def analyze(docs):
    """纯函数：审计事件列表 → 归因链。与 SodAnalyzer.Analyze 一一对应。"""
    out = {
        "scanned": len(docs),
        "attributed": 0,
        "sealed": 0,
        "dormant": 0,
        "batchGranters": [],
        "chains": [],
    }
    if not docs:
        return out

    ordered = sorted(docs, key=lambda d: (d.get("seq") or 0, _ts(d)))

    # ---------- R1 授予 ----------
    grants = {}
    for ev in ordered:
        if ev.get("result") != RESULT_SUCCESS:
            continue
        action = ev.get("action")
        if action == ACT_CREATE:
            kind = "create"
        elif action == ACT_SET_ROLE:
            kind = "set-role"
        else:
            continue

        role = _prop(ev.get("request"), "Role")
        by_role = isinstance(role, str) and role.strip().lower() == AUDIT_ROLE_TOKEN.lower()
        by_status = str(ev.get("statusAfter") or "").endswith("·" + AUDIT_ROLE_LABEL)
        if not (by_role or by_status):
            continue

        auditor = (ev.get("target") or "").strip()
        if not auditor:
            continue

        key = auditor.lower()
        cur = grants.get(key)
        if cur is None or (ev.get("seq") or 0) < (cur["seq"] or 0):
            grants[key] = {
                "auditor": auditor,
                "granter": ev.get("operatorName") or "",
                "kind": kind,
                "at": _ts(ev),
                "seq": ev.get("seq") or 0,
            }

    # ---------- R2/R3/R4 ----------
    chains = []
    for key, g in grants.items():
        own = [
            ev for ev in ordered
            if _ts(ev) >= g["at"] and str(ev.get("operatorName") or "").lower() == key
        ]

        logins = [ev for ev in own if ev.get("action") == ACT_LOGIN_OK]
        seals = [
            ev for ev in own
            if ev.get("result") == RESULT_SUCCESS
            and ev.get("action") in (ACT_CHANGE_PWD, ACT_RESET_PWD)
        ]
        reads = [
            ev for ev in own
            if ev.get("result") == RESULT_SUCCESS and ev.get("action") in ACT_READ
        ]

        seal = min(seals, key=lambda e: e.get("seq") or 0) if seals else None
        seal_seq = seal.get("seq") or 0 if seal else None

        attributed = [r for r in reads if seal_seq is None or (r.get("seq") or 0) < seal_seq]
        post = [r for r in reads if seal_seq is not None and (r.get("seq") or 0) >= seal_seq]

        evidence = [g["seq"]]
        if logins:
            evidence.append(logins[0].get("seq") or 0)
        if seal:
            evidence.append(seal.get("seq") or 0)
        if attributed:
            evidence.append(attributed[0].get("seq") or 0)
            if len(attributed) > 1:
                evidence.append(attributed[-1].get("seq") or 0)

        if not attributed:
            risk = RISK_DORMANT
        elif seal is None:
            risk = RISK_ATTRIBUTED
        else:
            risk = RISK_SEALED

        chains.append({
            "auditor": g["auditor"],
            "granter": g["granter"],
            "grantKind": g["kind"],
            "grantedAt": g["at"].isoformat() if g["at"] != datetime.min else None,
            "sealedAt": seal.get("timestamp").isoformat() if seal and isinstance(seal.get("timestamp"), datetime) else None,
            "firstLoginAt": (
                logins[0].get("timestamp").isoformat()
                if logins and isinstance(logins[0].get("timestamp"), datetime) else None
            ),
            "attributedReads": len(attributed),
            "postSealReads": len(post),
            "firstAttributedReadAt": (
                attributed[0].get("timestamp").isoformat()
                if attributed and isinstance(attributed[0].get("timestamp"), datetime) else None
            ),
            "lastAttributedReadAt": (
                attributed[-1].get("timestamp").isoformat()
                if attributed and isinstance(attributed[-1].get("timestamp"), datetime) else None
            ),
            "risk": risk,
            "evidenceSeqs": [s for s in evidence if s],
        })

    # ---------- R5 批量 ----------
    counter = {}
    for c in chains:
        k = c["granter"].lower()
        counter[k] = counter.get(k, 0) + 1
    out["batchGranters"] = sorted({c["granter"] for c in chains
                                  if counter.get(c["granter"].lower(), 0) >= 2})

    out["attributed"] = sum(1 for c in chains if c["risk"] == RISK_ATTRIBUTED)
    out["sealed"] = sum(1 for c in chains if c["risk"] == RISK_SEALED)
    out["dormant"] = sum(1 for c in chains if c["risk"] == RISK_DORMANT)

    rank = {RISK_ATTRIBUTED: 0, RISK_SEALED: 1, RISK_DORMANT: 2}
    chains.sort(key=lambda c: (rank.get(c["risk"], 9), -c["attributedReads"], c["grantedAt"] or ""))
    out["chains"] = chains
    return out


def _fmt_time(s):
    if not s:
        return "—"
    try:
        return datetime.fromisoformat(s).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return s


def print_report(result, db_name):
    print("")
    print("=" * 92)
    print("  职责分离（SoD）绕过线索 —— 独立复算（直接读库，不经过后端）")
    print("  库：%s    事件：%d 条" % (db_name, result["scanned"]))
    print("=" * 92)

    if not result["chains"]:
        print("  未发现任何「管理员造出审计管理员」的链路。")
        print("  说明：本结论只覆盖「授予 → 读取」这条已知绕过路径，不等于系统无其它风险。")
        print("=" * 92)
        return

    HEAD = "%-16s %-12s %-8s %-19s %-19s %6s %6s  %s"
    print(HEAD % ("审计管理员", "授予人", "方式", "授予时间", "封口时间", "归因读", "封口后", "判定"))
    print("-" * 92)
    for c in result["chains"]:
        print(HEAD % (
            c["auditor"][:16], c["granter"][:12], c["grantKind"],
            _fmt_time(c["grantedAt"]), _fmt_time(c["sealedAt"]),
            c["attributedReads"], c["postSealReads"], _RISK_TEXT.get(c["risk"], c["risk"])
        ))

    print("-" * 92)
    print("  可归因且未封口 %d 条 · 已封口 %d 条 · 造号未使用 %d 条"
          % (result["attributed"], result["sealed"], result["dormant"]))
    if result["batchGranters"]:
        print("  批量制造审计身份的管理员：%s（名下 ≥2 条链）"
              % "、".join(result["batchGranters"]))
    print("")
    print("  口径提醒：")
    print("   · 造审计管理员本身是合法分工，本文列出的是「可归因性」，不是「违规认定」；")
    print("   · ATTRIBUTED 只说明口令由授予人设定且该账号用它读过审计，")
    print("     不能证明当时操作的就是授予人本人；")
    print("   · 同机部署下来源 IP/UA 无区分力，结论完全基于事件序列。")
    print("=" * 92)


_RISK_TEXT = {
    RISK_ATTRIBUTED: "⚠ 可归因（未封口）",
    RISK_SEALED: "已封口（历史仍归因）",
    RISK_DORMANT: "造号未使用",
}


def main():
    ap = argparse.ArgumentParser(description="职责分离绕过线索（独立复算，只读）")
    ap.add_argument("--db", default="AuthBaselineDb", help="库名（默认 AuthBaselineDb，只读）")
    ap.add_argument("--uri", default="mongodb://localhost:27017", help="Mongo 连接串")
    ap.add_argument("--json", action="store_true", help="输出 JSON（字段名与 /api/audit/sod 一致）")
    ap.add_argument("--strict", action="store_true", help="存在 ATTRIBUTED 链时退出码 1")
    args = ap.parse_args()

    conn = mongo_client(args.uri)
    try:
        docs = load_events(conn, args.db)
    finally:
        conn.close()

    result = analyze(docs)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_report(result, args.db)

    return 1 if (args.strict and result["attributed"] > 0) else 0


if __name__ == "__main__":
    sys.exit(main())
