# -*- coding: utf-8 -*-
"""真机验证：纯人脸登录（FaceId）P1 —— 录入闸门与模板存储。

全部对着**独立测试库**打真实 HTTP + 直连数据库断言，用**假引擎**跑，
因此**不需要摄像头**也能覆盖最难的几条分支：
质量闸门（多脸 / 太小 / 侧脸 / 糊）、引擎降级、口令二次确认的计次、
模板密文落库、上限淘汰、模型作废、注销连带清理。

验证十组：
  A. 状态    —— 未录入的账号：enrolled=false、引擎就绪、上限 3；无票据被拒
  B. 口令闸门—— 空口令 / 错口令（A 组计次 + 审计码）/ 口令对 ⇒ 录入成功
  C. 质量闸门—— no_face / multi_face / blurry / turned / engine_down 逐条都必须被拒，
                 且**模板数不变**、**失败不计次**（录入发生在已登录之后）
  D. 存储审计—— 库里是密文（长度 = 512×4，有 nonce/tag，modelId=stub:*），
                 审计里**不出现特征向量**、链字段完整
  E. 上限淘汰—— MAX_TEMPLATES=2 时连录 3 次 ⇒ 只留 2 张
  F. 模型作废—— 把 modelId 改成旧模型 ⇒ 状态报 usable=0/mismatch=1；
                 再录一次 ⇒ 旧模板被清掉（purgedForeign=1）
  G. 删除    —— 空口令 / 错口令（计次）/ 口令对 ⇒ 模板真删
  H. 注销    —— 管理员注销账号 ⇒ FaceIdTemplates 里该用户的数据被清理
  I. 活体闸门—— 活体显式打开：spoof ⇒ 400 且计次；模型不可用 ⇒ 503（fail closed）；
                 同样的输入关掉活体会成功（证明拒绝确实来自 PAD）
  J. 人脸登录—— 成功签票且票据可用、审计标 SecondFactor=FACEID；
                 未录入 ⇒ 401 NOT_ENROLLED 且**不计次**；判错 ⇒ 401 MISMATCH 且**计次**；
                 不存在的账号与「不匹配」同码

用法：
  python tools/faceid_enroll_probe.py <exe路径> <端口> [--db NAME]

⚠️ 探针打真实库是 bug：库名必须含 `Probe`（`resolve_probe_db` 已守卫）。
⚠️ 必须 AUTHBASELINE_REQUIRE_HTTPS=false，且用带 pymongo 的**系统** Python 跑。
"""
import contextlib
import json
import sys
import time

from _probe_common import (
    ProbeDb,
    http_call,
    resolve_probe_db,
    start_backend,
    stop_backend,
    wait_backend_ready,
)

EXE = sys.argv[1]
PORT = int(sys.argv[2])
BASE = "http://127.0.0.1:%d" % PORT
DB_NAME = resolve_probe_db("AuthBaselineFaceIdProbe")

ADMIN_PW = "Admin123"
USER = "faceidprobe"
USER_PW = "Faceidprobe123"
DROP_USER = "faceiddrop"
DROP_PW = "Faceiddrop123"
PAD_USER = "faceidpad"
PAD_PW = "Faceidpad123"

probe_db = ProbeDb(DB_NAME)
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name, ("  -> " + str(detail)) if detail else ""))


def call(method, path, body=None, ticket=None):
    return http_call(BASE, method, path, body=body, ticket=ticket)


def login(user, pw):
    return call("POST", "/api/auth/login", {"username": user, "password": pw})


def status(ticket):
    return call("GET", "/api/faceid/status", ticket=ticket)


def enroll(ticket, pw):
    return call("POST", "/api/faceid/enroll", {"password": pw}, ticket)


def delete(ticket, pw):
    return call("POST", "/api/faceid/delete", {"password": pw}, ticket)


@contextlib.contextmanager
def backend(behavior, tag, extra=None):
    """起一个后端（假引擎 + 指定行为），退出时关掉。

    假引擎的行为在**启动时**读取，所以每组不同行为都要重启；
    也让探针不会因为前一段的失败计数/模板残留而互相污染。
    """
    env = {
        # 探针走明文 HTTP：TLS 那套由 transport_* 专项脚本负责。
        "AUTHBASELINE_REQUIRE_HTTPS": "false",
        "AUTHBASELINE_FACEID_ENGINE": "stub",
        "AUTHBASELINE_FACEID_STUB_IDENTITY": USER,
        "AUTHBASELINE_FACEID_STUB_BEHAVIOR": behavior,
    }
    if extra:
        env.update(extra)

    proc = start_backend(EXE, PORT, DB_NAME,
                         log_name="faceid_probe_%s_%d.log" % (tag, PORT),
                         extra_env=env)
    try:
        if not wait_backend_ready(BASE, proc, timeout_s=90):
            raise SystemExit("后端启动失败（日志见 tools/buildlogs/faceid_probe_%s_%d.log）" % (tag, PORT))
        yield proc
    finally:
        stop_backend(proc)
        time.sleep(1.0)   # 让端口与 Mongo 连接释放，避免下一段起不来


# ---------------------------------------------------------------------------
# 直连库的断言工具
# ---------------------------------------------------------------------------
def templates(username=USER):
    return list(probe_db["FaceIdTemplates"].find({"username": username}))


def audit_docs(action=None):
    """跨全部分片取审计文档（顶层字段是 camelCase）。"""
    docs = []
    for name in probe_db.list_collection_names():
        if not name.startswith("AuditLogs_"):
            continue
        flt = {"action": action} if action else {}
        docs.extend(probe_db[name].find(flt))
    return docs


def audit_count(action):
    return len(audit_docs(action))


def audit_reason_count(reason):
    """按**原因码**数审计条数。

    ⚠️ 原因码在 `reasonCode` 字段里，不是 `action`：
    action 是"发生了什么"（FACEID_ENROLL_FAILED），reasonCode 是"为什么"
    （FACEID_ENROLL_REJECTED）。两者混用会让断言永远为 0 —— 看起来像"没写审计"。
    """
    n = 0
    for name in probe_db.list_collection_names():
        if name.startswith("AuditLogs_"):
            n += probe_db[name].count_documents({"reasonCode": reason})
    return n


def parse_bag(raw):
    """审计的 request / response 落库时是**字符串**（PascalCase JSON），解析回来再断言。

    ⚠️ 不解析直接对字符串判"有没有长数组"会永远为假 —— 断言会变成一句空话。
    """
    if not raw:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return None


def has_long_array(obj):
    if isinstance(obj, list):
        return len(obj) >= 64 or any(has_long_array(v) for v in obj)
    if isinstance(obj, dict):
        return any(has_long_array(v) for v in obj.values())
    return False


def main():
    print("=" * 70)
    print("纯人脸登录 P1 录入探针 · 库=%s · 端口=%d" % (DB_NAME, PORT))
    print("=" * 70)

    if probe_db.drop_if_exists():
        print("（已清理上次残留的测试库）")

    # =====================================================================
    # A：状态骨架 + B：口令二次确认 + 首次录入
    # =====================================================================
    print("\n[A] 状态：未录入的账号 + 无票据被拒")
    with backend("ok", "a"):
        st, r = login("admin", ADMIN_PW)
        admin_ticket = (r.get("data") or {}).get("ticket", "")
        check("admin 登录（准备票据）", st == 200 and bool(admin_ticket), "%s %s" % (st, r.get("code")))

        st, r = call("POST", "/api/auth/create-account", {
            "username": USER, "password": USER_PW, "role": "User",
            "email": "", "operatorPassword": ADMIN_PW}, admin_ticket)
        check("建测试账号", st == 200 and r.get("code") == "OK", "%s %s" % (st, r.get("code")))

        st, r = status(None)
        check("状态是受保护接口（无票据 401）", st == 401, "%s %s" % (st, r.get("code")))

        st, r = login(USER, USER_PW)
        ticket = (r.get("data") or {}).get("ticket", "")
        check("测试账号登录", st == 200 and bool(ticket), "%s %s" % (st, r.get("code")))

        st, r = status(ticket)
        d = r.get("data") or {}
        check("状态：未录入 / 引擎就绪 / 上限 3 / 阈值 0.30（P3 定档）",
              st == 200 and d.get("enrolled") is False and d.get("templateCount") == 0
              and d.get("usableCount") == 0 and d.get("modelMismatchCount") == 0
              and d.get("engineReady") is True and d.get("maxTemplates") == 3
              and abs((d.get("threshold") or 0) - 0.30) < 1e-9,
              str(d))
        check("状态下发当前模型身份（stub:*）",
              str(d.get("modelId", "")).startswith("stub:"), str(d.get("modelId")))
        check("状态查询不写审计（每次开页都会拉）",
              audit_count("FACEID_ENROLL") == 0 and audit_count("FACEID_ENROLL_FAILED") == 0,
              "enroll=%d" % audit_count("FACEID_ENROLL"))

    print("\n[B] 口令二次确认：空 / 错 / 对")
    with backend("ok", "b"):
        st, r = login(USER, USER_PW)
        ticket = (r.get("data") or {}).get("ticket", "")
        check("（准备）拿到票据", bool(ticket), "%s %s" % (st, r.get("code")))

        st, r = enroll(ticket, "")
        check("空口令 ⇒ 400 EMPTY_FIELDS", st == 400 and r.get("code") == "EMPTY_FIELDS",
              "%s %s" % (st, r.get("code")))

        st, r = enroll(ticket, "WrongPass123")
        check("错口令 ⇒ 401 INVALID_CREDENTIALS", st == 401 and r.get("code") == "INVALID_CREDENTIALS",
              "%s %s" % (st, r.get("code")))
        check("错口令按 A 组计次 = 1", (r.get("data") or {}).get("failedAttempts") == 1,
              str(r.get("data")))

        st, r = enroll(ticket, USER_PW)
        d = r.get("data") or {}
        check("口令对 ⇒ 录入成功（模板 1 张）",
              st == 200 and r.get("code") == "OK" and d.get("templateCount") == 1,
              "%s %s %s" % (st, r.get("code"), d))

        st, r = status(ticket)
        d = r.get("data") or {}
        check("状态：已录入 / 可用 1 张 / 记录录入时刻",
              d.get("enrolled") is True and d.get("usableCount") == 1 and bool(d.get("enrolledAt")),
              str(d))

    # =====================================================================
    # C：质量闸门 —— 每条都要拒、都不许改模板数、都不许计次
    # =====================================================================
    print("\n[C] 质量闸门：五条拒绝路径（模板数不变 + 失败不计次）")
    cases = [
        ("no_face", 400, "FACEID_NO_FACE"),
        ("multi_face", 400, "FACEID_MULTIPLE_FACES"),
        ("blurry", 400, "FACEID_LOW_QUALITY"),
        ("turned", 400, "FACEID_NOT_FRONTAL"),
    ]
    for behavior, expect_status, expect_code in cases:
        with backend(behavior, "c_" + behavior):
            st, r = login(USER, USER_PW)
            ticket = (r.get("data") or {}).get("ticket", "")
            before = len(templates())

            st, r = enroll(ticket, USER_PW)
            check("%s ⇒ %d %s" % (behavior, expect_status, expect_code),
                  st == expect_status and r.get("code") == expect_code,
                  "%s %s" % (st, r.get("code")))
            check("%s：模板数不变（%d 张）" % (behavior, before), len(templates()) == before,
                  "now=%d" % len(templates()))

            # 录入失败发生在**已登录之后**，没有任何安全含义 ⇒ 不得累加失败计数。
            # 若这里被计次，用户反复调整坐姿就会把自己锁掉。
            doc = probe_db["Users"].find_one({"username": USER})
            check("%s：录入失败不计次（failedAttempts=0）" % behavior,
                  (doc or {}).get("failedLoginAttempts", 0) == 0,
                  "failed=%s" % (doc or {}).get("failedLoginAttempts"))

            check("%s：审计记 FACEID_ENROLL_REJECTED" % behavior,
                  audit_reason_count("FACEID_ENROLL_REJECTED") >= 1,
                  "n=%d" % audit_reason_count("FACEID_ENROLL_REJECTED"))

    with backend("engine_down", "c_engine_down"):
        st, r = login(USER, USER_PW)
        ticket = (r.get("data") or {}).get("ticket", "")
        st, r = enroll(ticket, USER_PW)
        check("engine_down ⇒ 503 FACEID_ENGINE_UNAVAILABLE",
              st == 503 and r.get("code") == "FACEID_ENGINE_UNAVAILABLE",
              "%s %s" % (st, r.get("code")))
        check("engine_down：审计记 FACEID_ENGINE_UNAVAILABLE",
              audit_reason_count("FACEID_ENGINE_UNAVAILABLE") >= 1,
              "n=%d" % audit_reason_count("FACEID_ENGINE_UNAVAILABLE"))

    # =====================================================================
    # D：存储与审计 —— 密文落库、审计不含特征
    # =====================================================================
    print("\n[D] 存储 / 审计：密文落库、审计无特征向量")
    docs = templates()
    check("模板文档存在（1 张）", len(docs) == 1, "n=%d" % len(docs))
    if docs:
        doc = docs[0]
        check("密文长度 = 512 × 4 = 2048", len(doc.get("cipher") or b"") == 2048,
              "len=%d" % len(doc.get("cipher") or b""))
        check("nonce 12 字节 / tag 16 字节",
              len(doc.get("nonce") or b"") == 12 and len(doc.get("tag") or b"") == 16,
              "nonce=%d tag=%d" % (len(doc.get("nonce") or b""), len(doc.get("tag") or b"")))
        check("模型身份随模板落库（stub:*）",
              str(doc.get("modelId", "")).startswith("stub:"), str(doc.get("modelId")))
        check("模板文档里没有明文字段（feature / vector / embedding）",
              not any(k.lower() in ("feature", "vector", "embedding") for k in doc.keys()),
              str(list(doc.keys())))

    enroll_docs = audit_docs("FACEID_ENROLL")
    check("成功录入写了一条 FACEID_ENROLL", len(enroll_docs) >= 1, "n=%d" % len(enroll_docs))
    if enroll_docs:
        doc = enroll_docs[0]
        merged = [parse_bag(doc.get("request")), parse_bag(doc.get("response"))]
        check("审计的 request/response 里没有特征向量（无长数组）",
              not any(has_long_array(x) for x in merged), str([type(x).__name__ for x in merged]))
        check("审计带诊断量但不含画面",
              "frames=" in (doc.get("request") or "") or "frames=" in (doc.get("response") or ""),
              "（诊断量仅入审计）")
        check("审计链字段完整（prevHash / selfHash 非空）",
              bool(doc.get("prevHash")) and bool(doc.get("selfHash")),
              "prev=%s self=%s" % (str(doc.get("prevHash"))[:8], str(doc.get("selfHash"))[:8]))

    # =====================================================================
    # E：上限淘汰（MAX_TEMPLATES=2，连录 3 次）
    # =====================================================================
    print("\n[E] 上限淘汰：MAX_TEMPLATES=2 连录 3 次 ⇒ 只留 2 张")
    with backend("ok", "e", extra={"AUTHBASELINE_FACEID_MAX_TEMPLATES": "2"}):
        st, r = login(USER, USER_PW)
        ticket = (r.get("data") or {}).get("ticket", "")

        st, r = status(ticket)
        check("上限随配置生效（maxTemplates=2）", (r.get("data") or {}).get("maxTemplates") == 2,
              str((r.get("data") or {}).get("maxTemplates")))

        # 先清掉上一段留下的模板，让"连录 3 次"的计数从干净状态开始
        probe_db["FaceIdTemplates"].delete_many({"username": USER})

        counts = []
        for i in range(3):
            st, r = enroll(ticket, USER_PW)
            counts.append((r.get("data") or {}).get("templateCount"))
            time.sleep(0.05)   # 让 createdAt 有可区分的顺序
        check("连录 3 次：返回的张数依次为 1 / 2 / 2", counts == [1, 2, 2], str(counts))
        check("库里只剩 2 张（超出上限淘汰最旧）", len(templates()) == 2, "n=%d" % len(templates()))

    # =====================================================================
    # F：模型作废（模板与 modelId 绑定）
    # =====================================================================
    print("\n[F] 模型作废：modelId 改成旧模型 ⇒ 不可用；再录 ⇒ 清掉旧模板")
    with backend("ok", "f"):
        probe_db["FaceIdTemplates"].update_many(
            {"username": USER}, {"$set": {"modelId": "cv:old-model:deadbeefdeadbeef:512"}})

        st, r = login(USER, USER_PW)
        ticket = (r.get("data") or {}).get("ticket", "")

        st, r = status(ticket)
        d = r.get("data") or {}
        check("★ 状态如实报告：总量 2 / 可用 0 / 模型不符 2",
              d.get("templateCount") == 2 and d.get("usableCount") == 0
              and d.get("modelMismatchCount") == 2, str(d))

        st, r = enroll(ticket, USER_PW)
        d = r.get("data") or {}
        check("★ 再录一次：旧模型模板被清掉（purgedForeign=2）",
              st == 200 and d.get("purgedForeign") == 2, "%s %s" % (st, d))
        check("★ 清掉后只剩 1 张（新模型）",
              len(templates()) == 1
              and str(templates()[0].get("modelId", "")).startswith("stub:"),
              "n=%d" % len(templates()))

    # =====================================================================
    # G：删除（口令二次确认）
    # =====================================================================
    print("\n[G] 删除：空 / 错 / 对")
    with backend("ok", "g"):
        st, r = login(USER, USER_PW)
        ticket = (r.get("data") or {}).get("ticket", "")

        st, r = delete(ticket, "")
        check("空口令 ⇒ 400 EMPTY_FIELDS", st == 400 and r.get("code") == "EMPTY_FIELDS",
              "%s %s" % (st, r.get("code")))

        st, r = delete(ticket, "WrongPass123")
        check("错口令 ⇒ 401 INVALID_CREDENTIALS 且计次",
              st == 401 and r.get("code") == "INVALID_CREDENTIALS"
              and (r.get("data") or {}).get("failedAttempts") == 1,
              "%s %s %s" % (st, r.get("code"), r.get("data")))

        before = len(templates())
        st, r = delete(ticket, USER_PW)
        d = r.get("data") or {}
        check("口令对 ⇒ 删除成功（removed=%d）" % before,
              st == 200 and d.get("removed") == before, "%s %s" % (st, d))
        check("删除后库里没有该用户模板", len(templates()) == 0, "n=%d" % len(templates()))

        st, r = status(ticket)
        check("状态回落到未录入", (r.get("data") or {}).get("enrolled") is False, str(r.get("data")))

        check("删除写了审计 FACEID_TEMPLATE_DELETED",
              audit_count("FACEID_TEMPLATE_DELETED") >= 1,
              "n=%d" % audit_count("FACEID_TEMPLATE_DELETED"))

    # =====================================================================
    # H：注销连带清理（生物特征不留孤儿）
    # =====================================================================
    print("\n[H] 注销：账号删掉后模板必须一并消失")
    with backend("ok", "h"):
        st, r = login("admin", ADMIN_PW)
        admin_ticket = (r.get("data") or {}).get("ticket", "")

        st, r = call("POST", "/api/auth/create-account", {
            "username": DROP_USER, "password": DROP_PW, "role": "User",
            "email": "", "operatorPassword": ADMIN_PW}, admin_ticket)
        check("建待注销账号", st == 200 and r.get("code") == "OK", "%s %s" % (st, r.get("code")))

        st, r = login(DROP_USER, DROP_PW)
        drop_ticket = (r.get("data") or {}).get("ticket", "")
        st, r = enroll(drop_ticket, DROP_PW)
        check("待注销账号录入人脸", st == 200 and len(templates(DROP_USER)) == 1,
              "%s %s" % (st, r.get("code")))

        st, r = call("POST", "/api/auth/delete-user", {"username": DROP_USER}, admin_ticket)
        check("管理员注销账号", st == 200 and r.get("code") == "OK", "%s %s" % (st, r.get("code")))
        check("★ 注销后 FaceIdTemplates 无残留（不留孤儿生物特征）",
              len(templates(DROP_USER)) == 0, "n=%d" % len(templates(DROP_USER)))

    # =====================================================================
    # I：活体判定（P1b）—— 照片被拒 + 计次；模型缺失 fail closed；关掉对照放行
    # =====================================================================
    print("\n[I] 活体判定：spoof 被拒且计次 / 模型缺失 fail closed / 关掉后放行")
    # ⚠️ PAD 默认是关的（验收要手举照片），所以这一组必须**显式打开**，
    #    否则测到的是"没开活体自然放行"，不构成任何证据。
    with backend("spoof", "i_spoof", {"AUTHBASELINE_FACEID_PAD_ENABLED": "true"}):
        st, r = login("admin", ADMIN_PW)
        admin_ticket = (r.get("data") or {}).get("ticket", "")
        st, r = call("POST", "/api/auth/create-account", {
            "username": PAD_USER, "password": PAD_PW, "role": "User",
            "email": "", "operatorPassword": ADMIN_PW}, admin_ticket)
        check("建活体测试账号", st == 200 and r.get("code") == "OK", "%s %s" % (st, r.get("code")))

        st, r = login(PAD_USER, PAD_PW)
        pad_ticket = (r.get("data") or {}).get("ticket", "")

        st, r = enroll(pad_ticket, PAD_PW)
        check("★ spoof（举照片）⇒ 400 FACEID_LIVENESS_FAILED",
              st == 400 and r.get("code") == "FACEID_LIVENESS_FAILED",
              "%s %s" % (st, r.get("code")))
        check("spoof：模板没有写入", len(templates(PAD_USER)) == 0,
              "n=%d" % len(templates(PAD_USER)))

        doc = probe_db["Users"].find_one({"username": PAD_USER})
        check("★ spoof：活体失败计入失败窗口（failedAttempts=1）",
              (doc or {}).get("failedLoginAttempts", 0) == 1,
              "failed=%s" % (doc or {}).get("failedLoginAttempts"))
        check("spoof：审计记 FACEID_LIVENESS_FAILED（A 组）",
              audit_reason_count("FACEID_LIVENESS_FAILED") >= 1,
              "n=%d" % audit_reason_count("FACEID_LIVENESS_FAILED"))

    with backend("ok", "i_pad_down", {"AUTHBASELINE_FACEID_STUB_BEHAVIOR": "pad_down",
                                      "AUTHBASELINE_FACEID_PAD_ENABLED": "true"}):
        st, r = login(PAD_USER, PAD_PW)
        pad_ticket = (r.get("data") or {}).get("ticket", "")
        before = len(templates(PAD_USER))
        st, r = enroll(pad_ticket, PAD_PW)
        check("★ 活体模型不可用 ⇒ 503（fail closed，绝不放行）",
              st == 503 and r.get("code") == "FACEID_ENGINE_UNAVAILABLE",
              "%s %s" % (st, r.get("code")))
        check("pad_down：模板数不变", len(templates(PAD_USER)) == before,
              "now=%d" % len(templates(PAD_USER)))

    with backend("ok", "i_pad_off", {"AUTHBASELINE_FACEID_PAD_ENABLED": "false"}):
        st, r = login(PAD_USER, PAD_PW)
        pad_ticket = (r.get("data") or {}).get("ticket", "")
        st, r = enroll(pad_ticket, PAD_PW)
        check("对照组：关掉活体后能录入（证明拒绝来自 PAD 而不是别的原因）",
              st == 200 and len(templates(PAD_USER)) == 1,
              "%s %s" % (st, r.get("code")))

    # =====================================================================
    # J：纯人脸登录（P2）—— 签票 / 判错计次 / 未录入不计次
    # =====================================================================
    print("\n[J] 纯人脸登录：成功签票 / 判错计次 / 未录入不计次")
    LOGIN_USER = "faceidlogin"
    LOGIN_PW = "Faceidlogin123"

    with backend("ok", "j_login"):
        st, r = login("admin", ADMIN_PW)
        admin_ticket = (r.get("data") or {}).get("ticket", "")
        st, r = call("POST", "/api/auth/create-account", {
            "username": LOGIN_USER, "password": LOGIN_PW, "role": "User",
            "email": "", "operatorPassword": ADMIN_PW}, admin_ticket)
        check("建「未录入」账号（用于对照）", st == 200 and r.get("code") == "OK",
              "%s %s" % (st, r.get("code")))

        # PAD_USER 在 I 组的 pad_off 环节已经录过一张模板，这里直接拿它登。
        st, r = call("POST", "/api/faceid/login", {"username": PAD_USER})
        ticket = (r.get("data") or {}).get("ticket", "")
        check("★ 人脸登录成功并签发票据", st == 200 and bool(ticket),
              "%s %s" % (st, r.get("code")))
        st2, r2 = status(ticket)
        check("★ 签出的票据真的可用（status 200）", st2 == 200, str(st2))

        doc = [d for d in audit_docs("LOGIN_SUCCESS") if d.get("target") == PAD_USER]
        check("审计记 LOGIN_SUCCESS 且标明 SecondFactor=FACEID",
              any("FACEID" in str(d.get("response", "")) for d in doc),
              "n=%d" % len(doc))

        st, r = call("POST", "/api/faceid/login", {"username": LOGIN_USER})
        check("★ 未录入人脸 ⇒ 401 FACEID_NOT_ENROLLED（不是「人脸不像」）",
              st == 401 and r.get("code") == "FACEID_NOT_ENROLLED",
              "%s %s" % (st, r.get("code")))
        d2 = probe_db["Users"].find_one({"username": LOGIN_USER})
        check("未录入：不计次（failedAttempts=0）",
              (d2 or {}).get("failedLoginAttempts", 0) == 0,
              "failed=%s" % (d2 or {}).get("failedLoginAttempts"))

        st, r = call("POST", "/api/faceid/login", {"username": "nobody_here"})
        check("★ 不存在的账号 ⇒ 与「不匹配」同码（不给枚举额外信号）",
              st == 401 and r.get("code") == "FACEID_MISMATCH",
              "%s %s" % (st, r.get("code")))

    # 判错要用**另一个身份**的假引擎：默认 backend() 注入的 STUB_IDENTITY 就是 USER，
    # 同一个身份算出来的特征余弦恒为 1.0 —— 那样"判错"永远测不出来（会得到 200）。
    with backend("ok", "j_mismatch", {"AUTHBASELINE_FACEID_STUB_IDENTITY": "stranger-identity"}):
        mismatch_before = audit_reason_count("FACEID_MISMATCH")
        st, r = call("POST", "/api/faceid/login", {"username": PAD_USER})
        check("★ 人脸判错 ⇒ 401 FACEID_MISMATCH", st == 401 and r.get("code") == "FACEID_MISMATCH",
              "%s %s" % (st, r.get("code")))
        sim = (r.get("data") or {}).get("similarity")
        check("判错时回传相似度（便于用户判断是光线还是脸不对）",
              isinstance(sim, (int, float)), "sim=%s" % sim)

        d3 = probe_db["Users"].find_one({"username": PAD_USER})
        check("★ 判错计入失败窗口（failedAttempts=1）",
              (d3 or {}).get("failedLoginAttempts", 0) == 1,
              "failed=%s" % (d3 or {}).get("failedLoginAttempts"))
        check("审计记 FACEID_MISMATCH（本组恰好多 1 条）",
              audit_reason_count("FACEID_MISMATCH") == mismatch_before + 1,
              "n=%d→%d" % (mismatch_before, audit_reason_count("FACEID_MISMATCH")))

    # =====================================================================
    # 汇总
    # =====================================================================
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print("\n" + "=" * 70)
    print("汇总：%d/%d 通过" % (passed, total))
    for name, ok, detail in results:
        if not ok:
            print("  ✗ %s  -> %s" % (name, detail))
    print("=" * 70)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
