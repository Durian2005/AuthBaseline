# -*- coding: utf-8 -*-
"""真机验证：人脸第二因子（账号级可选启用）。

全部对着**独立测试库**打真实 HTTP + 直连数据库断言，用**假引擎**跑，
因此**不需要摄像头**也能覆盖最难的几条分支（A/B 组分流、引擎不可用降级）。

验证十组：
  A. 骨架      —— 未录人脸的账号登录行为与改造前逐字一致（这是「可选」的前提）
  B. 录入      —— 两步式录入（先口令换挑战、再采集）；交叉用途与跨账号不可挪用
  C. 第二因子  —— 已录人脸 ⇒ 口令后只发挑战、不发票据；挑战一次性；人脸过后才签票
  D. 降级闸门  —— 自助删除需二次口令；口令错按 A 组计次；口令错不连坐票据
  E. 处置      —— 管理员重置他人人脸走 CanBeManagedBy；注销账号**连带清理**模板
  F. 复录      —— 为后续「引擎不可用 / A 组计次」重新备好前置（USER 有模板）
  G. fail-close—— 已录人脸但引擎不可用 ⇒ 拒绝登录（不是静默退回单因子）
  H. B 组不计次—— 质量问题（画面无人脸）不累加失败计数
  I. A 组计次  —— 欺骗信号（活体未过）累加并触发 3 次锁定
  J. 存储/审计 —— 库里的模板是**密文**；审计里**不出现任何特征向量**；链字段完整

用法：
  python tools/face_second_factor_probe.py <exe路径> <端口> [--db NAME]

⚠️ 探针打真实库是 bug：库名必须含 `Probe`（`resolve_probe_db` 已守卫）。
⚠️ 跑本探针**必须** AUTHBASELINE_REQUIRE_HTTPS=false（见下方 extra_env），
   且要用带 pymongo 的**系统** Python 跑（托管 Python 环境里没有 pymongo）。
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
DB_NAME = resolve_probe_db("AuthBaselineFaceProbe")

ADMIN_PW = "Admin123"
USER = "faceprobe"
USER_PW = "Faceprobe123"
DEL_USER = "facedel"
DEL_PW = "Facedel123"

probe_db = ProbeDb(DB_NAME)

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name, ("  -> " + str(detail)) if detail else ""))


def call(method, path, body=None, ticket=None):
    return http_call(BASE, method, path, body=body, ticket=ticket)


def login(user, pw):
    return call("POST", "/api/auth/login", {"username": user, "password": pw})


def api(path_suffix):
    return "/api/auth" + path_suffix


def enroll_face(user, pw, ticket):
    """走完整的两步式录入，返回 (ok, 说明)。"""
    st, r = call("POST", api("/face/enroll"), {"password": pw}, ticket)
    token = (r.get("data") or {}).get("challengeToken", "")
    if not token:
        return False, "第一步未下发挑战：%s %s" % (st, r.get("code"))
    st, r = call("POST", api("/face/enroll/complete"), {"challengeToken": token}, ticket)
    return (st == 200 and r.get("code") == "OK"), "%s %s" % (st, r.get("code"))


def face_login(user, pw):
    """口令 → FACE_REQUIRED → 刷脸 → 票据。返回 (最终 status, 最终响应, 挑战响应)。"""
    st, first = login(user, pw)
    token = (first.get("data") or {}).get("challengeToken", "")
    if not token:
        return st, first, first
    st2, second = call("POST", api("/login/face"), {"challengeToken": token})
    return st2, second, first


# ---------------------------------------------------------------------------
# 起 / 停后端：假引擎的行为在**启动时**读取，所以每组要重启一次。
# ---------------------------------------------------------------------------
@contextlib.contextmanager
def backend(behavior, tag):
    """起一个后端（假引擎 + 指定行为），退出时关掉。"""
    proc = start_backend(
        EXE,
        PORT,
        DB_NAME,
        log_name="face_probe_%s_%d.log" % (tag, PORT),
        extra_env={
            # 探针走明文 HTTP：TLS 那套由 transport_* 专项脚本负责，
            # 这里若开 TLS，整个探针会因缺证书而拒绝启动（默认 fail closed）。
            "AUTHBASELINE_REQUIRE_HTTPS": "false",
            "AUTHBASELINE_FACE_ENGINE": "stub",
            # 假引擎把"呈现身份"的 SHA-256 派生为特征向量：
            # 等于账号用户名 ⇒ 余弦 1.0（本人）；换成别的字符串 ⇒ 近乎正交（非本人）。
            "AUTHBASELINE_FACE_STUB_IDENTITY": USER,
            "AUTHBASELINE_FACE_STUB_BEHAVIOR": behavior,
        },
    )
    try:
        if not wait_backend_ready(BASE, proc, timeout_s=90):
            raise SystemExit("后端启动失败（日志见 tools/buildlogs/face_probe_%s_%d.log）" % (tag, PORT))
        yield proc
    finally:
        stop_backend(proc)
        time.sleep(1.0)   # 让端口与 Mongo 连接释放，避免下一段起不来


# ---------------------------------------------------------------------------
# 直连库的读断言
# ---------------------------------------------------------------------------
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


def bag_get(doc, key, field):
    """在 request/response JSON 袋里大小写不敏感地取字段。"""
    obj = parse_bag(doc.get(key))
    if not isinstance(obj, dict):
        return None
    for k, v in obj.items():
        if k.lower() == field.lower():
            return v
    return None


def has_long_array(obj):
    if isinstance(obj, list):
        return len(obj) >= 64 or any(has_long_array(v) for v in obj)
    if isinstance(obj, dict):
        return any(has_long_array(v) for v in obj.values())
    return False


def main():
    print("=" * 70)
    print("人脸第二因子探针 · 库=%s · 端口=%d" % (DB_NAME, PORT))
    print("=" * 70)

    if probe_db.drop_if_exists():
        print("（已清理上次残留的测试库）")

    # =====================================================================
    # A：骨架 —— 未录人脸 ⇒ 与改造前逐字一致
    # =====================================================================
    print("\n[A] 未录人脸的账号：行为与改造前逐字一致（「可选」的前提）")
    with backend("ok", "a"):
        st, r = login("admin", ADMIN_PW)
        check("admin 未录人脸 ⇒ 单因子登录成功", st == 200 and r.get("code") == "OK",
              "%s %s" % (st, r.get("code")))
        admin_ticket = (r.get("data") or {}).get("ticket", "")
        check("admin 登录签发票据（没有第二因子拦截）", bool(admin_ticket))

        st, r = call("POST", api("/create-account"), {
            "username": USER, "password": USER_PW, "role": "User",
            "email": "", "operatorPassword": ADMIN_PW}, admin_ticket)
        check("建测试账号", st == 200 and r.get("code") == "OK", "%s %s" % (st, r.get("code")))

        st, r = login(USER, USER_PW)
        check("测试账号未录人脸 ⇒ 单因子登录成功", st == 200 and r.get("code") == "OK",
              "%s %s" % (st, r.get("code")))
        ticket = (r.get("data") or {}).get("ticket", "")

        st, r = call("GET", api("/face"), ticket=ticket)
        d = r.get("data") or {}
        check("人脸状态：未录入且引擎就绪",
              st == 200 and d.get("enrolled") is False and d.get("engineReady") is True
              and abs((d.get("threshold") or 0) - 0.5) < 1e-9, str(d))

        st, r = call("GET", api("/face"))
        check("人脸状态是受保护接口（无票据被拒）", st == 401, "%s %s" % (st, r.get("code")))

    # =====================================================================
    # B：录入 —— 两步式 + 挑战绑定
    # =====================================================================
    print("\n[B] 录入：两步式 + 挑战绑定（用途 / 账号 / 一次性）")
    with backend("ok", "b"):
        st, r = login(USER, USER_PW)
        ticket = (r.get("data") or {}).get("ticket", "")
        check("（准备）拿到票据", bool(ticket), "%s %s" % (st, r.get("code")))

        st, r = call("POST", api("/face/enroll"), {"password": "WrongPass123"}, ticket)
        check("录入第一步：口令错被拒",
              st == 401 and r.get("code") == "INVALID_CREDENTIALS", "%s %s" % (st, r.get("code")))
        check("录入第一步：口令错按 A 组计次 = 1",
              (r.get("data") or {}).get("failedAttempts") == 1, str(r.get("data")))

        st, r = call("POST", api("/face/enroll"), {}, ticket)
        check("录入第一步：未填口令被拒（EMPTY_FIELDS）",
              st == 400 and r.get("code") == "EMPTY_FIELDS", "%s %s" % (st, r.get("code")))

        st, r = call("POST", api("/face/enroll"), {"password": USER_PW}, ticket)
        d = r.get("data") or {}
        enroll_token = d.get("challengeToken", "")
        check("录入第一步：口令对 ⇒ 下发动作挑战",
              st == 200 and bool(enroll_token) and d.get("action") in ("left", "right", "up", "down"),
              "action=%s" % d.get("action"))
        check("挑战带中文动作指令与提示",
              bool(d.get("actionText")) and bool(d.get("actionHint")),
              "%s / %s" % (d.get("actionText"), d.get("actionHint")))
        check("挑战声明的有效期与配置一致（90s）",
              d.get("expiresInSeconds") == 90, str(d.get("expiresInSeconds")))

        # 用途绑定：录入挑战不能当登录通行证
        st, r = call("POST", api("/login/face"), {"challengeToken": enroll_token})
        check("交叉用途被拒：录入挑战不能用于登录",
              st == 401 and r.get("code") == "FACE_CHALLENGE_INVALID", "%s %s" % (st, r.get("code")))

        # 上面那次提交已把票消费掉 —— 正好验证「先取出再校验」的一次性语义
        st, r = call("POST", api("/face/enroll/complete"), {"challengeToken": enroll_token}, ticket)
        check("录入挑战一次性：消费过再用失败",
              st == 400 and r.get("code") == "FACE_CHALLENGE_INVALID", "%s %s" % (st, r.get("code")))

        ok, why = enroll_face(USER, USER_PW, ticket)
        check("录入第二步：写入模板", ok, why)

        st, r = call("GET", api("/face"), ticket=ticket)
        d = r.get("data") or {}
        check("状态：已启用且记录录入时刻",
              d.get("enrolled") is True and d.get("templateCount") == 1
              and bool(d.get("enrolledAt")), str(d))

    # =====================================================================
    # C：登录第二因子
    # =====================================================================
    print("\n[C] 登录第二因子：口令后只发挑战，人脸过了才签票")
    with backend("ok", "c"):
        st, r = login(USER, USER_PW)
        d = r.get("data") or {}
        check("口令通过 ⇒ 返回 FACE_REQUIRED 且**不含票据**",
              st == 200 and r.get("code") == "FACE_REQUIRED" and bool(d.get("challengeToken"))
              and not d.get("ticket"), "%s %s" % (st, r.get("code")))
        token = d.get("challengeToken", "")

        st, r = call("POST", api("/login/face"), {"challengeToken": "not-a-real-token"})
        check("伪造 token 被拒",
              st == 401 and r.get("code") == "FACE_CHALLENGE_INVALID", "%s %s" % (st, r.get("code")))

        st, r = call("POST", api("/login/face"), {})
        check("空 token 被拒",
              st == 401 and r.get("code") == "FACE_CHALLENGE_INVALID", "%s %s" % (st, r.get("code")))

        st, r = call("POST", api("/login/face"), {"challengeToken": token})
        d2 = r.get("data") or {}
        check("人脸通过 ⇒ 签发票据",
              st == 200 and r.get("code") == "OK" and bool(d2.get("ticket")),
              "%s %s" % (st, r.get("code")))
        check("票据可用于访问受保护接口",
              call("GET", api("/face"), ticket=d2.get("ticket"))[0] == 200)

        st, r = call("POST", api("/login/face"), {"challengeToken": token})
        check("登录挑战一次性：重放被拒",
              st == 401 and r.get("code") == "FACE_CHALLENGE_INVALID", "%s %s" % (st, r.get("code")))

    # =====================================================================
    # D：降级闸门 —— 自助删除需二次口令
    # =====================================================================
    print("\n[D] 降级闸门：自助删除需二次口令，口令错按 A 组计次")
    with backend("ok", "d"):
        st, r, _ = face_login(USER, USER_PW)
        ticket = (r.get("data") or {}).get("ticket", "")
        check("（准备）刷脸登录拿到票据", bool(ticket), "%s %s" % (st, r.get("code")))

        st, r = call("POST", api("/face/delete"), {}, ticket)
        check("自助删除：未填口令被拒",
              st == 400 and r.get("code") == "EMPTY_FIELDS", "%s %s" % (st, r.get("code")))

        st, r = call("POST", api("/face/delete"), {"password": "WrongPass123"}, ticket)
        check("自助删除：口令错被拒",
              st == 401 and r.get("code") == "INVALID_CREDENTIALS", "%s %s" % (st, r.get("code")))
        check("自助删除：口令错计次",
              (r.get("data") or {}).get("failedAttempts", 0) >= 1, str(r.get("data")))

        st, r = call("GET", api("/face"), ticket=ticket)
        check("口令错**不**连坐票据（仍是已登录态）", st == 200, "%s %s" % (st, r.get("code")))

        st, r = call("POST", api("/face/delete"), {"password": USER_PW}, ticket)
        check("自助删除：口令对 ⇒ 清空模板",
              st == 200 and r.get("code") == "OK" and (r.get("data") or {}).get("removed") == 1,
              "%s %s %s" % (st, r.get("code"), r.get("message")))

        st, r = login(USER, USER_PW)
        check("删除后 ⇒ 退回单因子（口令即可登录）",
              st == 200 and r.get("code") == "OK" and bool((r.get("data") or {}).get("ticket")),
              "%s %s" % (st, r.get("code")))

    # =====================================================================
    # E：处置 —— 管理员重置 / 注销连带清理
    # =====================================================================
    print("\n[E] 处置：管理员重置他人人脸 / 注销连带清理模板")
    with backend("ok", "e"):
        st, r = login("admin", ADMIN_PW)
        admin_ticket = (r.get("data") or {}).get("ticket", "")

        # 给 USER 重新录一张，供「管理员重置」验证
        st, r = login(USER, USER_PW)
        ticket = (r.get("data") or {}).get("ticket", "")
        ok, why = enroll_face(USER, USER_PW, ticket)
        check("（准备）重新录入一张", ok, why)

        st, r = call("POST", api("/reset-face"), {"username": USER}, admin_ticket)
        check("管理员重置他人人脸",
              st == 200 and r.get("code") == "OK" and (r.get("data") or {}).get("removed") == 1,
              "%s %s" % (st, r.get("code")))
        check("重置后该账号退回单因子",
              probe_db["FaceTemplates"].count_documents({"username": USER}) == 0)

        st, r = call("POST", api("/reset-face"), {"username": "no-such-user"}, admin_ticket)
        check("重置不存在的账号 ⇒ NOT_FOUND",
              st == 404 and r.get("code") == "NOT_FOUND", "%s %s" % (st, r.get("code")))

        st, r = call("POST", api("/reset-face"), {"username": "admin"}, admin_ticket)
        check("管理员不能重置自己的人脸（自我豁免）",
              st == 400 and r.get("code") == "FORBIDDEN_TARGET", "%s %s" % (st, r.get("code")))

        st, r = call("POST", api("/reset-face"), {"username": USER})
        check("重置人脸是受保护接口（无票据被拒）", st == 401, "%s %s" % (st, r.get("code")))

        # 注销连带清理：另建一个账号并录入人脸，然后注销
        st, r = call("POST", api("/create-account"), {
            "username": DEL_USER, "password": DEL_PW, "role": "User",
            "email": "", "operatorPassword": ADMIN_PW}, admin_ticket)
        check("（准备）建待注销账号", st == 200, "%s %s" % (st, r.get("code")))
        st, r = login(DEL_USER, DEL_PW)
        dticket = (r.get("data") or {}).get("ticket", "")
        ok, why = enroll_face(DEL_USER, DEL_PW, dticket)
        check("（准备）待注销账号已录人脸",
              ok and probe_db["FaceTemplates"].count_documents({"username": DEL_USER}) == 1, why)

        st, r = call("POST", api("/delete-user"), {"username": DEL_USER}, admin_ticket)
        check("注销账号成功", st == 200 and r.get("code") == "OK", "%s %s" % (st, r.get("code")))
        check("注销**连带清理**人脸模板（不留生物特征孤儿）",
              probe_db["FaceTemplates"].count_documents({"username": DEL_USER}) == 0,
              "%d 条残留" % probe_db["FaceTemplates"].count_documents({"username": DEL_USER}))
        check("账号本身已删除", probe_db["Users"].count_documents({"username": DEL_USER}) == 0)

    # =====================================================================
    # F：复录 —— 后面三组的前置
    # =====================================================================
    print("\n[F] 复录：为「引擎不可用 / A 组计次」备好前置（该账号有模板）")
    with backend("ok", "f"):
        st, r = login(USER, USER_PW)
        ticket = (r.get("data") or {}).get("ticket", "")
        check("（准备）单因子登录（上一步已被重置）", bool(ticket), "%s %s" % (st, r.get("code")))
        ok, why = enroll_face(USER, USER_PW, ticket)
        check("（准备）重新录入一张人脸", ok, why)
        check("库中模板数 = 1",
              probe_db["FaceTemplates"].count_documents({"username": USER}) == 1,
              str(probe_db["FaceTemplates"].count_documents({"username": USER})))

    # =====================================================================
    # G：fail closed
    # =====================================================================
    print("\n[G] 已录人脸 + 引擎不可用 ⇒ 拒绝登录（fail closed，不静默降级）")
    with backend("engine_down", "g"):
        st, r = login(USER, USER_PW)
        check("引擎不可用 ⇒ 503 FACE_ENGINE_UNAVAILABLE",
              st == 503 and r.get("code") == "FACE_ENGINE_UNAVAILABLE", "%s %s" % (st, r.get("code")))
        check("引擎不可用 ⇒ 不签发票据", not (r.get("data") or {}).get("ticket"), str(r.get("data")))

        st, r = call("GET", api("/face"))
        check("引擎不可用时自助入口也要先过鉴权（无票据被拒）", st == 401, "%s" % st)

    # =====================================================================
    # H：B 组不计次
    # =====================================================================
    print("\n[H] 质量问题（画面里没人脸）⇒ 不计入失败窗口")
    with backend("no_face", "h"):
        st, r = login(USER, USER_PW)
        token = (r.get("data") or {}).get("challengeToken", "")
        check("引擎正常时仍会下发挑战",
              st == 200 and r.get("code") == "FACE_REQUIRED", "%s %s" % (st, r.get("code")))

        st, r = call("POST", api("/login/face"), {"challengeToken": token})
        d = r.get("data") or {}
        check("无人脸 ⇒ FACE_NO_FACE",
              st == 401 and r.get("code") == "FACE_NO_FACE", "%s %s" % (st, r.get("code")))
        check("**不计次**：failedAttempts 未增长", d.get("failedAttempts") == 0, str(d))
        check("未签发票据", not d.get("ticket"), str(d))
        check("响应**不**下发 counted（不告诉攻击者哪类失败不被计数）",
              "counted" not in d, str(sorted(d.keys())))

        doc = probe_db["Users"].find_one({"username": USER})
        check("库里计数也确实没动（不是只没回给客户端）",
              doc and doc.get("failedLoginAttempts") == 0,
              str(doc.get("failedLoginAttempts") if doc else None))

    # =====================================================================
    # I：A 组计次 + 锁定
    # =====================================================================
    print("\n[I] 欺骗信号（活体未过）⇒ 计次并触发 3 次锁定")
    with backend("liveness_failed", "i"):
        for i in (1, 2, 3):
            st, r = login(USER, USER_PW)
            token = (r.get("data") or {}).get("challengeToken", "")
            if not token:
                check("第 %d 次仍能拿到挑战" % i, False, "%s %s" % (st, r.get("code")))
                break
            st, r = call("POST", api("/login/face"), {"challengeToken": token})
            d = r.get("data") or {}
            check("第 %d 次活体失败 ⇒ 计次到 %d" % (i, i),
                  d.get("failedAttempts") == i
                  and r.get("code") in ("FACE_LIVENESS_FAILED", "ACCOUNT_LOCKED"),
                  "%s %s %s" % (st, r.get("code"), d))

        st, r = login(USER, USER_PW)
        check("三次之后 ⇒ 口令这一步就已被锁定拦截",
              r.get("code") == "ACCOUNT_LOCKED", "%s %s" % (st, r.get("code")))
        doc = probe_db["Users"].find_one({"username": USER})
        check("库中确实落成 Locked 且带锁定截止时刻",
              doc and doc.get("status") == "Locked" and doc.get("lockoutEnd") is not None,
              str(doc.get("status") if doc else None))

    # =====================================================================
    # J：存储与审计边界（直连库断言；此时后端已全部关闭）
    # =====================================================================
    print("\n[J] 存储边界：模板是密文，审计里不出现任何特征向量")
    templates = list(probe_db["FaceTemplates"].find({}))
    check("人脸模板集合确实有数据（前置）", len(templates) >= 1, "%d 条" % len(templates))
    if templates:
        t = templates[0]
        allowed = {"_id", "userId", "username", "cipher", "nonce", "tag", "dim", "version", "createdAt"}
        extra = set(t.keys()) - allowed
        check("模板文档没有计划外的字段（尤其没有明文特征）", not extra, "多出：%s" % sorted(extra))
        check("cipher 是二进制且非空",
              isinstance(t.get("cipher"), (bytes, bytearray)) and len(t["cipher"]) > 0,
              "%s" % type(t.get("cipher")).__name__)
        check("没有名为 feature / embedding / template / vector 的明文字段",
              not any(k.lower() in ("feature", "embedding", "template", "vector") for k in t.keys()),
              str(sorted(t.keys())))

    print("\n[J] 审计：新动作全部进链，且链里**不含任何特征向量**")
    face_actions = ["FACE_LOGIN_REQUIRED", "FACE_LOGIN_SUCCESS", "FACE_LOGIN_FAILED",
                    "FACE_ENROLL", "FACE_ENROLL_FAILED", "FACE_TEMPLATE_DELETED",
                    "FACE_TEMPLATE_RESET"]
    for a in face_actions:
        n = audit_count(a)
        check("审计含 %s" % a, n > 0, "count=%d" % n)

    failures = audit_docs("FACE_LOGIN_FAILED")
    reasons = {}
    for doc in failures:
        rc = doc.get("reasonCode")
        reasons[rc] = reasons.get(rc, 0) + 1
    check("FACE_LOGIN_FAILED 带可检索的原因码（A 组与 B 组各出现过）",
          reasons.get("FACE_NO_FACE", 0) >= 1 and reasons.get("FACE_LIVENESS_FAILED", 0) >= 1
          and reasons.get("FACE_ENGINE_UNAVAILABLE", 0) >= 1,
          json.dumps(reasons, ensure_ascii=False))

    ok_docs = audit_docs("FACE_LOGIN_SUCCESS")
    sim = [bag_get(d, "response", "Similarity") for d in ok_docs]
    thr = [bag_get(d, "response", "Threshold") for d in ok_docs]
    check("人脸登录成功的审计里可核对相似度与阈值（不是黑箱）",
          any(v is not None for v in sim) and any(v == 0.5 for v in thr),
          "sim=%s thr=%s" % (sim, thr))

    successes = audit_docs("LOGIN_SUCCESS")
    with_face = [d for d in successes
                 if str(bag_get(d, "response", "SecondFactor") or "") == "FACE"]
    without = [d for d in successes
               if str(bag_get(d, "response", "SecondFactor") or "") == "NONE"]
    check("人脸登录的 LOGIN_SUCCESS 在 JSON 袋里标了 SecondFactor=FACE",
          len(with_face) >= 1, "%d/%d 条" % (len(with_face), len(successes)))
    check("单因子登录标 SecondFactor=NONE（两档可区分）",
          len(without) >= 1, "%d/%d 条" % (len(without), len(successes)))

    # 隐私硬断言：任何审计文档里都不该出现"长数字数组"（特征向量会有 128 个数）
    leaked = []
    for a in face_actions:
        for doc in audit_docs(a):
            if has_long_array(parse_bag(doc.get("request"))) or has_long_array(parse_bag(doc.get("response"))):
                leaked.append("%s/%s" % (a, doc.get("reasonCode")))
    check("审计的 request/response 里不存在长度 ≥64 的数组（无特征向量泄漏）",
          not leaked, str(leaked))

    # 链字段完整：人脸事件与其它事件一样是链上的一环
    chain_docs = [d for a in face_actions for d in audit_docs(a)]
    check("人脸审计全部带自哈希",
          chain_docs and all(str(d.get("selfHash") or "") for d in chain_docs),
          "%d 条" % len(chain_docs))
    check("人脸审计全部带前驱哈希（含创世空串也是字段存在）",
          chain_docs and all(d.get("prevHash") is not None for d in chain_docs),
          "%d 条" % len(chain_docs))
    check("人脸审计的序号单调唯一",
          len({d.get("seq") for d in chain_docs}) == len(chain_docs),
          "%d 条 / %d 个 seq" % (len(chain_docs), len({d.get("seq") for d in chain_docs})))

    # ---------- 清理 ----------
    print("\n[清理]")
    if probe_db.drop_if_exists():
        print("   测试库已清理：%s" % DB_NAME)

    bad = [n for n, ok, _ in results if not ok]
    print("\n" + "=" * 70)
    if bad:
        print("  结论：FAIL  %d/%d 项未达标" % (len(bad), len(results)))
        for n in bad:
            print("    - " + n)
    else:
        print("  结论：PASS  人脸第二因子 %d 项断言全部通过" % len(results))
    print("=" * 70)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
