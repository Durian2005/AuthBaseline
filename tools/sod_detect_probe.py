# -*- coding: utf-8 -*-
"""职责分离（SoD）绕过检测层 —— 端到端探针。

用法：
  python tools/sod_detect_probe.py <exe路径> <端口> [--keep]

它验证的是这样一件事：
  **管理员造出来的审计管理员，读审计这件事必须能被系统自己识别成"可归因于造号者"。**

在此之前，这条绕过路径只有"库里有几条原始记录"——CREATE_ACCOUNT、
LOGIN_SUCCESS、AUDIT_QUERY 分属三条记录，没有任何机制把它们串起来。
现在 `GET /api/audit/sod` 输出归因链，本探针验证这条链是真的、且与直接查库
独立复算的结果**逐条一致**。

覆盖矩阵：
  [2] 造两个审计管理员（一个会用、一个不会用）
  [3] 用第一个登录并读一次审计
  [4] 检测接口：ATTRIBUTED / DORMANT 两种结论都对，批量授予人被标出
  [5] 检测动作自身留痕（SOD_SCAN）—— 查过没查过必须可证明
  [6] 管理员打不了这个接口（403 + AUDIT_ACCESS_DENIED 留痕）
  [7] 该账号自助改密（封口）
  [8] 封口后：历史读取仍归因（SEALED），封口后的读取单独计数
  [9] 与 tools/sod_trace.py 的独立复算逐链对账（不信任被测系统）
  [10] 加了这一切之后，审计哈希链依然完整

⚠️ 探针只碰自己的 Probe 库（resolve_probe_db + ProbeDb 双守卫）。
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 探针一律明文 HTTP：桌面端默认强制 HTTPS，证书不可用会直接拒绝启动。
os.environ.setdefault("AUTHBASELINE_REQUIRE_HTTPS", "false")

from _probe_common import (  # noqa: E402
    ProbeDb, http_call, mongo_client, resolve_probe_db, start_backend,
)
import sod_trace  # noqa: E402  独立复算：同一套规则的另一份实现

EXE = sys.argv[1]
PORT = int(sys.argv[2])
DB = resolve_probe_db("AuthBaselineSodProbe")
BASE = "http://127.0.0.1:%d" % PORT
KEEP = "--keep" in sys.argv

PUPPET = "s_sod_puppet"   # 会被拿去读审计的那个"傀儡"审计管理员
NEVER = "s_sod_never"     # 造出来但从不登录、不读审计
PWD1 = "Puppet123"
PWD2 = "Puppet9x8"

print("exe    :", EXE)
print("端口   :", PORT)
print("测试库 :", DB)

probe_db = ProbeDb(DB)
if probe_db.drop_if_exists():
    print("已清理旧测试库")

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    mark = "OK  " if cond else "FAIL"
    print("  [%s] %s%s" % (mark, name, ("  — " + str(detail)) if detail else ""))


def call(method, path, body=None, ticket=None, timeout=90):
    return http_call(BASE, method, path, body=body, ticket=ticket, timeout=timeout)


def login(username, password):
    st, b = call("POST", "/api/auth/login", {"username": username, "password": password})
    data = b.get("data") or {}
    return st, data.get("ticket"), data


def chains_of(b):
    return (b.get("data") or {}).get("chains") or []


def pick_chains(b):
    return {c.get("auditor"): c for c in chains_of(b)}


logf = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "sod_detect_probe.log"), "w", encoding="utf-8")


def log(msg):
    logf.write(msg + "\n")
    logf.flush()


# ---------- [1] 启动 ----------
print("\n[1] 启动后端（全新库，自动播种 admin/Admin123）...")
proc = start_backend(EXE, PORT, DB)
ready = False
for _ in range(60):
    st, _ = call("GET", "/")
    if st != 0:
        ready = True
        break
    time.sleep(0.5)
if not ready:
    print("  !! 60 秒未就绪，放弃")
    proc.kill()
    sys.exit(1)
print("  就绪 (PID=%d)" % proc.pid)

# ---------- [2] 造两个审计管理员 ----------
print("\n[2] Admin 造两个审计管理员（这是规则允许的分工，不是漏洞）")
st, admin_tk, admin_info = login("admin", "Admin123")
check("admin 登录成功", st == 200 and bool(admin_tk), "HTTP %s" % st)

for name, pwd in ((PUPPET, PWD1), (NEVER, "Never1234")):
    st, b = call("POST", "/api/auth/create-account",
                 {"username": name, "password": pwd, "role": "AuditAdmin",
                  "operatorPassword": "Admin123"}, ticket=admin_tk)
    check("创建审计管理员 %s → 成功" % name, st == 200, "HTTP %s / %s" % (st, b.get("code")))
    check("  %s 角色 = AuditAdmin" % name, (b.get("data") or {}).get("role") == "AuditAdmin")

# ---------- [3] 傀儡登录并读一次审计 ----------
print("\n[3] %s 登录并读一次审计（模拟'借他人身份读日志'）" % PUPPET)
st, puppet_tk, puppet_info = login(PUPPET, PWD1)
check("%s 登录成功（口令是 admin 造号时设定的）" % PUPPET, st == 200 and bool(puppet_tk), "HTTP %s" % st)
check("  角色 = AuditAdmin（能看审计）", puppet_info.get("role") == "AuditAdmin")

st, b = call("GET", "/api/audit/logs", ticket=puppet_tk)
check("  读审计日志 → 允许", st == 200, "HTTP %s" % st)

# ---------- [4] 检测接口 ----------
print("\n[4] GET /api/audit/sod：检测层必须把这条链识别出来")
st, sod1 = call("GET", "/api/audit/sod", ticket=puppet_tk)
check("检测接口可用（仅 AuditRead）", st == 200, "HTTP %s / %s" % (st, sod1.get("code")))
d1 = sod1.get("data") or {}
by1 = pick_chains(sod1)
check("产出 2 条归因链", len(by1) == 2, list(by1.keys()))

c1 = by1.get(PUPPET) or {}
check("  [%s] 判定 = 可归因（ATTRIBUTED）" % PUPPET, c1.get("risk") == "ATTRIBUTED", c1.get("risk"))
check("  授予人 = admin", c1.get("granter") == "admin", c1.get("granter"))
check("  授予方式 = create", c1.get("grantKind") == "create", c1.get("grantKind"))
check("  归因读取 ≥ 1 次", (c1.get("attributedReads") or 0) >= 1, c1.get("attributedReads"))
check("  尚未封口（sealedAt 为空）", not c1.get("sealedAt"), c1.get("sealedAt"))
check("  已记录首次登录时间", bool(c1.get("firstLoginAt")), c1.get("firstLoginAt"))
check("  证据序号 ≥ 3 条（授予/登录/读取）",
      len(c1.get("evidenceSeqs") or []) >= 3, c1.get("evidenceSeqs"))

c2 = by1.get(NEVER) or {}
check("  [%s] 判定 = 造号未使用（DORMANT）" % NEVER, c2.get("risk") == "DORMANT", c2.get("risk"))
check("  归因读取 = 0", (c2.get("attributedReads") or 0) == 0, c2.get("attributedReads"))

check("汇总：可归因 1 条 / 已封口 0 条 / 未使用 1 条",
      (d1.get("attributed"), d1.get("sealed"), d1.get("dormant")) == (1, 0, 1),
      (d1.get("attributed"), d1.get("sealed"), d1.get("dormant")))
check("批量授予人被标出：admin", (d1.get("batchGranters") or []) == ["admin"],
      d1.get("batchGranters"))

# scanned 是"本次调用加载到的事件数"；比对库里此刻的条数（本次调用之后会多 1 条 SOD_SCAN）
db_total = sum(probe_db[n].count_documents({})
               for n in probe_db.list_collection_names() if n.startswith("AuditLogs"))
check("事件总数与库内一致（允许差 1 条 = 本次扫描自身留痕）",
      db_total in (d1.get("scanned"), d1.get("scanned") + 1),
      "接口 %s / 库 %s" % (d1.get("scanned"), db_total))

# ---------- [5] 检测动作自身留痕 ----------
print("\n[5] 检测动作自身留痕（SOD_SCAN）")
scans = []
for n in probe_db.list_collection_names():
    if n.startswith("AuditLogs"):
        scans.extend(probe_db[n].find({"action": "SOD_SCAN"}))
check("库里存在 SOD_SCAN 事件", len(scans) >= 1, len(scans))
check("  操作者 = %s" % PUPPET, all(s.get("operatorName") == PUPPET for s in scans),
      [s.get("operatorName") for s in scans])
check("  statusAfter 标为 ATTRIBUTED（本次确有问题链）",
      scans and scans[-1].get("statusAfter") == "ATTRIBUTED",
      scans[-1].get("statusAfter") if scans else None)

# ---------- [6] 管理员打不了这个接口 ----------
print("\n[6] Admin 打同一个接口 → 拒绝，且拒绝本身留痕")
st, b = call("GET", "/api/audit/sod", ticket=admin_tk)
check("admin 访问 /api/audit/sod → 403 NOT_AUDIT_ADMIN",
      st == 403 and b.get("code") == "NOT_AUDIT_ADMIN", "HTTP %s / %s" % (st, b.get("code")))

denied = []
for n in probe_db.list_collection_names():
    if n.startswith("AuditLogs"):
        denied.extend(probe_db[n].find({"action": "AUDIT_ACCESS_DENIED", "target": "audit/sod"}))
check("库里存在 AUDIT_ACCESS_DENIED(target=audit/sod)", len(denied) >= 1, len(denied))
check("  拒绝记录指向 admin", bool(denied) and denied[-1].get("operatorName") == "admin",
      denied[-1].get("operatorName") if denied else None)

# ---------- [7] 傀儡自助改密（封口） ----------
print("\n[7] %s 自助改密 → 链应封口" % PUPPET)
st, b = call("POST", "/api/auth/change-password",
             {"username": PUPPET, "oldPassword": PWD1, "newPassword": PWD2},
             ticket=puppet_tk)
check("自助改密成功", st == 200, "HTTP %s / %s" % (st, b.get("code")))

st, _ = call("GET", "/api/audit/logs", ticket=puppet_tk)
check("改密后旧票据失效", st == 401, "HTTP %s" % st)

st, puppet_tk2, _ = login(PUPPET, PWD2)
check("用新口令重新登录成功", st == 200 and bool(puppet_tk2), "HTTP %s" % st)

# ---------- [8] 封口后的判定 ----------
print("\n[8] 封口后再读一次审计：历史读取仍归因，新读取单独计数")
st, _ = call("GET", "/api/audit/logs", ticket=puppet_tk2)
check("封口后读审计 → 允许", st == 200, "HTTP %s" % st)

st, sod2 = call("GET", "/api/audit/sod", ticket=puppet_tk2)
check("检测接口再次可用", st == 200, "HTTP %s" % st)
by2 = pick_chains(sod2)
c3 = by2.get(PUPPET) or {}
check("  [%s] 判定 = 已封口（SEALED）" % PUPPET, c3.get("risk") == "SEALED", c3.get("risk"))
check("  sealedAt 已记录", bool(c3.get("sealedAt")), c3.get("sealedAt"))
check("  封口前归因读取次数不变",
      c3.get("attributedReads") == c1.get("attributedReads"),
      "%s → %s" % (c1.get("attributedReads"), c3.get("attributedReads")))
check("  封口后读取 ≥ 1 次且单独计数", (c3.get("postSealReads") or 0) >= 1, c3.get("postSealReads"))

d2 = sod2.get("data") or {}
check("汇总：已封口 1 条", d2.get("sealed") == 1, d2.get("sealed"))

# ---------- [9] 独立复算对账 ----------
print("\n[9] 与 tools/sod_trace.py 独立复算逐链对账（不信任被测系统）")
conn = mongo_client()
try:
    docs = sod_trace.load_events(conn, DB)
finally:
    conn.close()

py = sod_trace.analyze(docs)
st, sod3 = call("GET", "/api/audit/sod", ticket=puppet_tk2)
api = sod3.get("data") or {}

check("事件总数一致（离线 %d / 接口 %d）" % (len(docs), api.get("scanned")),
      py["scanned"] == api.get("scanned"), (py["scanned"], api.get("scanned")))

py_map = {c["auditor"]: c for c in py["chains"]}
api_map = pick_chains(sod3)
check("链数量一致", len(py_map) == len(api_map), (len(py_map), len(api_map)))
for name in (PUPPET, NEVER):
    p, a = py_map.get(name) or {}, api_map.get(name) or {}
    check("  [%s] 判定一致（离线 %s / 接口 %s）" % (name, p.get("risk"), a.get("risk")),
          p.get("risk") == a.get("risk"))
    check("  [%s] 归因读取一致（%s / %s）" % (name, p.get("attributedReads"), a.get("attributedReads")),
          p.get("attributedReads") == a.get("attributedReads"))
    check("  [%s] 封口后读取一致（%s / %s）" % (name, p.get("postSealReads"), a.get("postSealReads")),
          p.get("postSealReads") == a.get("postSealReads"))
    check("  [%s] 授予人一致（%s）" % (name, p.get("granter")),
          p.get("granter") == a.get("granter"))

check("批量授予人一致", (py["batchGranters"] or []) == (api.get("batchGranters") or []),
      (py["batchGranters"], api.get("batchGranters")))

# ---------- [10] 审计链完整性未被破坏 ----------
print("\n[10] 加了检测层之后，审计哈希链依然完整")
st, b = call("GET", "/api/audit/verify", ticket=puppet_tk2)
check("完整性校验 → 未发现断点", st == 200 and (b.get("data") or {}).get("intact") is True,
      "HTTP %s / intact=%s" % (st, (b.get("data") or {}).get("intact")))

# ---------- 收尾 ----------
proc.kill()
proc.wait(timeout=10)
try:
    logf.close()
except Exception:
    pass

print("\n" + "=" * 64)
print("  通过 %d 项，失败 %d 项" % (len(PASSED), len(FAILED)))
if FAILED:
    print("  失败清单：")
    for f in FAILED:
        print("    -", f)
print("  结论：%s" % ("PASS ✅ 职责分离绕过可被检测" if not FAILED else "FAIL ❌"))

if FAILED or KEEP:
    print("  测试库保留：%s（%s）" % (DB, "有失败项，留现场排查" if FAILED else "--keep 指定"))
else:
    probe_db.drop()
    print("  测试库已清理：%s" % DB)
print("=" * 64)
sys.exit(1 if FAILED else 0)
