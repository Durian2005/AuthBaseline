# -*- coding: utf-8 -*-
"""实验：账号锁定能否靠"把本机时钟往前拨"解开 —— 以及加固之后还剩哪些边界。

═══ 这个脚本现在要证明三件事 ═══

【A】原始结论（仍然成立，保留全部证据链）
    锁定判定式原先为 `LockoutEnd > DateTime.UtcNow`，两个操作数都受墙钟控制：
      · 第 707~713 行  连续错 3 次 → Status=Locked，LockoutEnd = UtcNow + 3min
      · 第 664 行      `Status==Locked && LockoutEnd > UtcNow` → 拒绝
      · 第 680 行      一旦 `LockoutEnd <= UtcNow` → 自动恢复 Enabled 并清零计数
    而后端是 sidecar，与客户端**同机**运行 —— 改本机时钟就等于改服务端时钟。
    因此"拨快 3 分钟即可解锁"在加固前是成立的。

    本脚本**不去修改系统时间**：那需要管理员权限（SeSystemtimePrivilege），
    且会影响整机证书校验 / 其它进程 / 日志，代价与风险都不成比例。
    改用**判定式等价**复现："`LockoutEnd > now` 为假"既可由 "now 变大"（改时钟）
    达成，也可由 "LockoutEnd 变小"（改库）达成，两者在判定式上不可区分。

【B】加固后的行为与实际边界（本次新增）
    锁定现在同时记录**两个锚点**：墙钟（lockoutWallAt）与系统运行时长（lockoutUptimeAt，
    Environment.TickCount64）。判定时若两条线背离超过容差，以单调线为准 ——
    于是"拨钟"这条最廉价的路径被堵死，且动过时钟这件事本身会留下审计记录。

    演示"拨钟"用的不是系统时钟，而是后端提供的演示开关
    `AUTH_TIME_SKEW_SECONDS`（默认关闭）：它只影响锁定判定所看到的墙钟，
    不碰审计时间戳、不需要提权。所以本脚本能在**不动系统时间**的前提下，
    端到端验证"墙钟被拨快 600 秒 / 回拨 3600 秒"时锁定的真实表现。

    边界同样写成断言，不藏着 —— 验收被问到可以直接跑出来看：
      · 重启电脑后运行时长归零 ⇒ 退回墙钟判定 ⇒ 拨钟仍可解锁（断言 11 显式验证）
      · 直接改库把 lockoutEnd 搬到过去 ⇒ 不受本加固影响（场景 B 已验证）
    这两条都不影响"改时钟不再能提前结束锁定"这个结论，但口径必须说清楚。

【C】失败计数窗口（本次新增）
    计数不再是"终身累计"，而是只统计**一个 3 分钟窗口内**的失败：
    从第一次失败起算，窗口内累计到 3 次即锁；窗口一过，旧计数作废、重新从 1 数起。
    于是"慢慢试"试不出锁定，而连续爆破的判定结果不变。

    窗口的"过期了没有"**同样**走单调线（TimeGuard.WindowExpired），这不是洁癖：
    窗口过期 = 计数清零 = 重新拿回 3 次机会，是对攻击者有利的方向。
    若按墙钟判，攻击者每次错 2 次就把时钟拨快 3 分钟即可让窗口作废、永不锁定 ——
    比"没有窗口"的现状更糟。断言 14 就是把这条堵死方式端到端跑一遍。

    窗口过期后的行为用"把两个锚点一起搬到 4 分钟前"来复现（等价于真实的 3 分钟已过），
    同样不动系统时间。

    拨钟在**未锁定阶段**也要留痕（断言 16）：
    留痕原先只挂在"账号已锁定、请求被拒"那条分支上 ——
    而那条分支要求账号已经是 Locked，于是攻击者在 3 次尝试**之内**拨钟，
    事后翻审计看不到任何记录。现在失败计数判定顺带核对一次锚点，把这段静默期补上。

    注意它**只留痕、不改判定**：拨钟既不加罚（不提前锁定）、也不放过
    （拿不到额外机会）。取证与裁决分开 —— 能拨钟的人本来就持有管理员权限，
    给他加罚只会误伤普通人。

用法：
  python tools/lockout_clock_probe.py <exe路径> <端口> [测试库名] [--keep]
"""
import ctypes
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

# 公共探针基础层：库名守卫 + 代理绕过 + 后端启动。
# 改造前的 `sys.argv[3] if ...` 无白名单校验 —— 传参错位就会把真实库名喂给
# drop_database()（10-05 事故形态）。现在统一走 resolve_probe_db()。
from _probe_common import (
    ProbeDb,
    resolve_probe_db,
    start_backend as _common_start_backend,
    http_call,
)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

EXE = sys.argv[1]
PORT = int(sys.argv[2])
DB = resolve_probe_db("AuthBaselineLockProbe")
BASE = "http://127.0.0.1:%d" % PORT
KEEP = "--keep" in sys.argv

VICTIM = "victim01"          # 被锁的靶子账号（跑完即随测试库删除）
VICTIM_PW = "Victim12345"
ADMIN_PW = "Admin123"        # 全新库启动时自动播种的 admin

# 靶子账号建为 UserAdmin 而不是 User：create-account 只允许管理员创建
# 管理员类角色（User 走自助注册），而锁定策略对四种角色一视同仁，
# 用哪个角色做靶子不影响本实验结论。
VICTIM_ROLE = "UserAdmin"

LOCK_MINUTES = 3             # 与后端 LockoutDuration 保持一致，用于断言比对
MAX_ATTEMPTS = 3             # 与后端 MaxFailedAttempts 保持一致

# 演示开关：只改"锁定判定看到的墙钟"，不动系统时间，也不影响审计时间戳
SKEW_ENV = "AUTH_TIME_SKEW_SECONDS"
FORWARD_SKEW = 600           # 前拨 10 分钟（远超 3 分钟锁定）
BACKWARD_SKEW = -3600        # 回拨 1 小时

print("exe    :", EXE)
print("端口   :", PORT)
print("测试库 :", DB, "（全新库起步，跑完即清）")

_k32 = ctypes.windll.kernel32
_k32.GetTickCount64.restype = ctypes.c_ulonglong


def uptime_ms():
    """系统运行时长（毫秒）—— 与后端 Environment.TickCount64 同一来源。"""
    return int(_k32.GetTickCount64())


# 受守卫的测试库句柄：破坏性操作只能经它执行。
probe_db = ProbeDb(DB)
if probe_db.drop_if_exists():
    print("已清理旧测试库")
db = probe_db

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print("  [%s] %s%s" % ("OK  " if cond else "FAIL", name, ("  — " + str(detail)) if detail else ""))


def call(method, path, body=None, ticket=None, timeout=60):
    return http_call(BASE, method, path, body=body, ticket=ticket, timeout=timeout)


def login(password, username=VICTIM):
    return call("POST", "/api/auth/login", {"username": username, "password": password})


def admin_login():
    st, b = call("POST", "/api/auth/login", {"username": "admin", "password": ADMIN_PW})
    return (b.get("data") or {}).get("ticket")


def utc_now():
    return datetime.now(timezone.utc)


def naive(dt):
    """统一成 naive UTC，便于与库里读出的 BSON 时间直接比较。"""
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def shards():
    return [n for n in db.list_collection_names() if n.startswith("AuditLogs")]


def user_doc():
    return db["Users"].find_one({"username": VICTIM}) or {}


def audit_count(action, reason=None):
    q = {"action": action}
    if reason:
        q["reasonCode"] = reason
    return sum(db[n].count_documents(q) for n in shards())


def latest_audit(action):
    rows = []
    for n in shards():
        rows += list(db[n].find({"action": action}).sort("seq", -1).limit(1))
    rows.sort(key=lambda d: d.get("seq") or 0)
    return rows[-1] if rows else None


def force_lockout(seconds_from_now):
    """把 lockoutEnd 直接搬到指定位置。

    注意这一步的语义：**它就是"时钟前移/回拨"的等价物**。
    把 lockoutEnd 放到过去 = 时钟已经走过终点；
    把 lockoutEnd 放到 30 分钟后 = 时钟被拨回了 30 分钟。
    """
    target = utc_now() + timedelta(seconds=seconds_from_now)
    db["Users"].update_one({"username": VICTIM}, {"$set": {"lockoutEnd": target}})
    return target


def wrong_three_times():
    """连续输错 3 次口令，触发锁定。返回第 3 次的响应体。"""
    last = {}
    for _ in range(MAX_ATTEMPTS):
        st, last = login("definitelyWrong9")
    return last


# ---------- 后端起停（加固后的场景需要在不同"墙钟偏移"下各跑一轮） ----------

LOG = os.path.join(tempfile.gettempdir(), "lock_probe_%d.log" % PORT)
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "buildlogs")
if os.path.exists(LOG):
    os.remove(LOG)


def launch_backend(skew_seconds=None):
    """起后端。skew_seconds 非 None 时通过演示开关给"锁定判定看到的墙钟"加偏移。

    库名注入与日志重定向统一由 _probe_common.start_backend 负责 ——
    它与探针的 pymongo 用的是**同一个库**（这是 10-05 事故的结构性修复）。
    本函数只叠加"时钟偏移"这一个专属环境变量。
    函数名刻意不叫 start_backend：避免遮蔽公共层的同名函数。
    """
    extra = {}
    if skew_seconds is not None:
        extra[SKEW_ENV] = str(skew_seconds)
    # 每次启动用独立日志，便于事后回看每一次启动的失败原因。
    proc = _common_start_backend(EXE, PORT, DB, extra_env=extra,
                                 log_dir=LOG_DIR,
                                 log_name="lock_probe_%d.log" % PORT)
    for _ in range(80):
        st, _ = call("GET", "/")
        if st != 0:
            return proc
        time.sleep(0.5)
    print("  !! 未就绪，日志尾部：")
    proc.kill()
    try:
        logpath = os.path.join(LOG_DIR, "lock_probe_%d.log" % PORT)
        tail = open(logpath, encoding="utf-8", errors="replace").read()[-1500:]
        print(tail)
    except Exception:
        pass
    sys.exit(1)


def restart(skew_seconds=None):
    """停掉当前后端并以新的墙钟偏移重启，返回 (proc, ticket)。

    日志文件句柄由 _probe_common 持有，本脚本不再需要自己管 ——
    每次启动写同一个 buildlogs/lock_probe_<port>.log。
    """
    global _proc
    try:
        _proc.kill()
        _proc.wait(timeout=10)
    except Exception:
        pass
    time.sleep(0.8)                      # 让监听端口彻底释放
    _proc = launch_backend(skew_seconds)
    label = "墙钟偏移 %+d 秒" % skew_seconds if skew_seconds is not None else "墙钟正常"
    print("    后端已重启（%s, PID=%d）" % (label, _proc.pid))
    return _proc, admin_login()


# ---------- 启动 ----------
print("\n[1] 启动后端（全新测试库，自动播种 admin）...")
_proc = launch_backend(None)
print("  就绪 (PID=%d)" % _proc.pid)

admin_tk = admin_login()
if not admin_tk:
    print("  !! admin 登录失败，中止")
    _proc.kill()
    sys.exit(2)

st, b = call("POST", "/api/auth/create-account",
             {"username": VICTIM, "password": VICTIM_PW, "role": VICTIM_ROLE,
              "operatorPassword": ADMIN_PW}, ticket=admin_tk)
print("  创建靶子账号 %s（%s）-> HTTP %s / %s" % (VICTIM, VICTIM_ROLE, st, b.get("code")))
if st != 200:
    print("  !! 建号失败，中止")
    _proc.kill()
    sys.exit(3)

# ============================================================
#  A 组：原始结论 —— 锁定的全部依据就是一个可被操纵的时间戳
# ============================================================

# ---------- 2. 锁定是否真的生效 ----------
print("\n[2] 场景 A：连续输错 3 次 → 锁定 → 再用**正确**口令尝试")
b3 = wrong_three_times()
u = user_doc()
lock_end = naive(u.get("lockoutEnd"))
now = naive(utc_now())
gap = (lock_end - now).total_seconds() if lock_end else None

check("第 3 次错口令返回 ACCOUNT_LOCKED", b3.get("code") == "ACCOUNT_LOCKED",
      "%s / %s" % (b3.get("code"), b3.get("message")))
check("库内 status = Locked", u.get("status") == "Locked", "status=%s" % u.get("status"))
check("lockoutEnd ≈ 当前时刻 + %d 分钟" % LOCK_MINUTES,
      gap is not None and abs(gap - LOCK_MINUTES * 60) < 30,
      "剩余 %.1f 秒" % (gap or -1))

st, b = login(VICTIM_PW)
check("锁定期内**正确口令也进不去**（锁定确实生效）",
      st == 401 and b.get("code") == "ACCOUNT_LOCKED",
      "HTTP %s / %s / %s" % (st, b.get("code"), b.get("message")))

logged = audit_count("LOGIN_FAILED", "ACCOUNT_LOCKED")
logged_all = sum(db[n].count_documents({"action": "LOGIN_FAILED", "target": VICTIM}) for n in shards())
check("3 次失败尝试均已入审计（可追溯谁在猜口令）", logged_all >= 3,
      "LOGIN_FAILED 共 %d 条（其中触发锁定 %d 条）" % (logged_all, logged))

# ---------- 3. 等价复现"时钟前移越过锁定终点" ----------
print("\n[3] 场景 B：把 lockoutEnd 搬到过去 —— 等价于「此刻已越过锁定终点」")
force_lockout(-1)
st, b = login(VICTIM_PW)
check("越过终点后，正确口令立刻登录成功（锁自动解除）", st == 200,
      "HTTP %s / %s" % (st, b.get("code")))

u = user_doc()
check("解锁同时把 status 恢复 Enabled", u.get("status") == "Enabled", "status=%s" % u.get("status"))
check("解锁同时把失败计数清零（下次要从 0 重新数满 3 次）",
      (u.get("failedLoginAttempts") or 0) == 0, "failedLoginAttempts=%s" % u.get("failedLoginAttempts"))

# ---------- 4. 纯时间流逝同样能解锁（证明无后台任务参与） ----------
print("\n[4] 场景 B2：lockoutEnd = now+4s，什么都不做，等 5 秒")
wrong_three_times()
force_lockout(4)
st, b = login(VICTIM_PW)
blocked = (st == 401 and b.get("code") == "ACCOUNT_LOCKED")
print("    等 5 秒前尝试 -> HTTP %s / %s" % (st, b.get("code")))
time.sleep(5)
st, b = login(VICTIM_PW)
check("仅靠时间流逝即解锁（无人工解锁、无后台定时任务）",
      blocked and st == 200, "5 秒后 HTTP %s / %s" % (st, b.get("code")))

# ---------- 5. 反向：时钟回拨只会延长锁定 ----------
print("\n[5] 场景 C：把 lockoutEnd 搬到 30 分钟后 —— 等价于「时钟被回拨 30 分钟」")
wrong_three_times()
force_lockout(30 * 60)
st, b = login(VICTIM_PW)
check("时钟回拨方向不会解锁，反而把锁定拖长", st == 401 and b.get("code") == "ACCOUNT_LOCKED",
      "HTTP %s / %s" % (st, b.get("code")))

# ---------- 6. 锁定状态的字段构成 ----------
print("\n[6] 场景 D：检视锁定状态记录了哪些时间依据")
u = user_doc()
keys = sorted(u.keys())
lock_fields = [k for k in keys if any(t in k.lower() for t in
                                      ("lock", "attempt", "remain", "expire", "tick",
                                       "elapsed", "uptime", "window"))]
print("    与锁定相关的字段：%s" % lock_fields)
check("lockoutEnd 为绝对时间戳（而非「还要等多久」的相对量）",
      isinstance(u.get("lockoutEnd"), datetime), "类型 %s" % type(u.get("lockoutEnd")).__name__)

# 加固后新增的两个锚点。断言它们成对存在、且运行时长锚点与当前 uptime 同量级 ——
# 只存墙钟的话，"现在到了没有"还得再读一次墙钟，而墙钟正是能被拨动的那个。
check("锁定同时留下墙钟锚点 lockoutWallAt",
      isinstance(u.get("lockoutWallAt"), datetime),
      "类型 %s" % type(u.get("lockoutWallAt")).__name__)
up_at = u.get("lockoutUptimeAt")
check("锁定同时留下运行时长锚点 lockoutUptimeAt（墙钟管不着的第二条时间线）",
      isinstance(up_at, (int, float)) and abs(up_at - uptime_ms()) < 5 * 60 * 1000,
      "锚点=%.1f 秒前  当前 uptime=%.1f 秒" % ((uptime_ms() - (up_at or 0)) / 1000, uptime_ms() / 1000))

# ---------- 7. 同一个时钟还驱动着审计时间戳 ----------
print("\n[7] 场景 E：服务端有没有独立时间源（还是共用本机时钟）")
ts_list = []
for n in shards():
    ts_list += [d["timestamp"] for d in db[n].find({}, {"timestamp": 1}) if d.get("timestamp")]
drift = None
if ts_list:
    newest = naive(max(ts_list))
    drift = (naive(utc_now()) - newest).total_seconds()
check("审计时间戳与本机真实 UTC 一致（偏差 < 10 秒）→ 无独立时间源",
      drift is not None and abs(drift) < 10,
      "最新记录距今 %.1f 秒" % (drift if drift is not None else -1))

# ============================================================
#  B 组：加固之后 —— 拨钟还能不能提前解锁
# ============================================================

# ---------- 8. 前拨 10 分钟 ----------
print("\n[8] 加固：把判定所见的墙钟**前拨 10 分钟**，看锁能不能被提前解开")
print("    先以墙钟正常重启，重新把靶子账号锁上（锚点由此记录）")
_, admin_tk = restart(None)
call("POST", "/api/auth/unlock", {"username": VICTIM, "operatorPassword": ADMIN_PW}, ticket=admin_tk)
wrong_three_times()
u0 = user_doc()
end0 = naive(u0.get("lockoutEnd"))
print("    已锁定，lockoutEnd=%s  锚点 wallAt=%s / uptimeAt=%.1f 秒"
      % (end0, naive(u0.get("lockoutWallAt")), (u0.get("lockoutUptimeAt") or 0) / 1000))

_, admin_tk = restart(FORWARD_SKEW)
seen_now = naive(utc_now()) + timedelta(seconds=FORWARD_SKEW)
print("    重启后后端看到的「现在」= %s" % seen_now)

st, b = login(VICTIM_PW)
rem = (b.get("data") or {}).get("remainingSeconds")   # ASP.NET 默认 camelCase 序列化
check("墙钟被前拨 10 分钟后，**正确口令仍然进不去**",
      st == 401 and b.get("code") == "ACCOUNT_LOCKED",
      "HTTP %s / %s / %s" % (st, b.get("code"), b.get("message")))
check("按墙钟读法该锁**早已过期**（说明拦住它的不是墙钟）",
      end0 is not None and end0 < seen_now,
      "lockoutEnd=%s < 墙钟现在=%s" % (end0, seen_now))
check("回显的剩余秒数按真实时间算（不会出现「再试 0 秒」却仍被拒）",
      isinstance(rem, int) and 0 < rem <= LOCK_MINUTES * 60,
      "RemainingSeconds=%s（应 ≤ %d）" % (rem, LOCK_MINUTES * 60))

fwd = latest_audit("CLOCK_ANOMALY")
check("库中出现 CLOCK_ANOMALY 记录（拨钟这件事本身留痕了）", fwd is not None,
      (fwd or {}).get("reasonCode") or "（无记录）")
check("该记录归因为「前拨」（CLOCK_ROLLED_FORWARD）",
      fwd is not None and fwd.get("reasonCode") == "CLOCK_ROLLED_FORWARD",
      "reasonCode=%s" % (fwd or {}).get("reasonCode"))
req = (fwd or {}).get("request") or ""
check("记录里写明背离量，可直接读出「被拨了多少」",
      ("DriftSeconds" in req and str(FORWARD_SKEW) in req),
      (req[:160] + "…") if req else "（空）")

# ---------- 9. 同一次锁定只记一条（防刷屏） ----------
print("\n[9] 加固：连续再试 3 次，确认时钟异常**只记一条**（否则审计会被刷屏）")
n_before = audit_count("CLOCK_ANOMALY")
for _ in range(3):
    login(VICTIM_PW)
n_after = audit_count("CLOCK_ANOMALY")
check("同一轮锁定内时钟异常只留一条记录（靠 lockoutDriftLogged 收敛）",
      n_after == n_before, "试前 %d 条 → 试后 %d 条" % (n_before, n_after))

# ---------- 10. 回拨 1 小时 ----------
print("\n[10] 加固：把判定所见的墙钟**回拨 1 小时**，看会不会把锁拖成一小时")
_, admin_tk = restart(None)
call("POST", "/api/auth/unlock", {"username": VICTIM, "operatorPassword": ADMIN_PW}, ticket=admin_tk)
wrong_three_times()
u1 = user_doc()
end1 = naive(u1.get("lockoutEnd"))

_, admin_tk = restart(BACKWARD_SKEW)
seen_back = naive(utc_now()) + timedelta(seconds=BACKWARD_SKEW)
st, b = login(VICTIM_PW)
rem = (b.get("data") or {}).get("remainingSeconds")   # ASP.NET 默认 camelCase 序列化
check("墙钟被回拨 1 小时后依然锁定（回拨方向本就不能解锁）",
      st == 401 and b.get("code") == "ACCOUNT_LOCKED",
      "HTTP %s / %s" % (st, b.get("code")))
check("回拨也不会把锁定拖长（仍按真实时间计，而不是 1 小时）",
      isinstance(rem, int) and 0 < rem <= LOCK_MINUTES * 60,
      "RemainingSeconds=%s（若按墙钟会被拖成 %d 秒）"
      % (rem, int((end1 - seen_back).total_seconds()) if end1 else -1))
back = latest_audit("CLOCK_ANOMALY")
check("该记录归因为「回拨」（CLOCK_ROLLED_BACKWARD），与攻击方向区分开",
      back is not None and back.get("reasonCode") == "CLOCK_ROLLED_BACKWARD",
      "reasonCode=%s" % (back or {}).get("reasonCode"))

# ---------- 11. 已知边界：重启电脑 ----------
print("\n[11] 已知边界：模拟「机器重启过」（把运行时长锚点改成大于当前 uptime）")
print("     重启会让单调线归零，锚点随之失效 ⇒ 判定退回墙钟。断言它确实如此 ——")
print("     边界要能被验证，而不是嘴上说挡不住。")
_, admin_tk = restart(FORWARD_SKEW)          # 墙钟仍然前拨，模拟「拨钟 + 重启」
db["Users"].update_one({"username": VICTIM},
                       {"$set": {"lockoutUptimeAt": uptime_ms() + 10 * 60 * 1000}})
st, b = login(VICTIM_PW)
check("锚点失效后退回墙钟判定 ⇒ 此时拨钟**仍可**解锁（已知边界，非疏漏）",
      st == 200, "HTTP %s / %s" % (st, b.get("code")))

# ============================================================
#  C 组：失败计数窗口 —— "3 分钟内的失败才算数"
# ============================================================

# ---------- 12. 窗口内连错 3 次，防护不能被削弱 ----------
print("\n[12] 窗口：墙钟正常，窗口内连错 3 次 → 仍然锁定（新增窗口不得削弱原有防护）")
_, admin_tk = restart(None)
b3 = wrong_three_times()
check("窗口内连续 3 次错 → ACCOUNT_LOCKED", b3.get("code") == "ACCOUNT_LOCKED",
      "%s / %s" % (b3.get("code"), b3.get("message")))
u = user_doc()
check("锁定同时把窗口锚点也钉下来（failedWindowWallAt / failedWindowUptimeAt）",
      isinstance(u.get("failedWindowWallAt"), datetime)
      and isinstance(u.get("failedWindowUptimeAt"), (int, float)),
      "wallAt=%s / uptimeAt=%.1f 秒" % (naive(u.get("failedWindowWallAt")),
                                        (u.get("failedWindowUptimeAt") or 0) / 1000))

# ---------- 13. 窗口过期 ⇒ 计数归零、不再锁定 ----------
print("\n[13] 窗口：错 2 次后把窗口锚点搬到 4 分钟前（等价于「3 分钟已经真实过去」），再错 1 次")
_, admin_tk = restart(None)
call("POST", "/api/auth/unlock", {"username": VICTIM, "operatorPassword": ADMIN_PW}, ticket=admin_tk)

st1, _ = login("definitelyWrong9")            # 窗口内第 1 次
st2, b2 = login("definitelyWrong9")           # 窗口内第 2 次
u = user_doc()
check("窗口内错 2 次不锁，提示还剩 1 次机会",
      st1 == 401 and st2 == 401 and b2.get("code") == "INVALID_CREDENTIALS"
      and "还剩 1 次机会" in (b2.get("message") or ""),
      "HTTP %s / %s / %s" % (st2, b2.get("code"), b2.get("message")))
check("库内计数 = 2", (u.get("failedLoginAttempts") or 0) == 2,
      "failedLoginAttempts=%s" % u.get("failedLoginAttempts"))

# 等价模拟"真实的 3 分钟已经走完"：把两个锚点**一起**搬到 4 分钟前。
# 只改锚点、不改系统时间 —— 与场景 B 用 lockoutEnd 复现"时钟前移"是同一手法。
db["Users"].update_one({"username": VICTIM}, {"$set": {
    "failedWindowWallAt": utc_now() - timedelta(minutes=4),
    "failedWindowUptimeAt": uptime_ms() - 4 * 60 * 1000,
}})

st3, b3 = login("definitelyWrong9")           # 越过窗口后的第 1 次
u = user_doc()
check("窗口已过期 ⇒ 这次错**不触发锁定**（旧计数作废）",
      st3 == 401 and b3.get("code") == "INVALID_CREDENTIALS",
      "HTTP %s / %s / %s" % (st3, b3.get("code"), b3.get("message")))
check("提示的剩余次数说明它已回到窗口的第 1 次（还剩 2 次）",
      "还剩 2 次机会" in (b3.get("message") or ""), b3.get("message") or "")
check("库内计数被重置为 1（而不是累积成 3）",
      (u.get("failedLoginAttempts") or 0) == 1,
      "failedLoginAttempts=%s" % u.get("failedLoginAttempts"))
check("status 仍为 Enabled（没有被过期前的 2 次拖去锁定）",
      u.get("status") == "Enabled", "status=%s" % u.get("status"))

# ---------- 14. 拨钟不能让窗口提前作废（新加固的关键证据） ----------
print("\n[14] 窗口：错 2 次后把墙钟**前拨 10 分钟**，看窗口会不会被误判成过期")
login(VICTIM_PW)                              # 登录成功 → 计数与窗口清零，干净起点
login("definitelyWrong9")
login("definitelyWrong9")                     # 窗口内已错 2 次
u = user_doc()
win_wall = naive(u.get("failedWindowWallAt"))
win_up = u.get("failedWindowUptimeAt")
print("    窗口锚点 wallAt=%s / uptimeAt=%.1f 秒" % (win_wall, (win_up or 0) / 1000))

_, admin_tk = restart(FORWARD_SKEW)           # 墙钟 +600 秒，锚点不变
seen_now = naive(utc_now()) + timedelta(seconds=FORWARD_SKEW)
st3, b3 = login("definitelyWrong9")           # 窗口内第 3 次
check("墙钟前拨 10 分钟后，第 3 次错**仍然锁定**（窗口按单调线判，未被提前作废）",
      st3 == 401 and b3.get("code") == "ACCOUNT_LOCKED",
      "HTTP %s / %s / %s" % (st3, b3.get("code"), b3.get("message")))
check("按墙钟读法此刻窗口早已过期（说明拦住它的不是墙钟，而是单调线锚点）",
      win_wall is not None and win_wall + timedelta(minutes=LOCK_MINUTES) < seen_now,
      "窗口起点+%d 分钟=%s < 墙钟现在=%s"
      % (LOCK_MINUTES, (win_wall + timedelta(minutes=LOCK_MINUTES)) if win_wall else None, seen_now))

# ---------- 15. 清零必须把窗口锚点一起带走 ----------
print("\n[15] 窗口：解锁/登录成功时，窗口锚点必须与计数一同消失（防「少清一个字段」）")
_, admin_tk = restart(None)
u = user_doc()
check("锁定期内窗口锚点仍在（这一轮锁定正是由它累计出来的）",
      u.get("failedWindowWallAt") is not None, "failedWindowWallAt=%s" % u.get("failedWindowWallAt"))
call("POST", "/api/auth/unlock", {"username": VICTIM, "operatorPassword": ADMIN_PW}, ticket=admin_tk)
u = user_doc()
check("管理员解锁后失败计数归零", (u.get("failedLoginAttempts") or 0) == 0,
      "failedLoginAttempts=%s" % u.get("failedLoginAttempts"))
check("管理员解锁后窗口**两个锚点**一并清空（只清计数不清锚点会让下一个人被提前锁掉）",
      u.get("failedWindowWallAt") is None and u.get("failedWindowUptimeAt") is None,
      "wallAt=%s / uptimeAt=%s" % (u.get("failedWindowWallAt"), u.get("failedWindowUptimeAt")))

# ---------- 16. 未锁定状态下拨钟：不加罚，但必须留痕 ----------
print("\n[16] 窗口：只错 1 次就拨钟（**还没锁定**）—— 不加罚、不放过，但必须留下 CLOCK_ANOMALY")
restart(None)
login(VICTIM_PW)                              # 登录成功 → 计数与两个锚点一起清零，干净起点
login("definitelyWrong9")                     # 窗口内第 1 次：只钉锚点，此刻无锚点可比、不可能判背离
u = user_doc()
print("    错 1 次后 failedLoginAttempts=%s / 窗口锚点 wallAt=%s / uptimeAt=%.1f 秒"
      % (u.get("failedLoginAttempts"), naive(u.get("failedWindowWallAt")),
         (u.get("failedWindowUptimeAt") or 0) / 1000))
n_before = audit_count("CLOCK_ANOMALY")

restart(FORWARD_SKEW)                         # 墙钟 +600 秒；窗口锚点保持不动
st2, b2 = login("definitelyWrong9")           # 第 2 次：仍未到阈值
u = user_doc()
check("未锁定状态下拨钟：计数照常 +1、账号**不锁定**（拨钟不构成额外的处罚理由）",
      st2 == 401 and b2.get("code") == "INVALID_CREDENTIALS"
      and (u.get("failedLoginAttempts") or 0) == 2
      and u.get("status") == "Enabled",
      "HTTP %s / %s / status=%s / failed=%s"
      % (st2, b2.get("code"), u.get("status"), u.get("failedLoginAttempts")))

win_fwd = latest_audit("CLOCK_ANOMALY")
win_req = (win_fwd or {}).get("request") or ""
check("未锁定状态下拨钟同样写入 CLOCK_ANOMALY 并标明来自失败计数窗口"
      "（旧实现此处完全静默：留痕只挂在「已锁定被拒」那条分支上）",
      audit_count("CLOCK_ANOMALY") == n_before + 1
      and (win_fwd or {}).get("reasonCode") == "CLOCK_ROLLED_FORWARD"
      and "FAILED_ATTEMPT_WINDOW" in win_req,
      "留痕 %d → %d 条 / reasonCode=%s / request=%s"
      % (n_before, audit_count("CLOCK_ANOMALY"), (win_fwd or {}).get("reasonCode"),
         (win_req[:120] + "…") if win_req else "（空）"))

# ---------- 收尾 ----------
try:
    _proc.kill()
    _proc.wait(timeout=10)
except Exception:
    pass

if FAILED or KEEP:
    print("\n  测试库保留：%s" % DB)
else:
    probe_db.drop()
    print("\n  测试库已清理：%s" % DB)

print("\n" + "=" * 70)
print("  通过 %d 项，失败 %d 项" % (len(PASSED), len(FAILED)))
if FAILED:
    for f in FAILED:
        print("    - %s" % f)
print("  结论：%s" % ("PASS ✅ 拨钟不再能提前结束锁定（且留痕）；"
                     "失败计数只在同一 3 分钟窗口内累计，且窗口过期判定同样不走墙钟；"
                     "未锁定阶段的拨钟也会留痕（但不因此加罚、也不多给机会）；"
                     "重启电脑 / 直接改库两条边界仍在，已被显式验证"
                     if not FAILED else "FAIL ❌ 有 %d 项未达标" % len(FAILED)))
print("=" * 70)
sys.exit(1 if FAILED else 0)
