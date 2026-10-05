# -*- coding: utf-8 -*-
"""自测：tools/_probe_common.py 的库名守卫与解析逻辑。

守卫是**安全设施**，所以它自己必须被验证 —— 否则就会出现
"以为有防护、实际没生效"的最坏情况（本项目在隐私扫描上踩过同款坑：
扫描脚本报"0 个 blob"和"模式失效"无法区分）。

本测试**不连数据库、不启后端**，纯逻辑断言，秒级完成。

用法：
  python tools/_probe_common_selftest.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _probe_common import (  # noqa: E402
    ProbeDbGuardError,
    ProbeDb,
    REAL_DB_NAMES,
    REAL_DB_OPTIN_FLAG,
    resolve_probe_db,
    require_real_db_optin,
    _guard,
)

PASSED, FAILED = [], []


def check(name, ok, extra=""):
    (PASSED if ok else FAILED).append(name)
    print("  [%s] %s%s" % ("OK  " if ok else "FAIL", name, ("  — " + str(extra)) if extra else ""))


def expect_block(fn, label):
    """断言 fn() 被守卫拦下。返回实际命中的守卫原因片段供打印。

    守卫的错误消息有两种形态：单行（后缀不合法）与多行（真实库，带醒目框）。
    这里统一抓"含标记的那一行"，不假设行数。

    标记有两个，对应两套语义（见 _probe_common 的说明）：
      - `[库名守卫]`     —— 探针打到真实库（bug）
      - `[真实库门禁]`   —— 真实库脚本没给确认开关
    只认前者会让后者的错误被打印成 "blocked"，测试断言就失去了定位能力。
    """
    try:
        fn()
    except ProbeDbGuardError as e:
        hit = next((ln.strip() for ln in str(e).splitlines()
                    if "库名守卫" in ln or "真实库门禁" in ln), "blocked")
        return True, hit
    except SystemExit as e:
        return True, "SystemExit(%s)" % e.code
    except Exception as e:  # noqa: BLE001
        return False, "抛了非守卫异常: %r" % e
    return False, "**没有被拦下** —— 守卫失效！"


def expect_pass(fn, label):
    try:
        return True, fn()
    except Exception as e:  # noqa: BLE001
        return False, repr(e)


print("=" * 70)
print("  _probe_common 守卫自测")
print("=" * 70)

# ---------------------------------------------------------------------------
print("\n[1] 直接守卫 _guard()：真实库必须被拒")
for real in sorted(REAL_DB_NAMES):
    ok, msg = expect_block(lambda r=real: _guard(r, action="测试"), real)
    check("拒绝真实库 %s" % real, ok, msg)

print("\n[2] 直接守卫 _guard()：不含 Probe 标记必须被拒")
for bad in ["SomeDb", "AuthBaseline", "AuthBaselineLock", "AuthBaseLineProbeX".replace("Probe", "Pr0be"), ""]:
    ok, msg = expect_block(lambda b=bad: _guard(b, action="测试"), bad)
    check("拒绝无标记的 %r" % bad, ok, msg)

print("\n[3] 直接守卫 _guard()：合法测试库必须放行（含派生库）")
for good in ["AuthBaselineLockProbe", "TicketHashProbe", "PepperProbe", "AuthBaselineRoleProbe",
             "PepperProbeFresh", "PepperProbeMig"]:
    ok, val = expect_pass(lambda g=good: _guard(g, action="测试"), good)
    check("放行合法测试库 %s" % good, ok and val == good, val)

# ---------------------------------------------------------------------------
print("\n[4] resolve_probe_db()：默认值本身要被守卫检查")
ok, msg = expect_block(lambda: resolve_probe_db("AuthBaselineDb", argv=[]), "默认值=真实库")
check("默认值写成真实库 → 拒绝（防止有人把 default 改坏）", ok, msg)

ok, val = expect_pass(lambda: resolve_probe_db("SafeNameProbe", argv=[]), "正常默认")
check("无参数时用默认值", ok and val == "SafeNameProbe", val)

# ---------------------------------------------------------------------------
print("\n[5] resolve_probe_db()：命令行解析 —— 这是事故的直接入口")
cases = [
    # (argv, 期望库名 或 None 表示应被拒, 说明)
    (["E:/x/AuthServer.exe", "5291", "AuthBaselineLockProbe"],
     "AuthBaselineLockProbe", "位置参数（旧调用习惯）正常"),
    (["E:/x/AuthServer.exe", "5291", "AuthBaselineDb"],
     None, "位置参数误传真实库 → 必须拒（这就是 10-05 事故的形态）"),
    (["E:/x/AuthServer.exe", "5291"],
     "DefaultProbe", "只给 exe+端口 → 用默认值"),
    (["E:/x/AuthServer.exe", "5291", "--db", "CliNamedProbe"],
     "CliNamedProbe", "--db NAME 显式命名"),
    (["E:/x/AuthServer.exe", "5291", "--db=EqProbe"],
     "EqProbe", "--db=NAME 形式"),
    (["E:/x/AuthServer.exe", "--db", "AuthBaselineDb"],
     None, "--db 传真实库 → 必须拒"),
    (["--keep", "E:/x/AuthServer.exe", "5291"],
     "DefaultProbe", "选项被跳过，路径被跳过，数字被跳过 → 用默认值"),
]
for argv, want, desc in cases:
    try:
        got = resolve_probe_db("DefaultProbe", argv=argv)
        if want is None:
            check(desc, False, "**应被拒但放行了** → %s" % got)
        else:
            check(desc, got == want, "得到 %s，期望 %s" % (got, want))
    except ProbeDbGuardError as e:
        if want is None:
            check(desc, True, "已拦截")
        else:
            check(desc, False, "意外被拒: %s" % next(
                (ln.strip() for ln in str(e).splitlines() if "库名守卫" in ln), "?"))

# ---------------------------------------------------------------------------
print("\n[6] ProbeDb：构造期守卫兜底（绕过 resolve 也拦得住）")
ok, msg = expect_block(lambda: ProbeDb("AuthBaselineDb"), "ProbeDb(真实库)")
check("直接用真实库名构造 ProbeDb → 拒绝", ok, msg)

ok, msg = expect_block(lambda: ProbeDb("NoMarker"), "ProbeDb(无标记)")
check("无 Probe 标记构造 ProbeDb → 拒绝", ok, msg)

# 合法构造：会真的建 MongoClient，但构造 Client 不连库（pymongo 惰性）
proc_ok = False
try:
    p = ProbeDb("GuardedProbeDb")
    proc_ok = p.name == "GuardedProbeDb"
except Exception as e:  # noqa: BLE001
    proc_ok = "pymongo 不可用" in repr(e) or "No module" in repr(e)
check("合法测试库名可构造 ProbeDb（或本机无 pymongo 则跳过）", proc_ok)

# ---------------------------------------------------------------------------
print("\n[7] 逃生舱：AUTHBASELINE_ALLOW_REAL_DB=1 只对真实库放行")
os.environ["AUTHBASELINE_ALLOW_REAL_DB"] = "1"
try:
    ok, val = expect_pass(lambda: _guard("AuthBaselineDb", action="测试"), "逃生舱")
    check("置位逃生舱后真实库放行（且会打印告警）", ok and val == "AuthBaselineDb", val)
finally:
    del os.environ["AUTHBASELINE_ALLOW_REAL_DB"]

ok, msg = expect_block(lambda: _guard("AuthBaselineDb", action="测试"), "复位后")
check("去掉逃生舱后又恢复拦截（状态不残留）", ok, msg)

# ---------------------------------------------------------------------------
print("\n[8] require_real_db_optin：真实库脚本的显式确认门禁")
print("     （与 _guard 语义相反：真实库是它的合法目标，但要显式确认）")

# 8a：非真实库（测试库）无需确认，直接放行
ok, val = expect_pass(
    lambda: require_real_db_optin("AuditE2eProbe", script="x", operation="y",
                                  argv=[]),
    "测试库免确认")
check("非真实库直接放行（无需 --i-know-...）", ok and val == "AuditE2eProbe", val)

# 8b：真实库 + 无确认开关 → 必须拦截
ok, msg = expect_block(
    lambda: require_real_db_optin("AuthBaselineDb", script="x", operation="删审计",
                                  argv=[]),
    "真实库无确认")
check("真实库 + 无确认开关 → 拦截", ok, msg)

# 8c：真实库 + 有确认开关 → 放行
ok, val = expect_pass(
    lambda: require_real_db_optin("AuthBaselineDb", script="x", operation="删审计",
                                  argv=[REAL_DB_OPTIN_FLAG]),
    "真实库有确认")
check("真实库 + --i-know-this-is-the-real-db → 放行",
      ok and val == "AuthBaselineDb", val)

# 8d：确认开关只认精确词，近似写法不算数（防止 "我以为是同一个开关"）
for near in ("--i-know-this-is-real-db", "--i_know_this_is_the_real_db",
             "i-know-this-is-the-real-db", "--I-KNOW-THIS-IS-THE-REAL-DB"):
    ok, _ = expect_block(
        lambda a=near: require_real_db_optin("AuthBaselineDb", script="x",
                                             operation="删审计", argv=[a]),
        "近似开关")
    check("近似开关 %r 不被认作确认 → 仍拦截" % near, ok)

# 8e：另一个真实库（ecg_auth_db，别的项目）同样受保护
ok, _ = expect_block(
    lambda: require_real_db_optin("ecg_auth_db", script="x", operation="写",
                                  argv=[]),
    "ecg_auth_db 无确认")
check("同实例的 ecg_auth_db 也被门禁覆盖", ok)

# 8f：确认开关夹在其它参数中间也要认出来（真实命令行常见形态）
ok, val = expect_pass(
    lambda: require_real_db_optin(
        "AuthBaselineDb", script="x", operation="写",
        argv=["--keep", REAL_DB_OPTIN_FLAG, "--verbose"]),
    "开关夹在中间")
check("确认开关夹在其它参数中间也能识别", ok and val == "AuthBaselineDb", val)

# 8g：定位断言 —— 门禁的报错必须含有"真实库门禁"字样，
#     以免它和 _guard 的报错混在一起分不清是哪一层拦的
ok, msg = expect_block(
    lambda: require_real_db_optin("AuthBaselineDb", script="x", operation="写",
                                  argv=[]),
    "文案")
check("门禁告警文案含 [真实库门禁] 标记（可与 [库名守卫] 区分）",
      "真实库门禁" in msg, msg[:60])

# ---------------------------------------------------------------------------
print("\n" + "=" * 70)
print("  通过 %d 项，失败 %d 项" % (len(PASSED), len(FAILED)))
if FAILED:
    print("  失败项：")
    for f in FAILED:
        print("    - %s" % f)
    print("  结论：FAIL ❌ 守卫需要修复，**不要**在修好前跑任何探针")
    sys.exit(1)
print("  结论：PASS ✅ 守卫生效：真实库被硬拦、测试库放行、逃生舱可控")
print("=" * 70)
