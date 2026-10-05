# -*- coding: utf-8 -*-
"""探针公共基础层 —— 所有 tools/ 下探针脚本的**唯一**基础设施出口。

存在的理由
==========
2026-10-05 发生了一次真实数据损毁事故：`AuthBaselineDb`（6 个账号 + 1641 条审计）
被某个探针脚本的 `drop_database()` 清空。复盘出的三个结构性缺陷，全部在本模块消除：

1. **库名靠"位置参数"猜**
   各脚本写法不一（`sys.argv[3]` / 扫 `sys.argv[3:]` / 硬编码），传参错位就会
   把真实库名喂给 `drop_database()`。→ 本模块统一 `resolve_probe_db()`，
   并强制**库名标记白名单**（必须含 `Probe`），真实库名一律拒绝。

2. **探针库 ≠ 后端库**
   探针用 pymongo 在 `XxxProbe` 做断言，后端却读 appsettings 的
   `DatabaseName = "AuthBaselineDb"`（探针只改了 URL 端口）。于是
   **断言打真实库、清理打测试库**，两边错位。→ 本模块 `start_backend()`
   强制注入 `MongoDbSettings__DatabaseName`，让两者**必然是同一个库**。

3. **破坏性操作散落各处**
   11 处 `drop_database` / `drop()` / `delete_many({})` 分散在 6 个脚本里，
   没有统一守卫。→ 全部收敛到 `ProbeDb.drop()` / `ProbeDb.drop_if_exists()`，
   执行前一律过守卫。

使用方式
========
    from _probe_common import (
        resolve_probe_db, ProbeDb, http_call, start_backend,
        require_backend_ready, stop_backend,
    )

    DB       = resolve_probe_db("AuthBaselineLockProbe")   # 安全解析 + 白名单
    BASE     = "http://127.0.0.1:%d" % PORT
    proc     = start_backend(EXE, PORT, DB)                # 注入测试库名
    probe_db = ProbeDb(DB)                                 # 破坏性操作入口
    ...
    probe_db.drop()                                        # 过守卫后才执行

安全契约（本模块对外承诺）
==========================
- `resolve_probe_db()` 返回的库名**一定**含 `Probe` 标记，且不等于任何已知真实库名。
- `ProbeDb.__init__()` 自身也调一次守卫 —— 即使调用方绕过 `resolve_probe_db`，
  也拦得住。
- `ProbeDb.drop()` 遇到真实库名会**直接抛 SystemExit 并打印醒目告警**，
  绝不"降级成跳过"（静默跳过会让人误以为清理成功）。
- 环境变量 `AUTHBASELINE_ALLOW_REAL_DB=1` 是**唯一**的逃生舱，
  且只对 `AuthBaselineDb` 放行（明确知道自己要干什么的场景）。
- `require_real_db_optin()` 面向**另一类**脚本 —— 管理 / 验收脚本，
  它们的合法目标**就是**真实库。那类脚本必须显式加
  `--i-know-this-is-the-real-db` 才放行；不加则拦截。
  与 `_guard()` 刻意分成两个函数：探针打真实库是 bug，
  验收脚本打真实库是设计意图，同一条规则罩不住两种相反语义。
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

__all__ = [
    "REAL_DB_NAMES",
    "PROBE_DB_MARKER",
    "REAL_DB_OPTIN_FLAG",
    "ProbeDbGuardError",
    "resolve_probe_db",
    "require_real_db_optin",
    "ProbeDb",
    "http_call",
    "wait_backend_ready",
    "start_backend",
    "stop_backend",
    "mongo_client",
    "run_portable_backend",
]

# ---------------------------------------------------------------------------
# 库名安全策略
# ---------------------------------------------------------------------------

#: 已知的真实库 —— 任何破坏性操作都必须避开它们。
#: `AuthBaselineDb` 是本项目的生产库；`ecg_auth_db` 是同实例下另一个项目
#: （CardioCrypt）的库，同样不许碰。
REAL_DB_NAMES = frozenset({"AuthBaselineDb", "ecg_auth_db"})

#: 合法的测试库名**必须包含**的标记。
#:
#: 用"包含"而非"以...结尾"是有意的：探针常由基础名派生出子库
#: （`PepperProbe` → `PepperProbeFresh` / `PepperProbeMig`），
#: 后缀式校验会把这类子库一并拒掉，逼得调用方去放宽规则 —— 那才是危险的开始。
#: 只要名字里带 `Probe`，就说明它是探针自己的库，不会与真实库混淆。
PROBE_DB_MARKER = "Probe"

#: 唯一逃生舱：显式声明"我知道我在动真实库"。
_ALLOW_REAL_ENV = "AUTHBASELINE_ALLOW_REAL_DB"


class ProbeDbGuardError(SystemExit):
    """库名守卫拦截 —— 继承 SystemExit 以确保脚本**立即停止**。

    刻意不继承 Exception：这类错误绝不该被调用方的 `except Exception`
    顺手吞掉然后继续往下跑（那样会留下"跑完了但什么也没做"的假象）。
    """


def _guard(db_name, *, action):
    """库名白名单守卫。不通过就抛 ProbeDbGuardError。"""
    if not isinstance(db_name, str) or not db_name:
        raise ProbeDbGuardError(
            "[库名守卫] %s：库名为空或非字符串（%r）。拒绝执行。" % (action, db_name)
        )

    allow_real = os.environ.get(_ALLOW_REAL_ENV) == "1"

    if db_name in REAL_DB_NAMES:
        if allow_real:
            print("[库名守卫] ⚠️  %s 命中真实库 %s —— 因 %s=1 已放行。"
                  % (action, db_name, _ALLOW_REAL_ENV))
            return db_name
        raise ProbeDbGuardError(
            "\n"
            + "=" * 70 + "\n"
            + "[库名守卫] 已拦截！！！\n"
            + "  动作    : %s\n" % action
            + "  目标库  : %s  ← 这是**真实库**，不允许被探针操作。\n" % db_name
            + "\n"
            + "  这通常意味着探针的参数传错了（库名靠位置参数解析，见\n"
            + "  tools/_probe_common.py 顶部说明）。请检查命令行里库名的位置，\n"
            + "  或改用 resolve_probe_db() 的显式关键字形式。\n"
            + "\n"
            + "  如果你**确实**要在真实库上执行破坏性操作，请显式设置环境变量：\n"
            + "      %s=1\n" % _ALLOW_REAL_ENV
            + "  并在心里确认一遍：这个操作会不可逆地改变真实数据吗？\n"
            + "=" * 70
        )

    if PROBE_DB_MARKER not in db_name:
        raise ProbeDbGuardError(
            "[库名守卫] %s：库名 %r 不含标记 %r，无法确认它是测试库。"
            % (action, db_name, PROBE_DB_MARKER)
        )

    return db_name


def resolve_probe_db(default, argv=None, *, keywords=("db", "--db")):
    """安全解析探针要用的测试库名。

    解析顺序（全部要过守卫）：
      1. 命令行 `--db=NAME` 或 `--db NAME`（显式命名，推荐）
      2. 命令行首个非 `--` 开头的**位置参数**（兼容既有脚本的调用习惯）
      3. `default`

    与旧写法的关键差别：**拿到候选值后一定过 `_guard()`**。
    旧写法 `DB = sys.argv[3]` 拿到什么就是什么，这是事故的直接原因。

    参数
    ----
    default : str
        缺省库名。**本身也要过守卫** —— 防止有人把 default 写成真实库名。
    argv : list[str] | None
        默认取 `sys.argv[1:]`（跳过脚本自身路径）。
    keywords : tuple[str, ...]
        被识别为"库名选项"的关键字（本函数只实现了 `--db`，保留参数便于扩展）。
    """
    default = _guard(default, action="校验默认库名")

    args = list(sys.argv[1:] if argv is None else argv)

    # 1) --db=NAME / --db NAME
    for i, a in enumerate(args):
        if a.startswith("--db="):
            return _guard(a.split("=", 1)[1], action="解析 --db=")
        if a == "--db" and i + 1 < len(args):
            return _guard(args[i + 1], action="解析 --db")

    # 2) 首个非选项位置参数
    for a in args:
        if a.startswith("--"):
            continue
        if a.startswith("-"):
            continue
        # 跳过看起来像路径的（Windows / POSIX 都有可能）
        if os.sep in a or "/" in a or a.endswith(".exe"):
            continue
        # 跳过纯数字（端口）
        if a.isdigit():
            continue
        return _guard(a, action="解析位置参数")

    # 3) 默认值
    return default


# ---------------------------------------------------------------------------
# 真实库脚本的门禁 —— 与探针守卫**刻意分开**的两套语义
# ---------------------------------------------------------------------------

#: 真实库脚本必须显式给出的确认开关（与既有管理脚本的写法保持一致）。
REAL_DB_OPTIN_FLAG = "--i-know-this-is-the-real-db"


def require_real_db_optin(db_name, *, script, operation, argv=None,
                          flag=REAL_DB_OPTIN_FLAG):
    """给"本来就是为真实库设计"的写库脚本用的**显式确认**门禁。

    为什么不复用 `_guard()` —— 两者的语义是相反的，合并会两败俱伤：

    | | `_guard()` | `require_real_db_optin()` |
    |---|---|---|
    | 面向对象 | 探针（打测试库） | 管理 / 验收脚本 |
    | 真实库 | **一律硬拒** | 是它的**合法目标**，但必须显式确认 |
    | 放行方式 | 环境变量逃生舱 | 命令行确认开关 |
    | 库名要求 | 必须含 `Probe` | 不要求（真实库名才是正常输入） |

    关键区分：
      - 探针打真实库 = **bug**（参数传错位了，见模块顶部的事故复盘）
      - 验收脚本打真实库 = **设计意图**（`audit_e2e_test.py` 就是来验真实链的）

    同一条规则罩不住两种相反的意图：硬拒会让验收脚本没法跑，
    一律放行则等于没有守卫。所以分成两个函数，各自表达各自的契约。

    参数
    ----
    db_name : str
        目标库名。**不在** `REAL_DB_NAMES` 里时直接放行（测试库无需确认）。
    script : str
        脚本名，用于告警文案。
    operation : str
        这次要做的破坏性动作（写进告警，让人知道自己会失去什么）。
    argv : list[str] | None
        默认取 `sys.argv[1:]`。
    """
    if db_name not in REAL_DB_NAMES:
        return db_name  # 非真实库（如 XxxProbe）无需确认

    args = list(sys.argv[1:] if argv is None else argv)
    if flag in args:
        print("[真实库门禁] ⚠️  %s：已确认对真实库 %s 执行「%s」"
              % (script, db_name, operation))
        return db_name

    raise ProbeDbGuardError(
        "\n"
        + "=" * 70 + "\n"
        + "[真实库门禁] 已拦截！！！\n"
        + "  脚本    : %s\n" % script
        + "  目标库  : %s  ← 这是**真实库**\n" % db_name
        + "  拟执行  : %s\n" % operation
        + "\n"
        + "  该操作会不可逆地改变真实数据。若确实要执行，请显式确认：\n"
        + "      python tools/%s ... %s\n" % (script, flag)
        + "\n"
        + "  更稳的做法：先用测试库演练（库名里含 %r 即可）。\n" % PROBE_DB_MARKER
        + "=" * 70
    )


# ---------------------------------------------------------------------------
# 数据库句柄：破坏性操作的唯一入口
# ---------------------------------------------------------------------------

def mongo_client(uri="mongodb://localhost:27017", timeout_ms=8000):
    """统一的 MongoClient 构造（pymongo 只在系统 Python 里有）。"""
    from pymongo import MongoClient  # 延迟导入：让本模块在无 pymongo 环境也能 import
    return MongoClient(uri, serverSelectionTimeoutMS=timeout_ms)


class ProbeDb:
    """受守卫保护的测试库句柄。

    只暴露两类操作：读（透传 pymongo 集合）与**受守卫的**破坏性操作。
    调用方拿不到裸的 `drop_database`，从而不可能绕过守卫。
    """

    def __init__(self, name, uri="mongodb://localhost:27017"):
        # 构造期就过守卫：即便调用方没走 resolve_probe_db 也拦得住。
        self.name = _guard(name, action="打开测试库")
        self._uri = uri
        self._cli = mongo_client(uri)

    # ----- 读 -----
    def __getitem__(self, collection):
        return self._cli[self.name][collection]

    @property
    def client(self):
        return self._cli

    def collections(self):
        return sorted(self._cli[self.name].list_collection_names())

    def list_collection_names(self):
        """与 pymongo Database 同名，便于把 `_cli[DB]` 直接换成 `probe_db`。"""
        return self._cli[self.name].list_collection_names()

    def exists(self):
        return self.name in self._cli.list_database_names()

    # ----- 破坏性（全部过守卫）-----
    def drop_if_exists(self):
        """存在才删 —— 幂等，用于脚本开头的"清理上次残留"。"""
        _guard(self.name, action="drop_if_exists")
        if self.exists():
            self._cli.drop_database(self.name)
            return True
        return False

    def drop(self):
        """无条件删库 —— 用于脚本结尾的"跑完即清"。

        与 `drop_if_exists` 分开是为了让调用点**读起来就知道意图**：
        开头清理用前者（可能没库），收尾用后者（一定有库）。
        """
        _guard(self.name, action="drop")
        self._cli.drop_database(self.name)

    def count_all(self):
        db = self._cli[self.name]
        return {n: db[n].count_documents({}) for n in self.collections()}


# ---------------------------------------------------------------------------
# HTTP：显式绕过系统代理
# ---------------------------------------------------------------------------

# 本机（以及本项目执行环境）会间歇性注入一个**指向失效端口的** http_proxy ——
# 此时对 127.0.0.1 的请求会被代理接管并返回 502，报错信息看起来像
# "后端没起来"，极易误导排查方向（后端其实监听正常）。
# 环回请求本就不该走代理，这里用空 ProxyHandler 显式声明。
#
# ⚠️ SSL 上下文必须挂在 **HTTPSHandler** 上，不能当 `open(..., context=)` 传 ——
# `OpenerDirector.open()` 不接受 context 关键字，传了会抛 TypeError，
# 而本函数把异常吞成 `(0, {"err": ...})` ⇒ 表现为"连不上/HTTP 0"，
# 看起来像后端没启动，排查方向被带偏。按有无 ctx 缓存两个 opener。
_OPENERS: dict[bool, urllib.request.OpenerDirector] = {}


def _opener(ctx=None):
    key = ctx is not None
    if key not in _OPENERS:
        handlers: list = [urllib.request.ProxyHandler({})]
        if ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        _OPENERS[key] = urllib.request.build_opener(*handlers)
    return _OPENERS[key]


def http_call(base, method, path, body=None, ticket=None, ctx=None, timeout=60):
    """统一的 HTTP 调用。返回 (status, parsed_or_text)。

    - 4xx/5xx 不抛异常（探针经常要断言"被拒绝"）
    - 连接失败返回 (0, {"err": ...})
    - `ctx` 传 ssl 上下文，供 TLS 相关探针复用
    """
    req = urllib.request.Request(base + path, method=method)
    req.add_header("Content-Type", "application/json")
    if ticket:
        req.add_header("Authorization", "Bearer " + ticket)
    data = json.dumps(body).encode() if body is not None else None

    try:
        with _opener(ctx).open(req, data, timeout=timeout) as r:
            text = r.read().decode("utf-8", "replace")
            try:
                return r.status, (json.loads(text) if text else {})
            except ValueError:
                return r.status, text
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace")
        try:
            return e.code, (json.loads(text) if text else {})
        except ValueError:
            return e.code, text
    except Exception as e:  # noqa: BLE001 —— 探针需要把"连不上"也当成一种可断言的返回
        return 0, {"err": str(e)}


# ---------------------------------------------------------------------------
# 后端生命周期
# ---------------------------------------------------------------------------

def start_backend(exe, port, db_name, *, log_dir=None, log_name=None,
                  extra_env=None, cwd=None):
    """启动后端，并**强制**让它使用测试库。

    这是修复"探针库 ≠ 后端库"缺陷的关键：通过 .NET 标准配置系统的环境变量
    语法 `MongoDbSettings__DatabaseName` 覆盖 appsettings.json 里的
    `AuthBaselineDb`。这样探针的 pymongo 与后端**必然是同一个库**，
    不会再出现"断言打真实库、清理打测试库"的错位。

    返回 subprocess.Popen。日志写文件而非管道 —— 给 .NET 后端接
    `stdout=PIPE` 而父进程不读会假死（本项目踩过）。
    """
    _guard(db_name, action="启动后端（注入测试库）")

    if log_dir is None:
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "buildlogs")
    os.makedirs(log_dir, exist_ok=True)
    if log_name is None:
        log_name = "%s_%d.log" % (os.path.basename(exe).replace(".exe", ""), port)
    log_path = os.path.join(log_dir, log_name)
    logf = open(log_path, "w", encoding="utf-8")

    env = {
        **os.environ,
        "ASPNETCORE_URLS": "http://127.0.0.1:%d" % port,
        # 双下划线是 .NET 配置系统的层级分隔符
        "MongoDbSettings__DatabaseName": db_name,
    }
    if extra_env:
        env.update(extra_env)

    print("[探针] 启动后端 %s @ %d → 库 %s" % (os.path.basename(exe), port, db_name))
    print("[探针] 日志: %s" % log_path)

    return subprocess.Popen(
        [exe], env=env, stdout=logf, stderr=subprocess.STDOUT,
        cwd=cwd or os.path.dirname(os.path.abspath(exe)),
    )


def wait_backend_ready(base, proc=None, *, timeout_s=30, path="/api/auth/transport"):
    """轮询直到后端就绪。返回 True/False。"""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            return False  # 进程已经退出，等下去没意义
        st, _ = http_call(base, "GET", path, timeout=5)
        if st == 200:
            return True
        time.sleep(0.5)
    return False


def require_backend_ready(base, proc=None, *, timeout_s=30, path="/api/auth/transport"):
    """就绪则返回，否则打印日志尾部并退出 —— 避免后续断言全变成噪音失败。"""
    if wait_backend_ready(base, proc, timeout_s=timeout_s, path=path):
        return
    print("[探针] 后端未就绪，退出。")
    if proc is not None:
        stop_backend(proc)
    raise SystemExit(2)


def stop_backend(proc):
    """停止后端进程。kill 后 wait 一下，避免端口未释放就退出。"""
    if proc is None:
        return
    try:
        proc.kill()
        proc.wait(timeout=10)
    except Exception:  # noqa: BLE001
        pass


def run_portable_backend(exe, port, db_name, *, ready_timeout_s=30, extra_env=None):
    """`start_backend` + `require_backend_ready` 的组合便捷入口。

    返回 (proc, base)。绝大多数探针只需要这一句。
    """
    base = "http://127.0.0.1:%d" % port
    proc = start_backend(exe, port, db_name, extra_env=extra_env)
    require_backend_ready(base, proc, timeout_s=ready_timeout_s)
    return proc, base
