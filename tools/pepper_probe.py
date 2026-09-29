# -*- coding: utf-8 -*-
"""口令 pepper + 渐进迁移（存储安全 S2）的真机验证。

要证明的一句话：
  **库里那批口令哈希，在没有 pepper 的情况下既验不过、也爆破不出来；
    而开启 pepper 之前存下来的老哈希，仍能正常登录并在登录时自动升级。**

判据（逐条对应断言）：
  1. 新写入的口令哈希带 `v2$` 标记 —— 包括启动时播种的 admin 账号。
  2. 该标记的构造能被 Python **独立复算**（HMAC-SHA256(pepper, 口令) → bcrypt），
     不依赖后端自证"我算对了"。
  3. 剥离标记后用**裸口令**直接验证必须失败 —— 这一条才真正证明 pepper 参与了运算，
     而不是"后端说它参与了"。
  4. 旧格式（`$2a$`、无 pepper）账号仍能登录。
  5. 登录后库里的哈希自动变成 `v2$`，且能被 P1 独立复算验证。
  6. 该次升级恰好留 1 条 PASSWORD_HASH_UPGRADED 审计，且审计全文不含口令。
  7. 再次登录不再产生升级审计（幂等）。
  8. 换用**错误的 pepper**：正确口令也登不进去，且不会把库里的哈希改坏。
  9. 库中已有 v2 哈希、而本机 pepper 丢失 ⇒ **拒绝启动**（退出码非 0 + 可读原因 +
     给出恢复指引），且**绝不静默生成**一个新 pepper。
 10. 干净的库 + 无 pepper ⇒ 首次初始化成功，落盘文件是 DPAPI 密文（不是 32 字节明文）。
 11. `--pepper-export` / `--pepper-import`：错误口令打不开封装文件；正确口令可导入，
     且导入端的指纹与导出端一致；用导入的 pepper 能正常起后端并登录。
 12. 早期版本把 pepper 落在**安装目录内**（`%LOCALAPPDATA%\AuthBaseline\`，正是 NSIS 的安装路径），
     清理安装残留时会连它一起删掉 ⇒ 现在落在同级的 `AuthBaselineData\`，并带一次性搬迁：
     老位置有、新位置没有时自动搬过去（内容不变、老文件删除），
     但**显式指定了 pepper 路径时绝不触发搬迁**（否则测试环境会被本机真实 pepper 污染）。

用法：
  python pepper_probe.py [exe路径] [端口] [测试库名] [--keep]
"""
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import bcrypt
from pymongo import MongoClient

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") \
    else os.path.join(ROOT, "AuthServer", "bin", "Release", "net8.0", "AuthServer.exe")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else 5232
DB = next((a for a in sys.argv[3:] if not a.startswith("--")), "PepperProbe")
FRESH_DB = DB + "Fresh"
MIG_DB = DB + "Mig"
BASE = "http://127.0.0.1:%d" % PORT
KEEP = "--keep" in sys.argv

ADMIN_USER = os.environ.get("E2E_ADMIN", "admin")
ADMIN_PW = os.environ.get("E2E_ADMIN_PASS", "Admin123")

LOG_DIR = os.path.join(ROOT, ".workbuddy", "tmp", "pepper_probe")
os.makedirs(LOG_DIR, exist_ok=True)

# 两个不同的 pepper：P1 是"本机的"，P2 专门用来演"拿错了 pepper"。
PEPPER1 = bytes(range(32))
PEPPER2 = bytes(range(32, 64))

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print("  [%s] %s%s" % ("OK  " if cond else "FAIL", name, ("  — " + str(detail)) if detail else ""))


# ---------- HTTP ----------
def call(method, path, body=None, ticket=None, timeout=60):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Content-Type", "application/json")
    if ticket:
        req.add_header("Authorization", "Bearer " + ticket)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8", "replace") or "{}")
    except Exception as e:
        return 0, {"err": str(e)}


def login(username, password):
    st, b = call("POST", "/api/auth/login", {"username": username, "password": password})
    return st, b, (b.get("data") or {}).get("ticket")


# ---------- 独立复算：与后端 PasswordHasher 的约定保持一致 ----------
def b64raw(b: bytes) -> str:
    return base64.b64encode(b).decode()


def prehash(password: str, pepper: bytes) -> str:
    """等价于 PasswordHasher.PreHash：HMAC-SHA256(pepper, 口令) → **标准** Base64（含 +/）。"""
    return b64raw(hmac.new(pepper, password.encode("utf-8"), hashlib.sha256).digest())


def v2_check(password: str, stored: str, pepper: bytes) -> bool:
    """自己算一遍，再拿 bcrypt 去比。不看后端代码，也不看后端返回值。"""
    if not stored.startswith("v2$"):
        return False
    body = stored[len("v2$"):].encode()
    try:
        return bcrypt.checkpw(prehash(password, pepper).encode(), body)
    except Exception:
        return False


def naked_check(password: str, stored: str) -> bool:
    """剥掉 v2$ 标记后，直接用**裸口令**验证 —— 这是"pepper 有没有真参与"的证伪测试。"""
    body = stored[len("v2$"):] if stored.startswith("v2$") else stored
    try:
        return bcrypt.checkpw(password.encode(), body.encode())
    except Exception:
        return False


def legacy_hash(password: str) -> str:
    """造一条改造前形态的哈希：$2a$11$…，不带 pepper。"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=11, prefix=b"2a")).decode()


# ---------- 库 ----------
_cli = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=8000)
for _d in (DB, FRESH_DB, MIG_DB):
    if _d in _cli.list_database_names():
        _cli.drop_database(_d)
        print("已清理旧测试库", _d)
db = _cli[DB]


def audit_docs():
    """遍历所有审计分片。"""
    for n in db.list_collection_names():
        if n.startswith("AuditLogs"):
            for d in db[n].find({}):
                yield n, d


def count_action(action: str) -> int:
    return sum(1 for _, d in audit_docs() if d.get("action") == action)


def read_log(path: str) -> str:
    """后端输出是 GBK（Windows 控制台默认代码页），别用 utf-8 硬读。"""
    with open(path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8", "gbk", "utf-16"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", "replace")


def base_env(dbname, extra):
    """构造子进程环境；显式清掉可能从外部继承的 pepper 变量，避免污染结论。"""
    env = {**os.environ,
           "ASPNETCORE_URLS": "http://127.0.0.1:%d" % PORT,
           "MongoDbSettings__DatabaseName": dbname}
    for k in ("AUTHBASELINE_PEPPER", "AUTHBASELINE_PEPPER_FILE", "AUTHBASELINE_PEPPER_PASSPHRASE",
              "AUTHBASELINE_PEPPER_LEGACY_FILE"):
        env.pop(k, None)
    env.update(extra)
    return env


def start(extra, tag, dbname=DB, timeout=60):
    """起后端并等就绪。返回 (proc, logf, logpath)。"""
    logpath = os.path.join(LOG_DIR, "%s.log" % tag)
    logf = open(logpath, "wb")
    p = subprocess.Popen([EXE], env=base_env(dbname, extra), stdout=logf, stderr=subprocess.STDOUT)
    for _ in range(int(timeout * 2)):
        if p.poll() is not None:
            break
        st, _ = call("GET", "/")
        if st != 0:
            return p, logf, logpath
        time.sleep(0.5)
    p.kill()
    p.wait(timeout=10)
    logf.close()
    raise RuntimeError("后端 %s 未就绪，日志见 %s\n%s" % (tag, logpath, read_log(logpath)[-2000:]))


def stop(p, logf):
    p.kill()
    p.wait(timeout=10)
    try:
        logf.close()
    except Exception:
        pass
    time.sleep(0.8)   # 等端口彻底释放


def run_cli(args, extra, timeout=120):
    """跑一次子命令（--pepper-export / --pepper-import），返回 (退出码, 输出文本)。"""
    cp = subprocess.run([EXE] + args, env=base_env(DB, extra),
                        capture_output=True, timeout=timeout)
    combined = cp.stdout + cp.stderr
    for enc in ("utf-8", "gbk"):
        try:
            return cp.returncode, combined.decode(enc)
        except Exception:
            continue
    return cp.returncode, combined.decode("utf-8", "replace")


print("exe    :", EXE)
print("端口   :", PORT)
print("测试库 :", DB, "+", FRESH_DB, "（全新库起步，跑完即清）")
print("pepper : P1 与 P2 均为内存态，经环境变量注入，**不触碰真实的 pepper 文件**")

tmp_dirs = []
proc = logf = None

try:
    # ============================================================
    print("\n[1] 全新库 + 显式 pepper 启动 —— 新写入的口令应当是 v2$ 形态")
    p1, logf, logpath1 = start({"AUTHBASELINE_PEPPER": b64raw(PEPPER1)}, "s1")
    proc = p1
    print("  就绪 (PID=%d)" % p1.pid)

    st, b, tk_admin = login(ADMIN_USER, ADMIN_PW)
    check("管理员可用播种口令登录", st == 200 and bool(tk_admin),
          "HTTP %s / %s" % (st, b.get("code")))

    admin_doc = db["Users"].find_one({"username": ADMIN_USER})
    h_admin_1 = (admin_doc or {}).get("passwordHash", "")
    check("播种管理员的口令哈希也是 v2$ 格式（没有绕过 pepper 的例外）",
          h_admin_1.startswith("v2$"), "实际前缀 %r" % h_admin_1[:8])
    check("独立复算：HMAC-SHA256(P1) → bcrypt 命中该哈希（不靠后端自证）",
          v2_check(ADMIN_PW, h_admin_1, PEPPER1))
    check("剥掉标记后用裸口令直接验证必须失败（证明 pepper 真的参与了运算）",
          not naked_check(ADMIN_PW, h_admin_1))

    # ============================================================
    print("\n[2] 造一条改造前形态的账号，验证渐进迁移")
    LEGACY_USER = "legacy_pepper_user"
    LEGACY_PW = "LegacyPass123"
    lh = legacy_hash(LEGACY_PW)
    db["Users"].insert_one({
        "username": LEGACY_USER,
        "passwordHash": lh,
        "status": "Enabled",
        "role": "User",
        "email": None,
        "emailVerified": False,
        "failedLoginAttempts": 0,
        "lockoutEnd": None,
        "createdAt": datetime.now(timezone.utc),
    })
    check("已造出旧格式账号（$2a$ 前缀、无 pepper）", lh.startswith("$2a$"), lh[:7])

    before = count_action("PASSWORD_HASH_UPGRADED")

    st, b, tk = login(LEGACY_USER, LEGACY_PW)
    check("旧格式账号仍能登录（升级不要求用户改口令）", st == 200 and bool(tk),
          "HTTP %s / %s" % (st, b.get("code")))

    h_after = (db["Users"].find_one({"username": LEGACY_USER}) or {}).get("passwordHash", "")
    check("登录后库里的哈希自动变成 v2$ 格式", h_after.startswith("v2$"),
          "实际前缀 %r" % h_after[:8])
    check("升级后的哈希能用 P1 独立复算验证（口令没有被改掉）",
          v2_check(LEGACY_PW, h_after, PEPPER1))

    after = count_action("PASSWORD_HASH_UPGRADED")
    check("恰好新增 1 条 PASSWORD_HASH_UPGRADED 审计", after - before == 1,
          "%d → %d" % (before, after))

    hits = []
    for n, d in audit_docs():
        for k, v in d.items():
            if isinstance(v, str) and LEGACY_PW in v:
                hits.append("%s.%s" % (n, k))
    check("审计里不含口令明文（升级记录也不能写口令）", not hits, "命中 %s" % hits)

    st, _, _ = login(LEGACY_USER, LEGACY_PW)
    check("再次登录仍成功", st == 200, "HTTP %s" % st)
    check("不产生第二条升级审计（幂等）", count_action("PASSWORD_HASH_UPGRADED") == after,
          "仍为 %d 条" % count_action("PASSWORD_HASH_UPGRADED"))

    if tk_admin:
        st_l, _ = call("GET", "/api/auth/users", ticket=tk_admin)
        check("升级期间不影响其它接口（管理员仍可查用户列表）", st_l == 200, "HTTP %s" % st_l)

    stop(proc, logf)

    # ============================================================
    print("\n[3] 换成错误的 pepper —— 正确口令也必须验不过")
    p2, logf, _ = start({"AUTHBASELINE_PEPPER": b64raw(PEPPER2)}, "s2")
    proc = p2

    st, b, tk_bad = login(LEGACY_USER, LEGACY_PW)
    check("错误 pepper 下，旧格式升级来的账号登不进去", st == 401,
          "HTTP %s / %s" % (st, b.get("code")))
    st2, b2, _ = login(ADMIN_USER, ADMIN_PW)
    check("错误 pepper 下，管理员同样登不进去", st2 == 401,
          "HTTP %s / %s" % (st2, b2.get("code")))
    check("验证失败时不会把库里的哈希改写坏",
          (db["Users"].find_one({"username": LEGACY_USER}) or {}).get("passwordHash") == h_after)

    stop(proc, logf)

    # ============================================================
    print("\n[4] 库里有 v2 哈希、本机 pepper 却丢了 —— 必须拒绝启动")
    lost_dir = tempfile.mkdtemp(prefix="pepper_probe_lost_")
    tmp_dirs.append(lost_dir)
    lost_path = os.path.join(lost_dir, "pepper.dat")

    logpath4 = os.path.join(LOG_DIR, "s3.log")
    with open(logpath4, "wb") as lf:
        p4 = subprocess.Popen([EXE], env=base_env(DB, {"AUTHBASELINE_PEPPER_FILE": lost_path}),
                              stdout=lf, stderr=subprocess.STDOUT)
        rc = None
        try:
            rc = p4.wait(timeout=90)
        except subprocess.TimeoutExpired:
            p4.kill()
            p4.wait(timeout=10)
    text4 = read_log(logpath4)

    check("退出码非 0（拒绝启动，而不是带病运行）", rc is not None and rc != 0,
          "退出码 %s" % rc)
    check("失败原因写明『这台机器曾经初始化过 pepper』", "曾经初始化过" in text4)
    check("给出恢复指引（--pepper-import）", "--pepper-import" in text4)
    check("绝不静默生成新 pepper —— 该位置没有产生任何文件",
          not os.path.exists(lost_path),
          "目录内容 %s" % os.listdir(lost_dir))

    # ============================================================
    print("\n[5] 干净的库 + 没有 pepper —— 首次初始化应当成功且落盘为密文")
    fresh_dir = tempfile.mkdtemp(prefix="pepper_probe_fresh_")
    tmp_dirs.append(fresh_dir)
    fresh_path = os.path.join(fresh_dir, "pepper.dat")

    p5, logf, logpath5 = start({"AUTHBASELINE_PEPPER_FILE": fresh_path}, "s5", dbname=FRESH_DB)
    proc = p5
    text5 = read_log(logpath5)

    check("后端正常启动（没有任何 v2 哈希时允许生成）", p5.poll() is None)
    check("pepper 文件已生成", os.path.exists(fresh_path), fresh_path)

    blob = open(fresh_path, "rb").read() if os.path.exists(fresh_path) else b""
    check("文件带 ABPEPPER 标识", blob.startswith(b"ABPEPPER"), "前 10 字节 %r" % blob[:10])
    check("文件不是 32 字节明文（DPAPI 密文明显更大）", len(blob) > 100, "%d 字节" % len(blob))

    m = re.search(r"指纹 ([0-9a-f]{16})", text5)
    fp_fresh = m.group(1) if m else ""
    check("启动日志打印了 pepper 指纹（便于确认换机前后是否同一份）", bool(fp_fresh),
          "指纹 %s" % (fp_fresh or "未解析到"))

    st, b, tk_fresh = login(ADMIN_USER, ADMIN_PW)
    check("该库里可以正常登录", st == 200 and bool(tk_fresh), "HTTP %s / %s" % (st, b.get("code")))

    stop(proc, logf)

    # ============================================================
    print("\n[6] 导出 / 导入（换机迁移的唯一通道）")
    export_path = os.path.join(fresh_dir, "export.pepper")
    rc_ex, out_ex = run_cli(["--pepper-export", export_path],
                                  {"AUTHBASELINE_PEPPER_FILE": fresh_path,
                                   "AUTHBASELINE_PEPPER_PASSPHRASE": "ExportPass123"})
    check("--pepper-export 退出码 0", rc_ex == 0, "退出码 %s\n%s" % (rc_ex, out_ex[-500:]))
    check("导出文件已生成", os.path.exists(export_path))

    eblob = open(export_path, "rb").read() if os.path.exists(export_path) else b""
    check("导出文件带 ABPEPPERX 封装标识", eblob.startswith(b"ABPEPPERX"), "前 10 字节 %r" % eblob[:10])
    # 9(magic) + 1(ver) + 4(iters) + 16(salt) + 12(nonce) + 16(tag) + 32(cipher)
    check("封装文件长度符合约定（90 字节）", len(eblob) == 90, "%d 字节" % len(eblob))

    import_dir = tempfile.mkdtemp(prefix="pepper_probe_import_")
    tmp_dirs.append(import_dir)
    import_path = os.path.join(import_dir, "pepper.dat")

    rc_wrong, out_wrong = run_cli(["--pepper-import", export_path],
                                        {"AUTHBASELINE_PEPPER_FILE": import_path,
                                         "AUTHBASELINE_PEPPER_PASSPHRASE": "WrongPass999"})
    check("错误口令导入必须失败（GCM 认证标签拦住）", rc_wrong != 0, "退出码 %s" % rc_wrong)
    check("错误口令时不会写出 pepper 文件", not os.path.exists(import_path))

    rc_ok, out_ok = run_cli(["--pepper-import", export_path],
                                  {"AUTHBASELINE_PEPPER_FILE": import_path,
                                   "AUTHBASELINE_PEPPER_PASSPHRASE": "ExportPass123"})
    check("正确口令导入成功", rc_ok == 0, "退出码 %s\n%s" % (rc_ok, out_ok[-400:]))
    check("导入端生成了 pepper 文件", os.path.exists(import_path))

    m2 = re.search(r"指纹 ([0-9a-f]{16})", out_ok)
    fp_import = m2.group(1) if m2 else ""
    check("导入端指纹与导出端一致（同一份 pepper）",
          bool(fp_fresh) and fp_import == fp_fresh,
          "导出 %s / 导入 %s" % (fp_fresh or "-", fp_import or "-"))
    check("两份 DPAPI 密文内容不同（每次加密都带随机，密文不构成可比对的指纹）",
          open(import_path, "rb").read() != blob if os.path.exists(import_path) else False)

    # ============================================================
    print("\n[7] 用导入进来的 pepper 起后端 —— 迁移闭环")
    p7, logf, _ = start({"AUTHBASELINE_PEPPER_FILE": import_path}, "s7", dbname=FRESH_DB)
    proc = p7
    st, b, tk7 = login(ADMIN_USER, ADMIN_PW)
    check("用「导入的 pepper」可以正常起后端并登录（换机后口令依然有效）",
          st == 200 and bool(tk7), "HTTP %s / %s" % (st, b.get("code")))
    stop(proc, logf)
    proc = None

    # ============================================================
    print("\n[8] 老位置（旧版落在安装目录里）的 pepper 自动搬迁到新位置")

    mig_dir = tempfile.mkdtemp(prefix="pepper_probe_mig_")
    tmp_dirs.append(mig_dir)
    mig_legacy = os.path.join(mig_dir, "legacy", "pepper.dat")
    mig_target = os.path.join(mig_dir, "target", "pepper.dat")

    # 8a. 先在"老位置"造一份 pepper（该库尚无 v2 哈希，允许首次初始化）。
    #     这一步同时是**守卫断言**：AUTHBASELINE_PEPPER_FILE 指向临时目录时，
    #     绝不能顺带把本机真实的老文件搬过来 —— 否则测试环境会被真实 pepper 污染，
    #     而且"首次生成"这条路径再也测不到（永远看不到生成分支）。
    p8, logf, logpath8 = start({"AUTHBASELINE_PEPPER_FILE": mig_legacy}, "s8", dbname=MIG_DB)
    text8 = read_log(logpath8)
    m8 = re.search(r"指纹 ([0-9a-f]{16})", text8)
    fp_a = m8.group(1) if m8 else ""
    check("[8a] 老位置按首次初始化生成了 pepper", os.path.exists(mig_legacy), mig_legacy)
    check("[8a] 指纹已打印", bool(fp_a), fp_a or "未解析到")
    check("[8a] 守卫：指向临时目录时不会去搬本机真实的老 pepper",
          "已把 pepper 从旧位置迁移" not in text8)
    stop(p8, logf)

    # 8b. 现在"老位置有、新位置没有" ⇒ 应自动搬迁，且内容不变。
    p8b, logf, logpath8b = start(
        {"AUTHBASELINE_PEPPER_FILE": mig_target, "AUTHBASELINE_PEPPER_LEGACY_FILE": mig_legacy},
        "s8b", dbname=MIG_DB)
    proc = p8b
    text8b = read_log(logpath8b)
    m8b = re.search(r"指纹 ([0-9a-f]{16})", text8b)
    fp_b = m8b.group(1) if m8b else ""

    check("[8b] 日志里有搬迁记录", "已把 pepper 从旧位置迁移" in text8b)
    check("[8b] 新位置已出现 pepper", os.path.exists(mig_target), mig_target)
    check("[8b] 老文件已删除（只保留唯一权威副本）", not os.path.exists(mig_legacy))
    check("[8b] 搬迁前后是同一份 pepper（指纹一致）",
          bool(fp_a) and fp_b == fp_a, "搬迁前 %s / 搬迁后 %s" % (fp_a or "-", fp_b or "-"))

    # 该库的管理员哈希是用"搬迁前"那台 pepper 播种的；能登录 ⇒ 搬迁确实保住了秘密本体，
    # 而不是"换了个能启动的新 pepper"（后者也会指纹一致地起不来，但登不进）。
    st, b, tk8 = login(ADMIN_USER, ADMIN_PW)
    check("[8b] 用搬迁后的 pepper 仍能用原口令登录（秘密本体未变）",
          st == 200 and bool(tk8), "HTTP %s / %s" % (st, b.get("code")))
    stop(proc, logf)
    proc = None

finally:
    if proc is not None:
        try:
            proc.kill()
            proc.wait(timeout=10)
        except Exception:
            pass
    for d in tmp_dirs:
        try:
            shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass
    if FAILED or KEEP:
        print("\n  测试库保留：%s / %s / %s" % (DB, FRESH_DB, MIG_DB))
        print("  临时目录保留：%s" % tmp_dirs)
    else:
        for d in (DB, FRESH_DB, MIG_DB):
            try:
                _cli.drop_database(d)
            except Exception:
                pass
        print("\n  测试库已清理：%s / %s / %s" % (DB, FRESH_DB, MIG_DB))

print("\n" + "=" * 68)
print("  结论：%s" % ("PASS ✅ 共 %d 项" % len(PASSED) if not FAILED
                     else "FAIL ❌ 有 %d 项未达标：%s" % (len(FAILED), FAILED)))
print("=" * 68)
sys.exit(1 if FAILED else 0)
