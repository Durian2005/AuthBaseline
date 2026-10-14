# -*- coding: utf-8 -*-
"""人脸模块 · **装机产物**校验（Release / 单文件链路）。

## 为什么需要这个工具

`tools/face_second_factor_probe.py` 打的是 Debug 构建。而装机后真正跑的是

    src-tauri/binaries/authserver-<triple>.exe  →  NSIS 装成 authserver.exe
    AuthServer/face-models/*                   →  $INSTDIR\\face-models\\*

中间隔着**发布（PublishSingleFile + IncludeNativeLibrariesForSelfExtract）**与
**打包（NSIS）**两层，Debug 与它们的行为**不保证一致**。本项目实测踩过：

  ① 单文件打包器把 `face_detection_yunet_2023mar.onnx` **吞进 exe 并从发布目录删掉**
     （SFace 那个又不动 —— 行为不一致），而加载器是从 exe 同级目录读模型的
     ⇒ 装机后已录人脸账号**全部 fail closed**，界面只有一句"本机人脸引擎不可用"；
  ② OpenCvSharp 的原生 DLL 走自解包，`Cv2.GetVersionString()` 可能在建引擎前就抛。

所以本工具按 NSIS 的 `File /oname=` 布局**镜像一份装机产物**，然后：

  步骤一 真引擎（`AUTHBASELINE_FACE_ENGINE=cv`）能否从**镜像里的 face-models** 加载；
  步骤二 把 `face_second_factor_probe.py` 的**全部断言**打到这份镜像 exe 上。

## 用法

    # 模式一：自建镜像（不需要真的安装；改完 publish/sidecar 就能跑）
    C:/Users/<你>/python.exe tools/face_release_probe.py 5700
    C:/Users/<你>/python.exe tools/face_release_probe.py 5700 --db AuthBaselineFaceReleaseProbe

    # 模式二：打**真实装机目录**（装完 NSIS 之后跑，证据最强）
    C:/Users/<你>/python.exe tools/face_release_probe.py 5710 --install-dir "%LOCALAPPDATA%\\AuthBaseline"

⚠️ 必须用**系统 Python**（带 pymongo）；⚠️ 库名必须含 `Probe`（`_guard()` 硬拒真实库）。
⚠️ 模式一前置：先跑过 `npm run publish:backend` 与 `npm run sync:sidecar`，否则镜像源缺文件。
⚠️ 本工具只**读**产物（镜像或装机目录）、只**写** `.workbuddy/tmp/`，不碰真实库。
"""
import os
import shutil
import subprocess
import sys
import time

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOLS_DIR)
sys.path.insert(0, TOOLS_DIR)

from _probe_common import (  # noqa: E402
    ProbeDb, http_call, resolve_probe_db, start_backend, stop_backend,
    wait_backend_ready,
)

MIRROR = os.path.join(ROOT, ".workbuddy", "tmp", "install_mirror")
# 实际被校验的目录（镜像 或 真实装机目录），由 main() 决定
TARGET = MIRROR

# NSIS 脚本里 File /oname= 的镜像（少一个就是打包漏了）
SIDECAR_SRC = os.path.join(ROOT, "src-tauri", "binaries",
                           "authserver-x86_64-pc-windows-msvc.exe")
FACE_MODELS_SRC = os.path.join(ROOT, "AuthServer", "face-models")
DIST_SRC = os.path.join(ROOT, "AuthClient", "dist")
APPSETTINGS_SRC = [
    os.path.join(ROOT, "AuthServer", "appsettings.json"),
    os.path.join(ROOT, "AuthServer", "appsettings.Local.json"),
]
REQUIRED_FACE_MODELS = {
    "face_detection_yunet_2023mar.onnx",
    "face_recognition_sface_2021dec.onnx",
    "LICENSE_yunet.txt",
    "LICENSE_sface.txt",
    "README.md",
}

PASSED, FAILED = [], []


def ok(msg):
    PASSED.append(msg)
    print("  [PASS] %s" % msg)


def bad(msg):
    FAILED.append(msg)
    print("  [FAIL] %s" % msg)


def decode_log(raw):
    """.NET 控制台输出是**系统 ANSI 编码**（本机 GBK）—— 按 UTF-8 读会乱码，
    判定串会假失败（本项目踩过）。"""
    for enc in ("utf-8", "gbk", "cp936"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def build_mirror():
    """按 NSIS 的 File /oname= 布局镜像一份装机产物。"""
    for p in [SIDECAR_SRC, FACE_MODELS_SRC, DIST_SRC, *APPSETTINGS_SRC]:
        if not os.path.exists(p):
            bad("缺少源产物：%s（先跑 publish:backend + sync:sidecar）" % p)
            return None
    if os.path.isdir(MIRROR):
        shutil.rmtree(MIRROR)
    os.makedirs(MIRROR)

    shutil.copy2(SIDECAR_SRC, os.path.join(MIRROR, "authserver.exe"))
    shutil.copytree(FACE_MODELS_SRC, os.path.join(MIRROR, "face-models"))
    shutil.copytree(DIST_SRC, os.path.join(MIRROR, "wwwroot"))
    for src in APPSETTINGS_SRC:
        shutil.copy2(src, os.path.join(MIRROR, os.path.basename(src)))
    print("[镜像] %s" % MIRROR)
    return MIRROR


def use_install_dir(path):
    """模式二：直接校验**真实装机目录**（NSIS 装完之后跑）。

    比镜像更硬的地方：镜像只复现了「文件布局」，而真实装机目录还带上了
    NSIS 解压出来的 exe 本身（md5 应与 publish 一致）与注册表/快捷方式。
    """
    if not os.path.isdir(path):
        bad("装机目录不存在：%s" % path)
        return None
    exe = os.path.join(path, "authserver.exe")
    if not os.path.exists(exe):
        bad("装机目录里没有 authserver.exe：%s" % path)
        return None
    size = os.path.getsize(exe)
    (ok if size > 0 else bad)("装机 authserver.exe 非空（%d 字节）" % size)
    if size == 0:
        # 只轮询文件出现、不同进程 wait 安装器时，就是这个下场
        bad("exe 为 0 字节 ⇒ 安装被中断（安装器必须同进程 wait 到退出）")
        return None
    print("[装机目录] %s" % path)
    return path


def check_target_layout(target):
    """装机目录/镜像的文件布局（不启动进程，纯静态判定）。"""
    print("\n[步骤零] 目标目录文件布局")
    got = set(os.listdir(os.path.join(target, "face-models"))) \
        if os.path.isdir(os.path.join(target, "face-models")) else set()
    missing = REQUIRED_FACE_MODELS - got
    (ok if not missing else bad)(
        "face-models 含全部 5 个文件" if not missing
        else "face-models 缺：%s" % ", ".join(sorted(missing)))
    for rel in ["wwwroot/index.html", "appsettings.json",
                "appsettings.Local.json", "authserver.exe"]:
        p = os.path.join(target, *rel.split("/"))
        (ok if os.path.exists(p) else bad)("存在 %s" % rel)
    # ⚠️ 单文件打包器若把 .onnx 吞进 exe，磁盘上就没有它了；这条同时反向兜住
    data = open(os.path.join(target, "authserver.exe"), "rb").read()
    for name in ["face_detection_yunet_2023mar", "face_recognition_sface_2021dec"]:
        cnt = data.count(name.encode())
        (ok if cnt == 0 else bad)(
            "exe 内**未**内嵌 %s（打包器没吞模型）" % name)


def step1_real_engine(port, db_name):
    """真引擎能否从**目标目录里的 face-models** 加载。"""
    print("\n[步骤一] 真引擎从**目标目录里的 face-models** 加载")
    exe = os.path.join(TARGET, "authserver.exe")
    log = os.path.join(ROOT, ".workbuddy", "tmp", "mirror_cv_engine.log")

    proc = start_backend(exe, port, db_name, log_dir=os.path.dirname(log),
                         log_name=os.path.basename(log), extra_env={
                             "AUTHBASELINE_REQUIRE_HTTPS": "false",
                             "AUTHBASELINE_FACE_ENGINE": "cv",
                         })
    try:
        base = "http://127.0.0.1:%d" % port
        if not wait_backend_ready(base, proc, timeout_s=120):
            bad("目标 exe 未能就绪")
            return
        ok("目标 exe（authserver.exe 与 face-models 同级）能启动并就绪")

        st, r = http_call(base, "POST", "/api/auth/login",
                          body={"username": "admin", "password": "Admin123"})
        ticket = (r.get("data") or {}).get("ticket")
        if not ticket:
            bad("admin 登录未拿到票据（st=%s code=%s）" % (st, r.get("code")))
            return
        st, r2 = http_call(base, "GET", "/api/auth/face", ticket=ticket)
        ready = bool((r2.get("data") or {}).get("engineReady"))
        (ok if ready else bad)("接口 /api/auth/face 报 engineReady=%s" % ready)
    finally:
        stop_backend(proc)

    time.sleep(0.5)
    text = decode_log(open(log, "rb").read())
    (ok if "[Face] 引擎就绪" in text else bad)("启动日志出现「[Face] 引擎就绪」")
    (ok if "[Face] 第二因子已就绪" in text else bad)("启动日志出现「第二因子已就绪」")
    (ok if "引擎不可用" not in text else bad)("启动过程中**未**出现「引擎不可用」")
    for line in text.splitlines():
        if "[Face]" in line:
            print("        " + line.strip())


def step2_full_probe(port, db_name):
    """把 face_second_factor_probe 的全部断言打到目标 exe 上。"""
    print("\n[步骤二] 全量断言打到目标 exe（Debug 探针覆盖不到的那条链路）")
    probe = os.path.join(TOOLS_DIR, "face_second_factor_probe.py")
    exe = os.path.join(TARGET, "authserver.exe")
    cmd = [sys.executable, probe, exe, str(port), "--db", db_name]
    print("        " + " ".join(cmd))
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    out, _ = proc.communicate()          # ⚠️ 同进程 wait，别让子进程变孤儿
    text = decode_log(out)
    tail = [ln for ln in text.splitlines() if "结论" in ln or "断言" in ln]
    for ln in tail:
        print("        " + ln.strip())
    if proc.returncode == 0:
        ok("目标 exe 上 77 项断言全部通过")
    else:
        bad("目标 exe 上探针未通过（exit=%s）" % proc.returncode)
        line = [ln for ln in text.splitlines() if "[FAIL]" in ln]
        for ln in line[:10]:
            print("        " + ln.strip())


def main():
    global TARGET
    argv = sys.argv[1:]

    # 模式二：--install-dir <真实装机目录>
    # ⚠️ 必须先把它从 argv 里摘掉再交给 resolve_probe_db：后者的第 2 条规则会把
    #    「首个非 -- 开头的位置参数」当库名，那个路径过不了 `_guard()`（不含 Probe）
    #    就会直接把脚本 SystemExit 掉。
    install_dir = None
    rest = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--install-dir" and i + 1 < len(argv):
            install_dir = os.path.expandvars(argv[i + 1])
            i += 2
            continue
        if a.startswith("--install-dir="):
            install_dir = os.path.expandvars(a.split("=", 1)[1])
            i += 1
            continue
        rest.append(a)
        i += 1

    ports = [a for a in rest if a.isdigit()]
    port = int(ports[0]) if ports else 5700
    db_name = resolve_probe_db("AuthBaselineFaceReleaseProbe", rest)

    print("=" * 70)
    print("  人脸模块 · 装机产物校验（Release / 单文件 / NSIS 布局）")
    print("  模式: %s" % ("真实装机目录" if install_dir else "自建镜像"))
    print("  目标: %s" % (install_dir or MIRROR))
    print("  库:   %s（须含 Probe）" % db_name)
    print("=" * 70)

    if install_dir:
        TARGET = use_install_dir(install_dir)
    else:
        TARGET = build_mirror()
    if TARGET is None:
        return 1

    check_target_layout(TARGET)

    db = ProbeDb(db_name)
    db.drop_if_exists()
    try:
        step1_real_engine(port, db_name)
        step2_full_probe(port + 1, db_name)
    finally:
        db.drop_if_exists()
        print("\n[清理] 测试库已清理：%s" % db_name)

    print("\n" + "=" * 70)
    print("  断言：%d 项通过 / %d 项失败" % (len(PASSED), len(FAILED)))
    if FAILED:
        for m in FAILED:
            print("    ✗ %s" % m)
        print("  结论：FAIL — 装机产物未通过，**不要发布**")
        print("=" * 70)
        return 1
    print("  结论：PASS  装机产物（单文件 exe + 磁盘模型）行为与 Debug 一致")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
