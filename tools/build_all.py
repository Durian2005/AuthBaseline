"""编译后端 + 前端（两套产物）并只打印关键行。

为什么要写成脚本：
  1. 本机 bash 工具链 PATH 是断的，`tail`/`head`/`grep` 全不可用，
     所以过滤必须放在 Python 里做；
  2. `subprocess` 直接用 PIPE 捕获长输出有撑满管道缓冲区的风险
     （见 tools/race_storm_test.py 的踩坑记录），统一重定向到文件再读。

为什么前端要出两套产物、还要校验一致性：
  同一个 vite 工程有两条分发链路，靠 mode 区分输出目录（见 AuthClient/vite.config.js）：
    默认模式      -> AuthServer/wwwroot   由 ASP.NET Core 静态托管（浏览器访问，同源 /api）
    desktop 模式  -> AuthClient/dist      由 Tauri 打包 / deploy_hotswap 灌进安装目录
  只构建其中一套，另一条链路的产物就会悄悄停在旧版本 —— 之前出过一次：
  wwwroot 落后 dist 15 天，浏览器打开后端时看到的还是旧界面。
  所以这里两套都构建，构建完再逐字节比对，把"忘了同步"变成构建期就能发现的错误。

用法：
  python tools/build_all.py            # 后端 Release + 前端两套产物 + 一致性校验
  python tools/build_all.py backend    # 只后端
  python tools/build_all.py frontend   # 只前端（dist + wwwroot）
  python tools/build_all.py check      # 只做前端产物一致性校验，不构建
"""

import hashlib
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGDIR = os.path.join(ROOT, "tools", "buildlogs")
CLIENT = os.path.join(ROOT, "AuthClient")
DOTNET = r"C:\Program Files\dotnet\dotnet.exe"
NPM = os.environ.get("WB_NPM") or os.path.join(
    os.path.expanduser("~"), ".workbuddy", "binaries", "node",
    "versions", "22.22.2-3", "npm.CMD")

# 两条分发链路的落点，务必与 vite.config.js 的 outDir 保持一致
WWW = os.path.join(ROOT, "AuthServer", "wwwroot")
DIST = os.path.join(CLIENT, "dist")

KEY = re.compile(r":\s*(error|warning)\b|Build succeeded|Build FAILED|\d+ Error|\d+ Warning|"
                 r"error TS|✓ built|built in|transformed", re.IGNORECASE)


def run(name, args, cwd, logfile):
    os.makedirs(LOGDIR, exist_ok=True)
    path = os.path.join(LOGDIR, logfile)
    with open(path, "w", encoding="utf-8", errors="replace") as fh:
        proc = subprocess.run(args, cwd=cwd, stdout=fh, stderr=subprocess.STDOUT)
    text = open(path, encoding="utf-8", errors="replace").read()
    print(f"\n===== {name} (exit={proc.returncode}) =====")
    hits = [ln.rstrip() for ln in text.splitlines() if KEY.search(ln)]
    # 日志里同类报错可能刷屏，去重后仍保留出现次数
    seen = {}
    for ln in hits:
        seen[ln] = seen.get(ln, 0) + 1
    for ln, n in seen.items():
        print(("  x%d " % n) + ln if n > 1 else "  " + ln)
    if not hits:
        print("  (无 error / warning 关键字命中，全文见 %s)" % path)
    return proc.returncode


def snapshot(root):
    """目录 -> {相对路径: md5}；目录不存在返回 None。"""
    if not os.path.isdir(root):
        return None
    out = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            h = md5sum(full)
            if h is not None:
                out[rel] = h
    return out


def md5sum(path):
    try:
        h = hashlib.md5()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def check_frontend_sync():
    """比对后端托管的 wwwroot 与桌面端 dist 是否同一份产物。

    当前两者由同一份源码、两个 mode 构建而来，且源码没有用 import.meta.env
    （运行期靠 '__TAURI_INTERNALS__' in window 判定环境），所以产物逐字节相同。
    一旦这里报不一致，通常意味着"某一套忘了重新构建"。
    若将来确实需要两套产物不同，改这里之前先确认两条分发链路各自要什么。
    """
    www, dist = snapshot(WWW), snapshot(DIST)
    print("\n===== 前端产物一致性（wwwroot vs dist）=====")
    if www is None or dist is None:
        missing = [p for p, s in ((WWW, www), (DIST, dist)) if s is None]
        print("  x 目录不存在：%s" % "、".join(missing))
        print("    先执行：python tools/build_all.py frontend")
        return 1

    only_www = sorted(set(www) - set(dist))
    only_dist = sorted(set(dist) - set(www))
    changed = sorted(k for k in set(www) & set(dist) if www[k] != dist[k])
    if not (only_www or only_dist or changed):
        print("  OK 一致：%d 个文件逐字节相同 -> %s" % (len(www), ", ".join(sorted(www))))
        return 0

    print("  ! 两处产物不一致，后端托管的界面很可能已过期：")
    for k in only_www:
        print("      仅 wwwroot 有 : %s" % k)
    for k in only_dist:
        print("      仅 dist   有  : %s" % k)
    for k in changed:
        print("      内容不同      : %s" % k)
    print("    处置：python tools/build_all.py frontend")
    return 1


def build_frontend():
    codes = [
        run("vite build --mode desktop  -> AuthClient/dist",
            [NPM, "--prefix", CLIENT, "run", "build:desktop"], ROOT, "frontend-desktop.txt"),
        run("vite build                  -> AuthServer/wwwroot",
            [NPM, "--prefix", CLIENT, "run", "build"], ROOT, "frontend-wwwroot.txt"),
    ]
    codes.append(check_frontend_sync())
    return codes


def main():
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    if what == "check":
        return check_frontend_sync()

    codes = []
    if what in ("all", "backend"):
        codes.append(run("dotnet build -c Release",
                         [DOTNET, "build", os.path.join(ROOT, "AuthServer", "AuthServer.csproj"),
                          "-c", "Release", "--nologo"], ROOT, "backend.txt"))
    if what in ("all", "frontend"):
        codes.extend(build_frontend())
    if not codes:
        print("未知参数 %r，见 --help" % what)
        return 2

    print("\n总结果:", "全部成功" if all(c == 0 for c in codes) else "有失败 -> %s" % codes)
    return 0 if all(c == 0 for c in codes) else 1


if __name__ == "__main__":
    sys.exit(main())
