"""编译后端 + 前端并只打印关键行。

为什么要写成脚本：
  1. 本机 bash 工具链 PATH 是断的，`tail`/`head`/`grep` 全不可用，
     所以过滤必须放在 Python 里做；
  2. `subprocess` 直接用 PIPE 捕获长输出有撑满管道缓冲区的风险
     （见 tools/race_storm_test.py 的踩坑记录），统一重定向到文件再读。

用法：
  python tools/build_all.py            # 后端 Release + 前端
  python tools/build_all.py backend    # 只后端
  python tools/build_all.py frontend   # 只前端
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGDIR = os.path.join(ROOT, "tools", "buildlogs")
DOTNET = r"C:\Program Files\dotnet\dotnet.exe"
NPM = os.environ.get("WB_NPM") or os.path.join(
    os.path.expanduser("~"), ".workbuddy", "binaries", "node",
    "versions", "22.22.2-3", "npm.CMD")

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


def main():
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    codes = []
    if what in ("all", "backend"):
        codes.append(run("dotnet build -c Release",
                         [DOTNET, "build", os.path.join(ROOT, "AuthServer", "AuthServer.csproj"),
                          "-c", "Release", "--nologo"], ROOT, "backend.txt"))
    if what in ("all", "frontend"):
        codes.append(run("vite build (AuthClient)",
                         [NPM, "--prefix", os.path.join(ROOT, "AuthClient"),
                          "run", "build:desktop"], ROOT, "frontend.txt"))
    print("\n总结果:", "全部成功" if all(c == 0 for c in codes) else "有失败 -> %s" % codes)
    return 0 if all(c == 0 for c in codes) else 1


if __name__ == "__main__":
    sys.exit(main())
