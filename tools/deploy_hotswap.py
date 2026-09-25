# -*- coding: utf-8 -*-
"""热替换已安装的桌面端后端与前端，免去重新打安装包。

背景：安装版把后端 sidecar 放在 <安装目录>\\authserver.exe，前端静态资源放在
<安装目录>\\wwwroot。只要这两处换成新构建产物，功能立刻生效，不需要重装。

不能直接覆盖的原因：
  1. 桌面端与后端正持有文件句柄，必须先结束进程；
  2. 进程退出后句柄释放有几秒延迟，复制会偶发 WinError 32，必须带重试；
  3. 覆盖前要留备份，否则出问题没法回滚。

用法：
  python tools/deploy_hotswap.py                 # 后端 + 前端
  python tools/deploy_hotswap.py --backend       # 只换后端
  python tools/deploy_hotswap.py --frontend      # 只换前端
  python tools/deploy_hotswap.py --no-kill       # 不动进程（本次不换 exe 时用）
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/AppData/Local"), "AuthBaseline")
SRC_EXE = os.path.join(ROOT, "AuthServer", "publish", "AuthServer.exe")
SRC_WWW = os.path.join(ROOT, "AuthClient", "dist")
PROCESSES = ["auth-baseline-desktop.exe", "authserver.exe"]


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def kill_all():
    for name in PROCESSES:
        r = subprocess.run(["taskkill", "/F", "/IM", name],
                           capture_output=True, text=True, errors="replace")
        out = (r.stdout or "").strip() or (r.stderr or "").strip()
        print("   taskkill %s -> %s" % (name, out.splitlines()[-1] if out else r.returncode))
    time.sleep(2)


def copy_retry(src, dst, tries=12, wait=2.0):
    """带重试复制：进程刚退出时句柄可能还没释放。"""
    last = None
    for i in range(tries):
        try:
            shutil.copy2(src, dst)
            return True
        except OSError as e:
            last = e
            print("   复制失败(第 %d 次)，%.0f 秒后重试：%s" % (i + 1, wait, e))
            time.sleep(wait)
    print("   !! 复制最终失败：%s" % last)
    return False


def backup(path, stamp):
    """挪走旧文件做备份；同名备份已存在则跳过，避免覆盖掉更早的回滚点。"""
    if not os.path.exists(path):
        return None
    bak = "%s.bak-%s" % (path, stamp)
    if os.path.exists(bak):
        print("   备份已存在，跳过：%s" % os.path.basename(bak))
        return bak
    os.rename(path, bak)
    print("   已备份 -> %s" % os.path.basename(bak))
    return bak


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", action="store_true")
    ap.add_argument("--frontend", action="store_true")
    ap.add_argument("--no-kill", action="store_true")
    ap.add_argument("--install", default=INSTALL)
    a = ap.parse_args()
    do_back = a.backend or not (a.backend or a.frontend)
    do_front = a.frontend or not (a.backend or a.frontend)

    stamp = time.strftime("%Y%m%d-%H%M")
    exe_dst = os.path.join(a.install, "authserver.exe")
    www_dst = os.path.join(a.install, "wwwroot")
    ok = True

    if not os.path.isdir(a.install):
        print("!! 安装目录不存在：%s" % a.install)
        return 1

    # 先校验源文件都在，避免"杀了进程才发现产物不全"
    if do_back and not os.path.exists(SRC_EXE):
        print("!! 找不到发布产物：%s（先跑 npm run publish:backend）" % SRC_EXE)
        return 1
    if do_front and not os.path.exists(os.path.join(SRC_WWW, "index.html")):
        print("!! 找不到前端产物：%s（先跑 build:frontend）" % SRC_WWW)
        return 1

    if not a.no_kill:
        print("[1] 结束桌面端与后端进程")
        kill_all()

    if do_back:
        print("[2] 替换后端 exe")
        backup(exe_dst, stamp)
        ok &= copy_retry(SRC_EXE, exe_dst)

    if do_front:
        print("[3] 替换前端 wwwroot")
        if os.path.isdir(www_dst):
            backup(www_dst, stamp)
        shutil.copytree(SRC_WWW, www_dst)
        print("   已复制 %d 个文件" % sum(len(f) for _, _, f in os.walk(www_dst)))

    print("[4] 校验")
    if do_back:
        a_, b_ = md5(SRC_EXE), md5(exe_dst)
        print("   exe  md5 源=%s 安装=%s  %s" % (a_[:12], b_[:12], "一致" if a_ == b_ else "不一致 !!"))
        ok &= a_ == b_
    if do_front:
        a_, b_ = md5(os.path.join(SRC_WWW, "index.html")), md5(os.path.join(www_dst, "index.html"))
        print("   index.html md5 源=%s 安装=%s  %s" % (a_[:12], b_[:12], "一致" if a_ == b_ else "不一致 !!"))
        ok &= a_ == b_

    print("\n结果：%s" % ("部署成功，可直接启动桌面端" if ok else "有步骤失败，请检查上面的输出"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
