# -*- coding: utf-8 -*-
"""重装桌面端：卸载旧版 → 静默安装新版 → 校验产物确实被替换。

为什么必须有这个脚本（三条实测踩过的坑）：
  1) **NSIS 静默安装遇到「同版本已安装」会直接跳过替换** —— 退出码 0、文件时间戳不变，
     看起来"装成功了"，实际跑的还是旧版。所以必须先卸载。
  2) **卸载器会把自身复制到 %TEMP% 再重启**，父进程可能先于实际卸载结束就返回 ——
     只等 wait() 会误判"卸完了"。必须轮询目标文件是否真的消失。
  3) **调用安装器/卸载器必须同进程 `Popen().wait()`**：在 Bash 里直接调用时，
     调用方一退出子进程就被回收 —— 退出码 0 但目录毫无变化，且与权限无关，极易误判成权限问题。

校验强度：安装完不是"看着文件在"就算过，而是比对**安装目录里的 sidecar 与
`AuthServer/publish/AuthServer.exe` 的 md5** —— 这样才能证明装进去的确实是新构建的后端。

用法：
    python tools/reinstall_desktop.py                # 用最新的 NSIS 安装包
    python tools/reinstall_desktop.py <setup.exe>    # 指定安装包
    python tools/reinstall_desktop.py --keep         # 不卸载，直接覆盖安装（仅调试用）
"""
import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCAL = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
INSTALL = LOCAL / "AuthBaseline"
MAIN = "auth-baseline-desktop.exe"
SIDECAR = "authserver.exe"
UNINSTALL = "uninstall.exe"

PUBLISHED_SIDECAR = ROOT / "AuthServer" / "publish" / "AuthServer.exe"
BUNDLE_DIR = ROOT / "src-tauri" / "target" / "release" / "bundle" / "nsis"


def md5(path: Path) -> str:
    if not path.is_file():
        return "(缺失)"
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def kill_running() -> None:
    """卸载/安装前必须结束占用文件的进程，否则卸载器删不掉 exe。"""
    for name in (MAIN, SIDECAR):
        subprocess.run(["taskkill", "/F", "/IM", name],
                       capture_output=True, text=True, errors="replace")
    time.sleep(1.5)


def run_and_wait(exe: Path, args, timeout=600) -> int:
    """同进程等待 —— 见模块注释第 3 点。"""
    return subprocess.Popen([str(exe), *args]).wait(timeout=timeout)


def wait_until(predicate, timeout: float, interval: float = 0.5) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def pick_setup() -> Path | None:
    if not BUNDLE_DIR.is_dir():
        return None
    cands = sorted(BUNDLE_DIR.glob("*-setup.exe"), key=lambda p: p.stat().st_mtime, reverse=True)
    return cands[0] if cands else None


def main() -> int:
    argv = [a for a in sys.argv[1:]]
    keep = "--keep" in argv
    argv = [a for a in argv if a != "--keep"]

    setup = Path(argv[0]) if argv else pick_setup()
    if not setup or not setup.is_file():
        print("未找到 NSIS 安装包。请先执行 npm run build（tauri build）")
        return 1

    print("=" * 68)
    print("桌面端重装")
    print(f"  安装包     {setup}")
    print(f"  包 md5     {md5(setup)}  ({setup.stat().st_size:,} 字节)")
    print(f"  参照 sidecar md5  {md5(PUBLISHED_SIDECAR)}")
    print(f"  安装目录   {INSTALL}")
    print("=" * 68)

    kill_running()

    before_main = INSTALL / MAIN
    b_mtime = before_main.stat().st_mtime if before_main.is_file() else None
    print(f"\n[1] 安装前状态：主程序 {'存在' if b_mtime else '不存在'}"
          f"{f'（{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(b_mtime))}）' if b_mtime else ''}")

    if not keep and (INSTALL / UNINSTALL).is_file():
        print("\n[2] 卸载旧版（NSIS 遇同版本会跳过替换，必须先卸）")
        rc = run_and_wait(INSTALL / UNINSTALL, ["/S"])
        print(f"    卸载器退出码 {rc}")
        gone = wait_until(lambda: not before_main.is_file(), timeout=90)
        print(f"    主程序已移除：{'是' if gone else '否（超时）'}")
        if not gone:
            print("    [x] 卸载未完成 —— 可能有进程占用文件，已中止。")
            return 2
    elif keep:
        print("\n[2] 跳过卸载（--keep）")
    else:
        print("\n[2] 未发现已安装版本，跳过卸载")

    print("\n[3] 静默安装新版（/S）")
    rc = run_and_wait(setup, ["/S"])
    print(f"    安装器退出码 {rc}")
    installed = wait_until(lambda: (INSTALL / MAIN).is_file(), timeout=180)
    if not installed:
        print("    [x] 安装后主程序未出现。")
        return 3

    a_mtime = (INSTALL / MAIN).stat().st_mtime
    changed = b_mtime is None or abs(a_mtime - b_mtime) > 1
    print(f"    主程序时间戳 {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(a_mtime))}"
          f"  {'（已替换）' if changed else '（未变化 —— 可能没真正覆盖）'}")

    print("\n[4] 校验装进去的后端确实是新构建（md5 比对，这是关键一步）")
    got = md5(INSTALL / SIDECAR)
    want = md5(PUBLISHED_SIDECAR)
    same = got == want
    print(f"    安装目录 sidecar  md5 {got}")
    print(f"    发布产物   sidecar  md5 {want}")
    print(f"    一致：{'是 [OK]' if same else '否 [x] —— 装进去的不是最新后端'}")

    print("\n[5] 文件完整性检查")
    subprocess.run([sys.executable, str(ROOT / "tools" / "verify_install.py")])

    print("\n结论：%s" % ("重装完成，产物已确认替换" if (same and changed)
                        else "重装完成但校验未通过，见上文"))
    return 0 if (same and changed) else 4


if __name__ == "__main__":
    sys.exit(main())
