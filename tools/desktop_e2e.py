"""桌面端界面级验证：启动安装版 → 登录 → 截图 → 可选制造篡改并截告警弹窗。

为什么必须在同一进程里完成：调用方 shell 退出后子进程会被回收，
分步执行拿不到窗口。

为什么加 `--single-process --disable-gpu`：
本机 WebView2（152.0.4191.66）的多进程 + GPU 合成路径**渲染不出画面**
（窗口全白，随后转全黑，前端与后端其实都正常）。
实测加上这两个参数后界面完整渲染（同一张图颜色数从 ~330 跳到 ~5700）。
这一对参数已经写进 src-tauri/tauri.conf.json 的 additionalBrowserArgs，
所以正式安装版不依赖外部环境变量；这里设置只是为了让未重装的旧包也能验证。

用法：
  python tools/desktop_e2e.py <输出图片> [步骤]
步骤（逗号分隔）：
  login:用户名:密码   在登录页填写并提交
  wait:秒             等待
  click:x,y           在当前窗口相对坐标点击
  shot:文件名         再截一张（存到 tools/ 下）
  tamper              直接改数据库制造篡改（需要 mongosh 或 python 驱动）
"""
import ctypes
import os
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

APP_DIR = Path(os.environ.get(
    "E2E_APPDIR", r"<用户目录>\AppData\Local\Programs\AuthBaseline"))
EXE = APP_DIR / "auth-baseline-desktop.exe"
TITLE_KEY = "口令认证基线系统"
# 与 tauri.conf.json 保持一致，保证未重装的旧包也能正常渲染
BROWSER_ARGS = ("--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection "
                "--single-process --disable-gpu")

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    try:
        user32.SetProcessDPIAware()
    except Exception:
        pass


def kill_leftovers():
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-Process -Name 'auth-baseline-desktop' | Stop-Process -Force;"
        "Get-CimInstance Win32_Process"
        " | Where-Object { $_.Name -eq 'msedgewebview2.exe' }"
        f" | Where-Object {{ $_.CommandLine -like '*{APP_DIR}*'"
        " -or $_.CommandLine -like '*ab-wv2-*' }"
        " | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
    )
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, timeout=40)
        time.sleep(2.0)
    except Exception:
        pass


def launch():
    env = dict(os.environ)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = BROWSER_ARGS
    return subprocess.Popen(
        [str(EXE)], cwd=str(APP_DIR), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=0x00000008 | 0x00000200)


def find_window(timeout=45):
    deadline = time.time() + timeout
    found = []

    def cb(hwnd, _):
        if user32.IsWindowVisible(hwnd):
            n = user32.GetWindowTextLengthW(hwnd)
            if n:
                buf = ctypes.create_unicode_buffer(n + 1)
                user32.GetWindowTextW(hwnd, buf, n + 1)
                if TITLE_KEY in buf.value:
                    found.append((hwnd, buf.value))
        return True

    cb_ptr = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND,
                                wintypes.LPARAM)(cb)
    while time.time() < deadline:
        found.clear()
        user32.EnumWindows(cb_ptr, 0)
        if found:
            return found[0]
        time.sleep(0.5)
    return None, None


def _bih():
    class BIH(ctypes.Structure):
        _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG),
                    ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD),
                    ("biBitCount", wintypes.WORD),
                    ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD),
                    ("biXPelsPerMeter", wintypes.LONG),
                    ("biYPelsPerMeter", wintypes.LONG),
                    ("biClrUsed", wintypes.DWORD),
                    ("biClrImportant", wintypes.DWORD)]
    return BIH


def capture(hwnd, out):
    """用 PrintWindow(PW_RENDERFULLCONTENT) 抓窗口自身内容，不依赖 z-order。"""
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    x0, y0 = rect.left, rect.top
    w, h = rect.right - rect.left, rect.bottom - rect.top
    if w <= 0 or h <= 0:
        print(f"窗口尺寸异常 {w}x{h}")
        return False

    hdc = user32.GetWindowDC(hwnd)
    mem = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
    gdi32.SelectObject(mem, bmp)
    user32.PrintWindow(hwnd, mem, 0x00000002)

    BIH = _bih()
    bi = BIH()
    bi.biSize = ctypes.sizeof(BIH)
    bi.biWidth, bi.biHeight = w, -h
    bi.biPlanes, bi.biBitCount = 1, 32
    buf = ctypes.create_string_buffer(w * h * 4)
    gdi32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(bi), 0)

    from PIL import Image
    img = Image.frombuffer("RGBA", (w, h), buf, "raw", "BGRA", 0, 1).convert("RGB")
    img.save(out)
    colors = len(set(img.getdata()))
    g = img.convert("L").histogram()
    total = w * h
    dark = sum(g[:12])
    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mem)
    user32.ReleaseDC(hwnd, hdc)
    print(f"截图已保存: {out}（{w}x{h}，非黑 {100 * (total - dark) / total:.1f}%，"
          f"颜色数 {colors}）")
    return colors > 500


def real_click(hwnd, rx, ry):
    """把窗口置前，按窗口相对坐标 (rx, ry) 点击（窗口坐标含标题栏）。"""
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    sx, sy = rect.left + int(rx), rect.top + int(ry)
    user32.ShowWindow(hwnd, 9)
    user32.BringWindowToTop(hwnd)
    user32.SetForegroundWindow(hwnd)
    time.sleep(0.5)
    user32.SetCursorPos(sx, sy)
    time.sleep(0.25)
    user32.mouse_event(0x0002, 0, 0, 0, 0)
    time.sleep(0.06)
    user32.mouse_event(0x0004, 0, 0, 0, 0)
    time.sleep(0.7)


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]


class _INPUT(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("ki", _KEYBDINPUT),
                ("_pad", ctypes.c_ubyte * 8)]


def type_text(text):
    """用 SendInput 以 Unicode 方式逐字符输入（支持中文与特殊字符）。"""
    UNICODE, KEYUP = 0x0004, 0x0002
    for ch in text:
        for flags in (UNICODE, UNICODE | KEYUP):
            inp = _INPUT()
            inp.type = 1
            inp.ki.wScan = ord(ch)
            inp.ki.dwFlags = flags
            user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(_INPUT))
            time.sleep(0.012)
        time.sleep(0.02)


def press(key):
    user32.keybd_event(key, 0, 0, 0)
    time.sleep(0.04)
    user32.keybd_event(key, 0, 2, 0)
    time.sleep(0.06)


def tamper_db():
    """直接改数据库里最新一条审计记录的字段，制造"被篡改"。

    重要：Mongo 里的字段名是 camelCase（selfHash / prevHash / seq / shard）。
    改造前的旧记录（AuditLogs 主集合）没有 selfHash，不参与哈希链校验，
    所以要在带 selfHash 的最新记录（通常在 AuditLogs_yyyyMM 分片）上动手。

    刻意只改 action、不改 selfHash —— 这样重算哈希链必然对不上，
    前端完整性巡检会在一个周期内发现断裂并弹出阻断式告警，
    正好验证"直接在数据库非法修改也会弹窗"。
    """
    try:
        import pymongo
    except ImportError:
        print("缺少 pymongo，无法自动篡改；请手动改库后重跑")
        return False
    try:
        cli = pymongo.MongoClient("mongodb://localhost:27017",
                                  serverSelectionTimeoutMS=5000)
        db = cli["AuthBaselineDb"]
        coll_name, doc = None, None
        for name in db.list_collection_names():
            if not name.startswith("AuditLogs"):
                continue
            d = db[name].find_one({"selfHash": {"$exists": True}},
                                  sort=[("seq", -1)])
            if d and (doc is None or (d.get("seq") or 0) > (doc.get("seq") or 0)):
                coll_name, doc = name, d
        if not doc:
            print("库里没有带 selfHash 的审计记录（旧数据不参与链校验）")
            return False
        res = db[coll_name].update_one(
            {"_id": doc["_id"]},
            {"$set": {"action": "TAMPERED_BY_ATTACKER",
                      "target": "直接改库测试"}})
        print(f"已篡改库中记录 seq={doc.get('seq')} 集合={coll_name} "
              f"（matched={res.matched_count}，selfHash 保持原值不动）")
        return res.matched_count == 1
    except Exception as e:
        print(f"篡改失败: {type(e).__name__}: {e}")
        return False


def main():
    if not EXE.exists():
        print(f"未找到 {EXE}")
        return 2
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "tools/desktop_audit.png")
    settle = float(os.environ.get("E2E_SETTLE", "16"))
    steps = sys.argv[2] if len(sys.argv) > 2 else ""

    kill_leftovers()
    proc = launch()
    print(f"桌面壳 PID={proc.pid}，等待界面渲染…")

    hwnd, title = find_window()
    if not hwnd:
        print("未找到应用窗口")
        print(f"  进程存活: {proc.poll() is None}")
        return 1
    print(f"窗口: {title} hwnd={hwnd}")

    time.sleep(settle)
    ok = capture(hwnd, out)

    for step in steps.split(","):
        step = step.strip()
        if not step:
            continue
        try:
            if step.startswith("wait:"):
                time.sleep(float(step.split(":", 1)[1]))
            elif step.startswith("login:"):
                _, user, pwd = step.split(":", 2)
                # 坐标点击容易受 DPI/布局影响，改成先点表单区域拿焦点，
                # 再用 Tab 在"用户名 → 密码"之间切换，最后 Enter 提交。
                real_click(hwnd, 1223, 614)      # 用户名输入框
                time.sleep(0.4)
                type_text(user)
                press(0x09)                       # Tab -> 密码
                time.sleep(0.3)
                type_text(pwd)
                press(0x0D)                       # Enter 提交
                print(f"已提交登录 {user}")
                time.sleep(3.0)
            elif step.startswith("click:"):
                # 坐标用 x 分隔，避免与逗号分隔的步骤列表冲突，例如 click:100x327
                rx, ry = step.split(":", 1)[1].split("x")
                real_click(hwnd, float(rx), float(ry))
                print(f"点击 ({rx},{ry})")
            elif step.startswith("shot:"):
                name = step.split(":", 1)[1]
                capture(hwnd, Path("tools") / name)
            elif step == "tamper":
                tamper_db()
                time.sleep(float(os.environ.get("E2E_TAMPER_WAIT", "8")))
            else:
                print(f"未知步骤: {step}")
        except Exception as e:
            print(f"步骤 {step} 失败: {type(e).__name__}: {e}")

    print(f"\n最终进程存活={proc.poll() is None}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
