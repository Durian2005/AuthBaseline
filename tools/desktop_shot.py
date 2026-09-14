"""一体化：启动桌面程序 -> 等界面就绪 -> 截取窗口真实画面 -> 驱动界面 -> 退出。

为什么合并成一个脚本：进程在调用方 shell 退出时会被回收，
分两步（先启动再截屏）拿不到窗口，必须同一进程内完成全部动作。

截图方式的选择（都实测过）：
  * PrintWindow / PW_RENDERFULLCONTENT —— WebView2 走 D3D 合成，拿到的是黑面，弃用。
  * WebView2 CDP Page.captureScreenshot —— 理论上最好，但本机上 Tauri 壳
    的 WebView2 调试端口只存活约 13 秒（前 5 秒可用），时序极不稳定，弃用。
  * 屏幕 BitBlt（采用）—— 把窗口置顶后用 GetDC(NULL) 抓窗口矩形区域，
    所见即所得，WebView2 内容完整，稳定可靠。

用法：
  python tools/desktop_shot.py [输出图片] [等待秒数] [操作脚本]
   操作脚本可选，逗号分隔的动作：
     login:admin:Admin123   登录
     click:AUDIT            点侧边栏"审计日志"
     sleep:2                等待
"""
import ctypes
import os
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

APP_DIR = Path(os.environ.get(
    "E2E_APPDIR", r"<用户目录>\AppData\Local\AuthBaseline"))
EXE = APP_DIR / "auth-baseline-desktop.exe"
TITLE_KEY = "口令认证基线系统"

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
    return subprocess.Popen(
        [str(EXE)], cwd=str(APP_DIR), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=0x00000008 | 0x00000200)


def find_window(timeout=60):
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

    cb_ptr = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)(cb)
    while time.time() < deadline:
        found.clear()
        user32.EnumWindows(cb_ptr, 0)
        if found:
            hwnd, title = found[0]
            rect = wintypes.RECT()
            user32.GetWindowRect(hwnd, ctypes.byref(rect))
            if rect.right - rect.left > 200 and rect.bottom - rect.top > 150:
                return hwnd, title
        time.sleep(0.5)
    return None, None


BIH_FIELDS = [
    ("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG),
    ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD),
    ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
    ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
    ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
    ("biClrImportant", wintypes.DWORD)]


def capture(hwnd, out, settle=1.5):
    """把窗口置顶，从屏幕抓取窗口矩形区域。

    为了真的让窗口到最前，先最小化再还原（SW_MINIMIZE -> SW_RESTORE），
    这样能绕开 SetForegroundWindow 在后台进程上的前台锁定。
    """
    if user32.IsIconic(hwnd):
        user32.ShowWindow(hwnd, 9)
    user32.ShowWindow(hwnd, 6)          # SW_MINIMIZE
    time.sleep(0.5)
    user32.ShowWindow(hwnd, 9)          # SW_RESTORE
    user32.BringWindowToTop(hwnd)

    # ALT 键"敲"一下，解除前台锁定后再置前
    user32.keybd_event(0x12, 0, 0, 0)
    user32.keybd_event(0x12, 0, 2, 0)
    user32.SetForegroundWindow(hwnd)
    time.sleep(settle)

    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    x, y = rect.left, rect.top
    w, h = rect.right - rect.left, rect.bottom - rect.top
    if w <= 0 or h <= 0:
        print(f"窗口尺寸异常 {w}x{h}")
        return False

    screen = user32.GetDC(0)
    mem = gdi32.CreateCompatibleDC(screen)
    bmp = gdi32.CreateCompatibleBitmap(screen, w, h)
    gdi32.SelectObject(mem, bmp)
    # SRCCOPY | CAPTUREBLT：必须带 CAPTUREBLT 才能抓到分层/合成窗口
    if not gdi32.BitBlt(mem, 0, 0, w, h, screen, x, y, 0x00CC0020 | 0x40000000):
        print("BitBlt 失败")

    class BIH(ctypes.Structure):
        _fields_ = BIH_FIELDS

    bi = BIH()
    bi.biSize = ctypes.sizeof(BIH)
    bi.biWidth, bi.biHeight = w, -h
    bi.biPlanes, bi.biBitCount = 1, 32
    buf = ctypes.create_string_buffer(w * h * 4)
    gdi32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(bi), 0)

    from PIL import Image
    img = Image.frombuffer("RGBA", (w, h), buf, "raw", "BGRA", 0, 1)
    img.convert("RGB").save(out)

    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mem)
    user32.ReleaseDC(0, screen)

    # 统计非黑像素比例，判断是否抓到了真实内容
    g = img.convert("L")
    hist = g.histogram()
    total = w * h
    dark = sum(hist[:12])
    print(f"截图已保存: {out}（{w}x{h}，非黑像素 {100 * (total - dark) / total:.1f}%）")
    return True


def click_rel(hwnd, rx, ry):
    """在窗口客户区相对坐标 (rx, ry) 处点击。"""
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    sx, sy = rect.left + int(rx), rect.top + int(ry)
    user32.SetForegroundWindow(hwnd)
    time.sleep(0.4)
    user32.SetCursorPos(sx, sy)
    time.sleep(0.2)
    user32.mouse_event(0x0002, 0, 0, 0, 0)   # LEFTDOWN
    time.sleep(0.05)
    user32.mouse_event(0x0004, 0, 0, 0, 0)   # LEFTUP
    time.sleep(0.6)


def type_text(text):
    """用 SendInput 逐字符输入 ASCII 文本。"""
    KEYEVENTF_UNICODE = 0x0004
    KEYEVENTF_KEYUP = 0x0002

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                    ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                    ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]

    class INPUT(ctypes.Structure):
        _fields_ = [("type", wintypes.DWORD), ("ki", KEYBDINPUT),
                    ("_pad", ctypes.c_ubyte * 8)]

    for ch in text:
        for flags in (KEYEVENTF_UNICODE, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP):
            inp = INPUT()
            inp.type = 1
            inp.ki.wScan = ord(ch)
            inp.ki.dwFlags = flags
            user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))
            time.sleep(0.012)
        time.sleep(0.02)


def main():
    if not EXE.exists():
        print(f"未找到 {EXE}")
        return 2
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "desktop_audit.png")
    settle = float(sys.argv[2] if len(sys.argv) > 2 else "16")
    steps = sys.argv[3] if len(sys.argv) > 3 else ""

    kill_leftovers()
    proc = launch()
    print(f"桌面壳 PID={proc.pid}，等待界面渲染…")

    hwnd, title = find_window(timeout=settle + 20)
    if not hwnd:
        print("未找到应用窗口")
        print(f"  进程存活: {proc.poll() is None}")
        return 1
    print(f"窗口: {title} hwnd={hwnd}")

    # 再等一会儿让 Vue 完成首屏渲染
    time.sleep(settle)

    ok = capture(hwnd, out)

    if steps:
        for step in steps.split(","):
            step = step.strip()
            if not step:
                continue
            if step.startswith("sleep:"):
                time.sleep(float(step.split(":", 1)[1]))
            elif step.startswith("click:"):
                rx, ry = step.split(":", 1)[1].split("x")
                click_rel(hwnd, float(rx), float(ry))
                print(f"点击 ({rx},{ry})")
            elif step.startswith("type:"):
                type_text(step.split(":", 1)[1])
                print("已输入文本")
            elif step.startswith("shot:"):
                name = step.split(":", 1)[1]
                capture(hwnd, Path("tools") / name)
            else:
                print(f"未知步骤: {step}")

    print(f"\n最终进程存活={proc.poll() is None}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
