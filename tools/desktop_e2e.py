r"""桌面端界面级验证：启动安装版 → 登录 → 截图 → 可选制造篡改并截告警弹窗。

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
  click:x坐标x y坐标  在当前窗口相对坐标点击（坐标之间用 x 分隔）
  shot:文件名         再截一张（存到 tools/ 下）
  tamper              直接改数据库制造篡改（需要 python 驱动 pymongo）
  deny                从应用之外直接用 HTTP 打管理接口，复现"越权访问被拒"

环境变量：
  E2E_APPDIR   覆盖安装目录（默认 %LOCALAPPDATA%\AuthBaseline）
  E2E_SETTLE   首次截图前的等待秒数（默认 16）
  E2E_TAMPER_WAIT  篡改后等待自动巡检弹窗的秒数（默认 8，巡检周期 30s 需调大）
  E2E_DENY_WAIT    越权后等待巡检弹窗的秒数（默认 14，越权巡检周期 10s）
"""
import ctypes
import os
import re
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

APP_DIR = Path(os.environ.get(
    "E2E_APPDIR", os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/AppData/Local"), "AuthBaseline")))
EXE = APP_DIR / "auth-baseline-desktop.exe"
TITLE_KEY = "基线系统"
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
    """用 PrintWindow(PW_RENDERFULLCONTENT) 抓窗口自身内容，不依赖 z-order。

    抓图前必须先确认窗口不是最小化状态：最小化时 GetWindowRect 返回的
    是标题栏那条窄条（实测形如 237x39），抓出来的图看不出任何界面内容，
    却会被误读成"界面渲染失败"。real_click 里为解除前台锁定会做一次
    最小化→还原，若还原没生效就会留下这个状态。
    """
    if user32.IsIconic(hwnd):
        user32.ShowWindow(hwnd, 9)   # SW_RESTORE
        user32.BringWindowToTop(hwnd)
        time.sleep(1.0)

    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    x0, y0 = rect.left, rect.top
    w, h = rect.right - rect.left, rect.bottom - rect.top
    if w <= 0 or h <= 0:
        print(f"窗口尺寸异常 {w}x{h}")
        return False
    if h < 200:
        # 多半是还原失败还没生效，再等一轮
        time.sleep(1.5)
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        w, h = rect.right - rect.left, rect.bottom - rect.top
        if h < 200:
            print(f"!! 窗口高度仅 {h}px，疑似仍处于最小化/异常状态，截图可能无效")

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
    # 用 getcolors 而不是 set(img.getdata())：后者对 1942x1286 要建一个
    # 250 万元素的集合，慢且在 Pillow 14 起 getdata 被弃用。
    colors = len(img.getcolors(maxcolors=w * h) or [])
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
    """把窗口置前，按窗口相对坐标 (rx, ry) 点击（窗口坐标含标题栏）。

    注意：必须先最小化再还原，再补一次 ALT 键，才能真正解除
    SetForegroundWindow 的前台锁定。否则窗口看似在前，键盘焦点其实还在
    原前台窗口上，表现为"点进了输入框、但打进去的字一个都没出现"。
    """
    if user32.IsIconic(hwnd):
        user32.ShowWindow(hwnd, 9)
    user32.ShowWindow(hwnd, 6)          # SW_MINIMIZE
    time.sleep(0.4)
    user32.ShowWindow(hwnd, 9)          # SW_RESTORE
    user32.BringWindowToTop(hwnd)
    user32.keybd_event(0x12, 0, 0, 0)   # ALT 按下
    user32.keybd_event(0x12, 0, 2, 0)   # ALT 抬起
    user32.SetForegroundWindow(hwnd)
    time.sleep(0.5)

    # 还原后窗口位置可能变化，坐标要重新取一次
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    sx, sy = rect.left + int(rx), rect.top + int(ry)
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
    """发送一次按键。

    方向键 / PageUp / PageDown / Home / End 属于**扩展键**，
    keybd_event 必须带上 KEYEVENTF_EXTENDEDKEY，否则 WebView2 侧收不到，
    表现为"按了 PageDown 页面纹丝不动"。
    """
    EXTENDED = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2D, 0x2E}
    ext = 0x0001 if key in EXTENDED else 0
    user32.keybd_event(key, 0, ext, 0)
    time.sleep(0.04)
    user32.keybd_event(key, 0, ext | 0x0002, 0)
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


def find_backend_port():
    """反查 sidecar 后端当前监听的端口。

    桌面端端口是动态分配的，越权请求必须现查 —— 写死端口只会打到空气上。
    从进程名过滤出 PID，再用 netstat 找出归属它的 LISTENING 行。
    """
    try:
        tl = subprocess.run(
            ["tasklist", "/fi", "imagename eq authserver.exe", "/fo", "csv", "/nh"],
            capture_output=True).stdout.decode("gbk", "replace")
        m = re.search(r'"authserver\.exe","(\d+)"', tl, re.I)
        if not m:
            return None
        pid = m.group(1)
        ns = subprocess.run(["netstat", "-ano"],
                            capture_output=True).stdout.decode("gbk", "replace")
        for line in ns.splitlines():
            parts = line.split()
            if (len(parts) >= 5 and parts[0] == "TCP"
                    and parts[3] == "LISTENING" and parts[4] == pid):
                return int(parts[1].rsplit(":", 1)[1])
    except Exception as e:
        print(f"  探测后端端口失败: {e}")
    return None


def deny_audit():
    """从应用之外直接打管理接口，复现「越权访问被拒」。

    与 tamper 步骤是对称的两种"绕过应用"：
      tamper = 有人绕过应用直接改库（改不掉）；
      deny   = 有人绕过界面直接读审计数据（看不到）。

    这里刻意不带任何凭证，就是 curl / PowerShell 的裸请求 ——
    界面完全看不到这种尝试，唯一能证明它发生过的是服务端写下的
    AUDIT_ACCESS_DENIED 事件。
    """
    import urllib.error
    import urllib.request

    port = find_backend_port()
    if not port:
        print("  未找到后端监听端口，跳过越权尝试")
        return
    print(f"  后端端口 {port}")
    # 两条路径都打：新版审计接口 + 旧版兼容路径（后者曾是"声明即管理员"的漏洞入口）
    for path in ("/api/audit/logs", "/api/auth/logs?adminUsername=admin"):
        url = f"http://127.0.0.1:{port}{path}"
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                print(f"  越权尝试 {path} -> HTTP {r.status}（异常：竟然放行了）")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:90]
            print(f"  越权尝试 {path} -> HTTP {e.code} {body}")
        except Exception as e:
            print(f"  越权尝试 {path} -> 请求失败 {e}")


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
            elif step.startswith("key:"):
                # 发送单个按键：key:esc / key:enter / key:tab / key:space
                # 方向键（key:down / key:up）用于在原生 select 展开的列表里移动选项，
                # 这是筛选下拉框最稳的驱动方式 —— 选项列表由系统渲染，坐标不可预知。
                # Esc 用于关闭模态子窗口（AppWindow 监听 document 的 Escape）
                name = step.split(":", 1)[1].strip().lower()
                vk = {"esc": 0x1B, "enter": 0x0D, "tab": 0x09, "space": 0x20,
                      "pgdn": 0x22, "pgup": 0x21, "end": 0x23, "home": 0x24,
                      "down": 0x28, "up": 0x26, "left": 0x25, "right": 0x27}.get(name)
                if vk is None:
                    print(f"未知按键: {name}")
                else:
                    press(vk)
                    print(f"按键 {name}")
            elif step.startswith("wheel:"):
                # 滚轮：wheel:-6 向下滚 6 格，wheel:6 向上。
                # 审计页表格很长，分页控件在最底部，必须先把光标移到页面中间
                # 再滚，否则滚轮会打在别的窗口上。
                n = int(step.split(":", 1)[1])
                rect = wintypes.RECT()
                user32.GetWindowRect(hwnd, ctypes.byref(rect))
                user32.SetCursorPos((rect.left + rect.right) // 2,
                                    (rect.top + rect.bottom) // 2)
                time.sleep(0.3)
                user32.mouse_event.argtypes = [
                    ctypes.c_uint, ctypes.c_uint, ctypes.c_uint,
                    ctypes.c_uint, ctypes.c_void_p
                ]
                step_delta = 0xFFFFFF88 if n < 0 else 120   # -120 的无符号写法
                for _ in range(abs(n)):
                    user32.mouse_event(0x0800, 0, 0, step_delta, 0)
                    time.sleep(0.12)
                print(f"滚轮 {n}")
            elif step.startswith("shot:"):
                name = step.split(":", 1)[1]
                capture(hwnd, Path("tools") / name)
            elif step == "deny":
                # 越权巡检周期 10s，等足一轮再截图，确保弹窗有机会出现
                deny_audit()
                time.sleep(float(os.environ.get("E2E_DENY_WAIT", "14")))
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
