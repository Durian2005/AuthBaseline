# -*- coding: utf-8 -*-
"""界面自验：账号页的「纯人脸登录」卡片（headless Edge + CDP）。

为什么需要这层验证：
  `npm run lint` 与 `vite build` 只能证明"模板能编译"，证明不了
  "这张卡片在后端真实状态下会显示成什么样"。而 P1 的交付物里有一半是**界面语义**：
  未录入 / 已录入 / 模型作废 / 引擎不可用这四种状态必须能被一眼区分，
  且「纯人脸登录」与「刷脸登录（第二因子）」必须是两张卡。

做法（全程 headless，不碰真实库）：
  1. 起后端（独立测试库 + **假引擎** + 明文 HTTP），静态文件取仓库里的 `AuthServer/wwwroot`；
  2. 用 HTTP 登录拿票据，再通过 CDP 把 `auth.ticket` / `auth.currentUser` 写进 localStorage
     —— 等价于"用户已经登录"，避免脚本去驱动登录表单；
  3. 点侧边栏「账号与口令」，滚到卡片，截图 + 断言文案。

用法：
  <faceid venv>/python tools/ui_faceid_check.py
产物：
  tools/evidence/faceid_p1_account_ui.png（`tools/evidence/` 不入库）
"""
import asyncio
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _probe_common import http_call, resolve_probe_db, start_backend, stop_backend, wait_backend_ready

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(ROOT, "AuthServer", "bin", "Debug", "net8.0", "AuthServer.exe")
CONTENT_ROOT = os.path.join(ROOT, "AuthServer")   # dotnet build 不复制 wwwroot，故显式指定内容根
PORT = int(os.environ.get("FACEID_UI_PORT", "5392"))
DEBUG_PORT = int(os.environ.get("FACEID_UI_CDP_PORT", "9451"))
DB = resolve_probe_db("AuthBaselineFaceIdUiProbe")
BASE = "http://127.0.0.1:%d" % PORT
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
SHOT = os.path.join(ROOT, "tools", "evidence", "faceid_p1_account_ui.png")


def cdp_targets():
    with urllib.request.urlopen("http://127.0.0.1:%d/json/list" % DEBUG_PORT, timeout=5) as r:
        return json.loads(r.read().decode("utf-8"))


def wait_target(timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            for t in cdp_targets():
                if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                    return t["webSocketDebuggerUrl"]
        except Exception:
            pass
        time.sleep(0.3)
    raise SystemExit("CDP 页面 target 未就绪")


async def run_ui(ws_url, ticket, user_json):
    import websockets

    async with websockets.connect(ws_url, max_size=32 * 1024 * 1024) as ws:
        counter = {"id": 0}

        async def cmd(method, params=None):
            counter["id"] += 1
            mid = counter["id"]
            await ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
            while True:
                msg = json.loads(await ws.recv())
                if msg.get("id") == mid:
                    return msg

        async def js(expr):
            r = await cmd("Runtime.evaluate", {
                "expression": expr, "awaitPromise": True, "returnByValue": True
            })
            return (r.get("result") or {}).get("result", {}).get("value")

        await cmd("Page.enable")
        await cmd("Runtime.enable")
        await cmd("Page.navigate", {"url": BASE + "/"})
        await asyncio.sleep(1.5)

        # 写入票据与用户缓存（等价于已完成登录），再刷新让应用以已登录状态启动
        await js(
            "localStorage.setItem('auth.ticket', %s);"
            "localStorage.setItem('auth.currentUser', %s);"
            "'ok'" % (json.dumps(ticket), json.dumps(user_json))
        )
        await cmd("Page.reload", {"ignoreCache": True})
        await asyncio.sleep(2.5)

        # 点侧边栏「账号与口令」
        clicked = await js(
            "(() => { const el = [...document.querySelectorAll('button')]"
            ".find(b => (b.textContent || '').includes('账号与口令'));"
            "if (!el) return 'no-nav'; el.click(); return 'clicked'; })()"
        )
        await asyncio.sleep(1.2)

        # 滚到「纯人脸登录」卡片
        await js(
            "(() => { const h = [...document.querySelectorAll('h3')]"
            ".find(e => (e.textContent || '').includes('纯人脸登录'));"
            "if (h) h.scrollIntoView({block:'center'}); return !!h; })()"
        )
        await asyncio.sleep(0.6)

        text = await js("document.body.innerText") or ""
        cards = await js(
            "[...document.querySelectorAll('h3')].map(e => (e.textContent || '').trim())"
        )

        shot = await cmd("Page.captureScreenshot", {"format": "png"})
        data = (shot.get("result") or {}).get("data")
        if data:
            os.makedirs(os.path.dirname(SHOT), exist_ok=True)
            with open(SHOT, "wb") as f:
                f.write(base64.b64decode(data))

        return clicked, text, cards


def main():
    if not os.path.exists(EXE):
        print("未找到后端：%s（先 dotnet build）" % EXE)
        return 2
    if not os.path.isdir(os.path.join(CONTENT_ROOT, "wwwroot")):
        print("未找到 AuthServer/wwwroot（先跑 tools/build_all.py frontend）")
        return 2

    proc = start_backend(EXE, PORT, DB, log_name="faceid_ui_%d.log" % PORT, extra_env={
        "AUTHBASELINE_REQUIRE_HTTPS": "false",
        "AUTHBASELINE_FACEID_ENGINE": "stub",
        "ASPNETCORE_CONTENTROOT": CONTENT_ROOT,
    })
    edge = None
    try:
        if not wait_backend_ready(BASE, proc, timeout_s=90):
            print("后端未就绪")
            return 2

        st, r = http_call(BASE, "POST", "/api/auth/login",
                          body={"username": "admin", "password": "Admin123"})
        ticket = (r.get("data") or {}).get("ticket", "")
        if not ticket:
            print("登录失败：%s %s" % (st, r))
            return 2

        user_json = json.dumps({"username": "admin", "status": "Enabled", "role": "Admin"})

        profile = tempfile.mkdtemp(prefix="faceid-ui-")
        edge = subprocess.Popen([
            EDGE, "--headless=new", "--disable-gpu", "--no-first-run",
            "--remote-debugging-port=%d" % DEBUG_PORT,
            "--user-data-dir=" + profile,
            "--window-size=1280,900",
            "about:blank",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        ws_url = wait_target()
        clicked, text, cards = asyncio.run(run_ui(ws_url, ticket, user_json))

        checks = [
            ("侧边栏可切换到账号页", clicked == "clicked", clicked),
            ("存在「刷脸登录」卡片（第二因子）", "刷脸登录" in (cards or []), cards),
            ("存在「纯人脸登录」卡片（独立登录方式）", "纯人脸登录" in (cards or []), cards),
            ("卡片显示录入状态", "录入状态" in text and "未录入" in text, ""),
            ("卡片显示特征模型身份", "特征模型" in text and "stub:" in text, ""),
            ("卡片声明二次口令要求", "重新输入当前口令" in text, ""),
            ("截图已生成", os.path.exists(SHOT), SHOT),
        ]
        ok = 0
        for name, passed, detail in checks:
            print("  [%s] %s%s" % ("PASS" if passed else "FAIL", name,
                                   ("  -> " + str(detail)) if detail else ""))
            ok += 1 if passed else 0

        print("\n截图：%s" % SHOT)
        print("汇总：%d/%d" % (ok, len(checks)))
        return 0 if ok == len(checks) else 1
    finally:
        if edge is not None:
            try:
                edge.kill()
            except Exception:
                pass
        stop_backend(proc)


if __name__ == "__main__":
    sys.exit(main())
