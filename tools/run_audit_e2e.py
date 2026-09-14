#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
在**同一进程**里起后端 → 跑四组验收脚本 → 关后端。

为什么需要它：本机沙箱中，调用方 shell 退出会回收其派生的子进程，
所以"先起服务再另开一条命令跑测试"必然连不上（ConnectionRefused）。
把两件事放进一个进程即可绕开。

用法：
    python tools/run_audit_e2e.py            # 跑四组验收
    python tools/run_audit_e2e.py --keep     # 保留注入的篡改数据
"""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "AuthServer" / "publish" / "AuthServer.exe"
PORT = int(os.environ.get("E2E_PORT", "5007"))


def wait_port(port, timeout=45):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.4)
    return False


def main():
    if not EXE.exists():
        print("未找到后端：%s" % EXE)
        return 1

    be_log = Path(os.environ.get("TEMP", ".")) / "be.log"
    env = dict(os.environ)
    env["BE_LOG"] = str(be_log)
    env["BASE"] = "http://localhost:%d" % PORT

    print("启动后端（端口 %d）…" % PORT)
    with open(be_log, "w", encoding="utf-8", errors="replace") as logf:
        proc = subprocess.Popen([str(EXE), "--urls", "http://127.0.0.1:%d" % PORT],
                                cwd=str(EXE.parent), stdout=logf, stderr=subprocess.STDOUT)
    try:
        if not wait_port(PORT):
            print("后端未在超时内就绪，日志尾部：")
            print(be_log.read_text(encoding="utf-8", errors="replace")[-1500:])
            return 1
        print("后端就绪，开始四组验收\n" + "=" * 60)
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "audit_e2e_test.py")] + sys.argv[1:],
                           cwd=str(ROOT), env=env)
        return r.returncode
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
