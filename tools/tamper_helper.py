#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
手动测试实验二「改不掉」的辅助工具。

配合 MongoDB Compass 使用：Compass 负责"改"，本脚本负责"还原 + 复检"。

为什么需要还原：tamper 演示只改 action 字段、不动 selfHash，
所以只要把值改回原样，该条哈希自动重新匹配，链即刻复原，
不需要重签任何后续记录。前提是**你必须记得改前的原值**。

用法：
    python tools/tamper_helper.py show          # 显示链尾若干条（改前先抄下原值）
    python tools/tamper_helper.py verify        # 校验当前链是否完整
    python tools/tamper_helper.py restore <seq> <原action> <原target>
                                                # 按记录的原值还原
    python tools/tamper_helper.py watch         # 轮询监测，直到发现链断裂
"""
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pymongo

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "AuthServer" / "publish" / "AuthServer.exe"
DB = pymongo.MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=3000)["AuthBaselineDb"]


def shards():
    return [n for n in DB.list_collection_names() if n.startswith("AuditLogs")]


def find_by_seq(seq):
    for name in shards():
        d = DB[name].find_one({"seq": seq})
        if d:
            return name, d
    return None, None


def cmd_show():
    """列出链尾记录，供测试前抄写原值。"""
    docs = []
    for name in shards():
        docs.extend(DB[name].find({"selfHash": {"$exists": True}}))
    docs.sort(key=lambda d: d["seq"], reverse=True)
    print("链尾最新 8 条（改库前请记下目标记录的 action / target 原值）：\n")
    print("  %-6s %-28s %-20s %s" % ("seq", "action", "target", "timestamp"))
    print("  " + "-" * 78)
    for d in docs[:8]:
        print("  %-6s %-28s %-20s %s" % (
            d["seq"], d.get("action", ""), repr(d.get("target"))[:20], d.get("timestamp")))
    print("\n注意：action 是受哈希保护的字段，改它就会触发告警。")
    print("选一条记下原值，例如： python tools/tamper_helper.py restore 399 AUDIT_VERIFY audit/verify")


def cmd_verify():
    """起后端并调校验接口，报告链状态。"""
    PORT = 5213
    proc = subprocess.Popen([str(EXE), "--urls", "http://127.0.0.1:%d" % PORT],
                            cwd=str(EXE.parent),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        t0 = time.time()
        while time.time() - t0 < 40:
            try:
                socket.create_connection(("127.0.0.1", PORT), timeout=1).close()
                break
            except OSError:
                time.sleep(0.4)
        else:
            print("后端未就绪")
            return 1

        def req(method, path, body=None, headers=None):
            h = {"Host": "127.0.0.1", "Connection": "close", "Accept": "application/json"}
            data = None
            if body is not None:
                h["Content-Type"] = "application/json"
                data = json.dumps(body).encode()
            h["Content-Length"] = str(len(data or b""))
            h.update(headers or {})
            raw = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
            s = socket.create_connection(("127.0.0.1", PORT), timeout=20)
            s.sendall(raw.encode() + (data or b""))
            buf = b""
            while True:
                try:
                    c = s.recv(65536)
                except Exception:
                    break
                if not c:
                    break
                buf += c
            s.close()
            head, _, payload = buf.partition(b"\r\n\r\n")
            # 后端对大响应会用 chunked 传输，不解码的话 payload 是空的，
            # json.loads 会直接抛 JSONDecodeError。
            if "Transfer-Encoding: chunked" in head.decode("latin1"):
                out, rest = b"", payload
                while True:
                    line, _, rest = rest.partition(b"\r\n")
                    if not line:
                        break
                    try:
                        n = int(line.split(b";")[0], 16)
                    except ValueError:
                        break
                    if n == 0:
                        break
                    out += rest[:n]
                    rest = rest[n + 2:]
                payload = out
            return json.loads(payload)

        j = req("POST", "/api/auth/login", {"username": "admin", "password": "Admin123"})
        tok = (j.get("data") or {}).get("ticket")
        r = req("GET", "/api/audit/verify", headers={"Authorization": "Bearer " + tok})
        d = r.get("data") or {}
        if d.get("intact"):
            print("链完整：%s 条记录全部自洽" % d.get("checked"))
        else:
            print("链已断裂！")
            print("  断裂序号：%s" % d.get("firstBrokenSeq"))
            print("  所在分片：%s" % d.get("brokenShard"))
            print("  断裂原因：%s" % d.get("brokenReason"))
            print("  期望哈希：%s" % str(d.get("expected"))[:32])
            print("  实际哈希：%s" % str(d.get("actual"))[:32])
        return 0 if d.get("intact") else 2
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


def cmd_restore(seq, action, target):
    """把指定记录恢复为原值，哈希随之自动复原。"""
    name, d = find_by_seq(int(seq))
    if not d:
        print("找不到 seq=%s 的记录" % seq)
        return 1
    before = {k: d.get(k) for k in ("action", "target")}
    DB[name].update_one({"_id": d["_id"]}, {"$set": {"action": action, "target": target}})
    print("已还原 seq=%s：%s -> action=%s target=%s" % (seq, before, action, target))
    print("接着运行 verify 确认链已复原。")
    return 0


def cmd_watch(timeout=90):
    """轮询链状态，直到发现断裂或超时。用于配合 Compass 改库。"""
    PORT = 5214
    proc = subprocess.Popen([str(EXE), "--urls", "http://127.0.0.1:%d" % PORT],
                            cwd=str(EXE.parent),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        t0 = time.time()
        while time.time() - t0 < 40:
            try:
                socket.create_connection(("127.0.0.1", PORT), timeout=1).close()
                break
            except OSError:
                time.sleep(0.4)
        print("监测中（最多 %d 秒）… 现在去 Compass 改库" % timeout)
        t0 = time.time()
        last = None
        while time.time() - t0 < timeout:
            name, _ = None, None
            docs = []
            for n in shards():
                docs.extend(DB[n].find({"selfHash": {"$exists": True}}))
            docs.sort(key=lambda d: d["seq"])
            expected = "0" * 64
            broken = None
            for d in docs:
                if d.get("prevHash") != expected:
                    broken = (d["seq"], "prevHash 不匹配")
                    break
                expected = d.get("selfHash")
            if broken:
                print("\n检出断裂！seq=%s（%s）" % broken)
                print("→ 桌面端应在 30 秒内弹出告警窗口")
                return 0
            if last != len(docs):
                print("  …已检查 %d 条，链完整" % len(docs))
                last = len(docs)
            time.sleep(3)
        print("超时未发现断裂")
        return 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    c = sys.argv[1]
    if c == "show":
        return cmd_show()
    if c == "verify":
        return cmd_verify()
    if c == "watch":
        return cmd_watch(int(sys.argv[2]) if len(sys.argv) > 2 else 90)
    if c == "restore":
        if len(sys.argv) < 5:
            print("用法：restore <seq> <原action> <原target>")
            return 1
        return cmd_restore(sys.argv[2], sys.argv[3], sys.argv[4])
    print("未知命令：%s" % c)
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
