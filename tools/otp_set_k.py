#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
把某个账号的一次性口令链游标挪到指定 k —— 链长、种子、迭代次数一律不动。

背景
====
运维工具 `authserver.exe --rechain` 只能建一条"满配额"的链（k = N-1），
没法把游标放到中间某个位置；而验收常常需要"库里 k 是个位数，
但登录、递减、续链的表现和平时完全一样"。

⚠️ 为什么不能靠"把链长改小"来让 k 变成小数字
    续链线是「k ≤ N × 5%」（OtpVerifier.RenewThresholdPercent，5 是判定契约常量）。
    N=6 时这条线只有 0.3 格，永远够不着 —— 链必然一路走到 0 并报「已用尽」。
    反推：要让 k=3 时仍能触发续链，必须 k×100 ≤ N×5，即 **N ≥ 60**。
    所以「短链 + 小 k + 有续链」三者不可兼得，正确解法是
    「链长保持 1000，只把游标挪到 3」。

它改什么
========
    只写两个字段：`k` 与 `v`。
    `v` 不是随便填的，必须是 x_{k+1} = H^{k+1}(PBKDF2(口令, r))，
    也就是"紧邻 k 的下一格"，由口令现算。判定式仍然是 H(提交值) == v。
    `r` / `length` / `kdfIterations` / `generation` / `createdAt` 一律不动 ——
    没换盐就不是换代，generation 不该 +1。

安全措施
========
    ① 默认干跑（只打印计划），--apply 才写库；
    ② 写库前自动备份整条记录到 tools/evidence/；
    ③ 写库前先用**旧状态**校验口令：H(x_旧k) == 旧v，不成立直接退出，
       口令打错时不会把账号改坏；
    ④ 写入用 CAS（条件 _id + 旧 k + 旧 v），期间有人登录把链推进了就整体不写，
       不会覆盖别人的核销。

用法
====
    set OTP_PASSWORD=<该账号的口令>
    python tools\\otp_set_k.py --username <账号> --k 3
    python tools\\otp_set_k.py --username <账号> --k 3 --apply

    口令也可以留空、运行时交互输入（不回显）。
    --db 可覆盖库名（默认 AuthBaselineDb），--uri 可覆盖连接串。

注意
====
    本脚本直接写库，**不经过服务端、不写审计**。它属于运维动作，
    与 `--rechain` 同级；它不会让任何"不该能登的东西"变得能登 ——
    改完的 v 仍然是那条链上真实的一格，只是游标位置被人为挪动了。
"""
import argparse
import base64
import datetime
import getpass
import hashlib
import json
import os
import sys

import bson
import pymongo

# 与 OtpVerifier.RenewThresholdPercent 一致。改这里之前先改那里，
# 否则脚本对"会不会续链"的预告就和服务端判定脱钩了。
RENEW_PERCENT = 5

BACKUP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "tools", "evidence")


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def chain_cell(password: str, r: str, iterations: int, times: int) -> bytes:
    """x_times = H^times(PBKDF2(password, salt=UTF8(r)))。与服务端 Root/Iterate 逐字一致。"""
    x = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                            r.encode("utf-8"), iterations, 32)
    for _ in range(times):
        x = hashlib.sha256(x).digest()
    return x


def main() -> int:
    ap = argparse.ArgumentParser(description="把链游标挪到指定 k（链长与种子不动）")
    ap.add_argument("--username", required=True, help="账号用户名")
    ap.add_argument("--k", type=int, required=True, help="目标游标（本次该提交 x_k）")
    ap.add_argument("--uri", default="mongodb://127.0.0.1:27017")
    ap.add_argument("--db", default="AuthBaselineDb", help="库名，默认 AuthBaselineDb")
    ap.add_argument("--apply", action="store_true", help="实际写库（默认干跑）")
    args = ap.parse_args()

    if args.k < 0:
        print("k 不能为负", file=sys.stderr)
        return 2

    client = pymongo.MongoClient(args.uri, serverSelectionTimeoutMS=3000)
    db = client[args.db]
    chains = db["OtpChains"]

    doc = chains.find_one({"username": args.username})
    if doc is None:
        doc = chains.find_one({"username": args.username.lower()})
    if doc is None:
        print("找不到这个账号的链：%s" % args.username, file=sys.stderr)
        return 3

    r = doc["r"]
    it = int(doc["kdfIterations"])
    length = int(doc["length"])
    k0 = int(doc["k"])
    v0 = doc["v"]
    gen = int(doc.get("generation", 1))

    if args.k > length - 1:
        print("k 超出范围：链长 %d ⇒ k 只能在 [0, %d]" % (length, length - 1), file=sys.stderr)
        return 4

    print("目标库    : %s" % args.db)
    print("账号      : %s" % doc["username"])
    print("当前      : k=%-5d length=%-5d gen=%d" % (k0, length, gen))

    if args.k == k0:
        print("已经是 k=%d，无需改动。" % k0)
        return 0

    password = os.environ.get("OTP_PASSWORD") or ""
    if not password:
        if sys.stdin.isatty():
            password = getpass.getpass("该账号的口令（不回显）：")
        if not password:
            print("缺少口令：请设环境变量 OTP_PASSWORD，或在交互终端里运行。", file=sys.stderr)
            return 5

    # ── 校验口令：用**旧状态**验，验不过就什么都不改 ──
    if b64(hashlib.sha256(chain_cell(password, r, it, k0)).digest()) != v0:
        print("口令与当前链不匹配，已拒绝，未做任何更改。", file=sys.stderr)
        return 6
    print("口令校验  : H(x_%d) == v 通过" % k0)

    v_new = b64(chain_cell(password, r, it, args.k + 1))
    in_line = args.k * 100 <= length * RENEW_PERCENT
    print("目标      : k=%d  v=x_%d" % (args.k, args.k + 1))
    print("续链线    : N×%d%% = %d 格 ⇒ k=%d %s"
          % (RENEW_PERCENT, length * RENEW_PERCENT // 100, args.k,
             "在线内，登录成功后会自动换链补满（k 回 %d）" % (length - 1)
             if in_line else
             "在线外，登录后 k 会真实减 1，直到降到 %d 才触发换链"
             % (length * RENEW_PERCENT // 100)))

    if not args.apply:
        print("\n[干跑] 未写库。加 --apply 执行。")
        return 0

    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(BACKUP_DIR, "otp_before_k%d_%s.json" % (args.k, stamp))
    snap = {k: (str(v) if isinstance(v, (bson.ObjectId, datetime.datetime)) else v)
            for k, v in doc.items()}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snap, f, ensure_ascii=False, indent=2)
    print("备份      : %s" % path)

    # CAS：只有"读到的这一份状态还在"才允许写，防止覆盖并发登录的核销结果
    res = chains.update_one({"_id": doc["_id"], "k": k0, "v": v0},
                            {"$set": {"k": args.k, "v": v_new}})
    if res.modified_count != 1:
        print("写库失败：状态已被别的请求改掉（有人正在登录？），未做任何更改。", file=sys.stderr)
        return 7

    after = chains.find_one({"_id": doc["_id"]})
    ka, va = int(after["k"]), after["v"]
    ok = b64(hashlib.sha256(chain_cell(password, r, it, ka)).digest()) == va
    print("完成      : k=%d  length=%d  gen=%d" % (ka, int(after["length"]), int(after.get("generation", 1))))
    print("自校验    : H(x_%d) == v -> %s" % (ka, "通过，可直接登录" if ok else "失败"))
    return 0 if ok else 8


if __name__ == "__main__":
    sys.exit(main())
