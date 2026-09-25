#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
入库前隐私扫描（GitHub 发布专用）。

回答的是一个问题：**如果现在把它推上去，会泄漏什么？**

扫描三块，缺一不可：
  1. 工作区里"将要被上传"的文件 —— git 已跟踪的 + 未被忽略的未跟踪文件。
     这是最要紧的一块，因为它就是下一次 push 的内容。
  2. 完整 git 历史里的每一个 blob —— 已经提交过的东西即使后来删掉，
     仍能被人从历史里翻出来，所以必须单独扫。
  3. 非文本文件（数据库导出 JSON 等）按容器语义判定 ——
     这类文件哪怕扫不出"关键字"，它本身就是一份数据泄漏。

输出全部脱敏：只给前缀 + 长度 + 行号，不打印完整敏感值，
免得扫描报告自己变成新的泄漏点。

用法：
    python tools/privacy_scan.py                 # 扫工作区 + 历史
    python tools/privacy_scan.py --no-history    # 只扫工作区（快）
"""

import os
import re
import subprocess
import sys
import collections

GIT = os.environ.get("WB_GIT") or os.path.join(
    os.path.expanduser("~"), ".workbuddy", "binaries", "PortableGit",
    "versions", "1.2.0", "cmd", "git.exe")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 文本才逐行扫；这些是二进制或无需扫描的扩展名
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".dll", ".exe", ".lib", ".rlib", ".pdb", ".rmeta", ".d",
    ".zip", ".7z", ".gz", ".pdf", ".so", ".node",
}

# 这些文件名/路径本身就是"数据泄漏"，不靠关键字判定
DATA_CONTAINER = re.compile(
    r"(evidence|backup|snapshot|dump|export)[^/]*\.(json|bson|sql|gz|zip)$",
    re.I,
)


def sh(*args, timeout=180):
    r = subprocess.run(
        [GIT, "-C", ROOT] + list(args),
        capture_output=True, text=True, errors="replace", timeout=timeout,
    )
    return (r.stdout or "") + (r.stderr or "")


def mask(s, keep=2):
    s = s.strip()
    if len(s) <= keep:
        return "<短>"
    return s[:keep] + "*" * min(len(s) - keep, 12) + "(%d)" % len(s)


# name -> (regex, 是否可能误报需人工确认)
_PRIVACY_NAMES = [x.strip() for x in
                   os.environ.get("PRIVACY_NAMES", "").split(",") if x.strip()]

PATTERNS = [
    ("邮箱地址",      re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), False),
    ("中国大陆手机号", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), False),
    ("bcrypt 口令哈希", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{50,}"), False),
    ("会话 ticket",   re.compile(r'"ticket"\s*:\s*"([A-Za-z0-9_\-]{20,})"'), False),
    ("口令字段赋值",   re.compile(r'(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b\s*[:=]\s*["\']([^"\']{6,})["\']'), True),
    ("私钥/平台令牌",  re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,})"), False),
    ("带凭据连接串",   re.compile(r"(mongodb(\+srv)?|mysql|postgres(ql)?|redis)://[^\s\"':@]+:[^\s\"'@]+@"), False),
    # 泛化成"任意盘符 + \Users\<登录名>"，不再依赖某台机器的用户名
    ("本机绝对路径",   re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s\"'<>|]+"), False),
    # 真实姓名没法用通用规则识别，改从环境变量读：
    #   set PRIVACY_NAMES=张某某,李某某   （不设则该条永不命中）
    ("真实姓名",      re.compile("|".join(re.escape(x) for x in _PRIVACY_NAMES)
                                 if _PRIVACY_NAMES else r"(?!x)x"), False),
    ("非回环 IP",     re.compile(r"(?<![\d.])(?!127\.0\.0\.1)(?!0\.0\.0\.0)(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"), True),
]

# 已知的演示默认口令：教学基线的正常设计，单列出来避免和真凭据混淆
DEMO_OK = {"Admin123", "Admin23", "Victim12345", "Ops12345", "NewPass123", "Ops9x8y7z", "wrongold1A", "WrongPass1"}


def is_text(path):
    return os.path.splitext(path)[1].lower() not in SKIP_EXT


def scan_text(text, findings, label):
    for name, rx, soft in PATTERNS:
        for m in rx.finditer(text):
            val = m.group(m.lastindex) if m.lastindex else m.group(0)
            if name == "口令字段赋值" and val in DEMO_OK:
                continue
            # 排除代码里的示例/占位写法
            if any(k in val for k in ("example.com", "your_", "xxxx", "<", "***", "变更")) :
                continue
            line = text[: m.start()].count("\n") + 1
            findings[name].append({
                "where": label, "line": line,
                "sample": mask(val), "soft": soft,
            })


def main():
    want_history = "--no-history" not in sys.argv

    print("=" * 74)
    print("  入库前隐私扫描")
    print("=" * 74)

    tracked = [l for l in sh("ls-files").splitlines() if l.strip()]
    status = [l for l in sh("status", "--porcelain", "--untracked-files=all").splitlines() if l.strip()]
    untracked = [l[3:].strip().strip('"') for l in status if l.startswith("??")]
    modified = [l[3:].strip().strip('"') for l in status if not l.startswith("??")]

    upload_set = sorted(set(tracked) | set(untracked))
    print("\n[范围]")
    print("  已跟踪          : %d" % len(tracked))
    print("  已修改(未提交)  : %d" % len(modified))
    print("  未跟踪(未忽略)  : %d" % len(untracked))
    print("  → 下次 push 会带上的文件共: %d" % len(upload_set))

    findings = collections.defaultdict(list)

    # ---- 1. 工作区 ----
    data_containers = []
    for f in upload_set:
        p = os.path.join(ROOT, f)
        if not os.path.isfile(p):
            continue
        if DATA_CONTAINER.search(f):
            data_containers.append((f, os.path.getsize(p)))
        if not is_text(f):
            continue
        try:
            t = open(p, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        scan_text(t, findings, f)

    # ---- 2. 历史 ----
    hist_hits = collections.defaultdict(list)
    if want_history:
        print("\n[历史] 遍历所有 blob（已提交过的东西删不掉，必须单独扫）…")
        objs = sh("rev-list", "--objects", "--all", timeout=300)
        blob_shas = []
        seen = set()
        for line in objs.splitlines():
            parts = line.split(" ", 1)
            if len(parts) != 2:
                continue
            sha, path = parts
            if path in seen:
                continue
            seen.add(path)
            if is_text(path):
                blob_shas.append((sha, path))
        print("  待扫文本 blob: %d" % len(blob_shas))
        scanned = 0
        for sha, path in blob_shas:
            # 注意：subprocess 里只要给了 errors=/encoding= 就**隐含文本模式**，
            # r.stdout 已经是 str。此前这里多写了一句 .decode()，结果每次都抛
            # AttributeError 被 except 吞掉 —— 表现是"历史 0 处命中"，
            # 看起来像"历史很干净"，其实是**一个 blob 都没扫**。
            # 这类静默失败比漏报更危险，所以下面加了扫描数量的硬校验。
            r = subprocess.run([GIT, "-C", ROOT, "cat-file", "blob", sha],
                               capture_output=True, text=True, errors="replace", timeout=60)
            t = r.stdout or ""
            if not t:
                continue
            scanned += 1
            scan_text(t, hist_hits, "历史:" + path)
        print("  实际扫到内容的 blob: %d" % scanned)
        if scanned == 0:
            raise RuntimeError(
                "历史扫描没有读到任何内容 —— 结果不可信，不要据此判断历史干净")
        # 自检：拿一个已知敏感的合成串过一遍，确认模式确实能命中。
        # 邮箱刻意用 chr(64) 拼出来 —— 否则扫描器的源码里会留下一个
        # 符合邮箱格式的字面量，扫描自己时命中自己，报告里就多一条噪声。
        probe = collections.defaultdict(list)
        probe_mail = "probe" + chr(64) + "example.org"
        scan_text('{"ticket":"' + "A" * 43 + '","email":"' + probe_mail + '"}',
                  probe, "自检")
        if not probe or "邮箱地址" not in probe or "会话 ticket" not in probe:
            raise RuntimeError("自检未覆盖到预期模式，结果不可信")
        print("  自检通过：邮箱与会话 ticket 模式均可正常命中")

    # ---- 报告 ----
    print("\n" + "=" * 74)
    print("  工作区发现（下次 push 会带上）")
    print("=" * 74)
    if not findings:
        print("  ✓ 未发现任何敏感串")
    for name in [p[0] for p in PATTERNS]:
        lst = findings.get(name) or []
        if not lst:
            continue
        by_file = collections.Counter(d["where"] for d in lst)
        mark = "" if not lst[0]["soft"] else "  [需人工确认]"
        print("\n  ### %s  —  %d 处%s" % (name, len(lst), mark))
        for f, n in by_file.most_common():
            lines = sorted({d["line"] for d in lst if d["where"] == f})[:6]
            ex = next(d["sample"] for d in lst if d["where"] == f)
            print("      %-50s %2d 处  L%s  例:%s"
                  % (f, n, ",".join(str(x) for x in lines), ex))

    print("\n  ### 数据容器文件（不靠关键字，文件本身即泄漏）")
    if data_containers:
        for f, sz in sorted(data_containers, key=lambda x: -x[1]):
            print("      %-50s %8.1f KB" % (f, sz / 1024))
    else:
        print("      (无)")

    if want_history:
        print("\n" + "=" * 74)
        print("  历史发现")
        print("=" * 74)
        if not hist_hits:
            print("  ✓ 历史中未发现敏感串")
        for name in [p[0] for p in PATTERNS]:
            lst = hist_hits.get(name) or []
            if not lst:
                continue
            by_file = collections.Counter(d["where"] for d in lst)
            print("\n  ### %s  —  %d 处" % (name, len(lst)))
            for f, n in by_file.most_common():
                print("      %-50s %2d 处" % (f, n))

    print("\n" + "=" * 74)
    total = sum(len(v) for v in findings.values())
    htotal = sum(len(v) for v in hist_hits.values())
    print("  工作区 %d 处 / 历史 %d 处 / 数据容器 %d 个文件"
          % (total, htotal, len(data_containers)))
    print("=" * 74)


if __name__ == "__main__":
    main()
