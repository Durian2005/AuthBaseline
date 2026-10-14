# -*- coding: utf-8 -*-
"""定位本机工具链可执行文件（node / npm / git）。

**为什么需要它**：workbuddy 托管工具的版本目录名带构建号，会随环境更新
（实测 node 已从 `22.22.2-3` 变成 `22.22.2-6`；PortableGit 从 `1.2.0` 变成 `1.3.0`）。
任何写死版本目录的路径都会在环境更新后突然 `FileNotFoundError`，而报错只说
"系统找不到指定的文件"，看不出是版本漂移 —— 排查时极易误判成权限问题或文件被删。
本机实测过一次：`privacy_scan.py` 与 `git_health_check.py` 都把 PortableGit 写成 `1.2.0`，
环境升到 `1.3.0` 后两个脚本一起挂，而报错完全没提版本。

`build_all.py` / 三个 UI 检查脚本 / `privacy_scan.py` / `git_health_check.py`
原先各有一份自己的实现，且都是写死的，所以收敛到这里：
**环境变量覆盖 → 读 current 指针（git 专有）→ 扫托管版本目录取最新 → 退回 PATH**。

用法（脚本与它同目录，直接 import 即可）：

    from _toolchain import find_node, find_npm, find_git
"""
import os
import shutil

_BASE = os.path.join(os.path.expanduser("~"), ".workbuddy", "binaries")
NODE_VERSIONS = os.path.join(_BASE, "node", "versions")
GIT_VERSIONS = os.path.join(_BASE, "PortableGit", "versions")


def _latest_in(versions_dir, names):
    """扫 `<versions_dir>/<版本>/<名>`，按版本目录名字符串序取最新。"""
    if not os.path.isdir(versions_dir):
        return None
    found = []
    for ver in os.listdir(versions_dir):
        for fn in names:
            p = os.path.join(versions_dir, ver, fn)
            if os.path.isfile(p):
                found.append((ver, p))
    if not found:
        return None
    # 字符串序即可满足"取最新"：22.22.2-6 > 22.22.2-3、1.3.0 > 1.2.0。
    # 真出现 22.22.2-10 这类跨位数时再换成元组比较。
    found.sort()
    return found[-1][1]


def _pick(names, env_var, versions_dir, fallback):
    override = os.environ.get(env_var)
    if override:
        return override
    hit = _latest_in(versions_dir, names)
    return hit if hit else fallback


def find_npm():
    """npm 可执行文件绝对路径（可用 WB_NPM 覆盖）。"""
    return _pick(("npm.CMD", "npm.cmd", "npm"), "WB_NPM", NODE_VERSIONS, "npm.cmd")


def find_node():
    """node 可执行文件绝对路径（可用 WB_NODE 覆盖）。"""
    return _pick(("node.exe", "node"), "WB_NODE", NODE_VERSIONS, "node")


def find_git():
    """git 可执行文件绝对路径（可用 WB_GIT 覆盖）。

    PortableGit 的版本目录多一个线索：`versions/current` 是一个**文本文件**，
    内容就是当前版本号（不是目录）。先读它，能命中就不必扫目录 ——
    也顺带避开"目录里还躺着旧版本、扫最新恰好扫错"的情况。
    """
    override = os.environ.get("WB_GIT")
    if override:
        return override

    pointer = os.path.join(GIT_VERSIONS, "current")
    if os.path.isfile(pointer):
        try:
            with open(pointer, encoding="utf-8", errors="replace") as f:
                ver = f.read().strip()
        except OSError:
            ver = ""
        if ver:
            p = os.path.join(GIT_VERSIONS, ver, "cmd", "git.exe")
            if os.path.isfile(p):
                return p

    hit = _latest_in(GIT_VERSIONS, ("cmd/git.exe", "git.exe", "bin/git.exe"))
    if hit:
        return hit

    return shutil.which("git") or "git"
