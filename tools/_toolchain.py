# -*- coding: utf-8 -*-
"""定位本机工具链可执行文件（node / npm）。

**为什么需要它**：workbuddy 托管 node 的版本目录名带构建号，会随环境更新
（本机实测已从 `22.22.2-3` 变成 `22.22.2-6`）。任何写死版本目录的路径都会在
环境更新后突然 `FileNotFoundError`，而报错只说"系统找不到指定的文件"，
看不出是版本漂移 —— 排查时极易误判成权限问题或文件被删。

`build_all.py` 与三个 UI 检查脚本原先各有一份自己的实现，且都是写死的，
所以收敛到这里：**环境变量覆盖 → 扫托管版本目录取最新 → 退回 PATH**。

用法（脚本与它同目录，直接 import 即可）：

    from _toolchain import find_node, find_npm
"""
import os

NODE_VERSIONS = os.path.join(
    os.path.expanduser("~"), ".workbuddy", "binaries", "node", "versions")


def _pick(names, env_var, fallback):
    override = os.environ.get(env_var)
    if override:
        return override
    if os.path.isdir(NODE_VERSIONS):
        found = []
        for ver in os.listdir(NODE_VERSIONS):
            for fn in names:
                p = os.path.join(NODE_VERSIONS, ver, fn)
                if os.path.isfile(p):
                    found.append((ver, p))
        if found:
            # 版本目录名字符串序即可满足"取最新"：22.22.2-6 > 22.22.2-3；
            # 真出现 22.22.2-10 这类跨位数时再换成元组比较。
            found.sort()
            return found[-1][1]
    return fallback


def find_npm():
    """npm 可执行文件绝对路径（可用 WB_NPM 覆盖）。"""
    return _pick(("npm.CMD", "npm.cmd", "npm"), "WB_NPM", "npm.cmd")


def find_node():
    """node 可执行文件绝对路径（可用 WB_NODE 覆盖）。"""
    return _pick(("node.exe", "node"), "WB_NODE", "node")
