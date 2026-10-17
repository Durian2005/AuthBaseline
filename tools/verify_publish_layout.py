#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""发布产物布局校验（CI 用，也可本地手动跑）。

回答一个问题：**这次 `dotnet publish` 出来的东西，是不是「模型在磁盘上、frontend 在
wwwroot 里、exe 没把不该吞的吞掉」？**

为什么单独写一个，而不是直接跑 `tools/face_release_probe.py`：
后者是完整的装机产物校验（14 项 + 内嵌 93 项），需要真后端起来、连库、走人脸接口 ——
那是"发布前验收"的活。CI 里每次 PR 都跑一遍不现实。这里只取其中**最贵的那条教训**：

    ⚠️ 单文件打包器会吞掉 `CopyToPublishDirectory` 的资源。
    `face-models/*.onnx` 必须显式 `ExcludeFromSingleFile="true"`，
    判据是"目录齐全 **且** exe 里找不到这些文件名"。
    一旦被吞，症状离原因极远：程序能启动，只是已录人脸的账号全部 fail closed，
    界面只说"本机人脸引擎不可用"。

换句话说：本脚本守的是"**构建配置被改坏**"这一类回归，而不是算法与接口。

用法：
    python tools/verify_publish_layout.py <publish 目录>
退出码：0 通过 / 1 失败（CI 直接拿它当门禁）
"""

import os
import sys

# 输出里有中文和 ✓/✗，而 Windows 上的 Python 默认按**系统代码页**编码 stdout。
# GitHub 的 Windows runner 是英文 locale（cp1252），第一次跑 CI 就在这里炸：
#   UnicodeEncodeError: 'charmap' codec can't encode characters in position 0-4
# 退出码是 1，于是门禁红了 —— 但红的原因跟它要守的东西毫无关系，
# 只因为一个打印语句。这类失败最耗人：看日志第一眼只会以为"构建坏了"。
# 所以这里钉死 UTF-8；errors="replace" 是兜底：宁可个别字符变成 ?，
# 也不要让一个字符毁掉整条门禁。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 必须是"随产物一起走、不允许被塞进单文件 exe"的资源。
# 加新条目时请同时想清楚：它被吞掉的症状是什么？离原因有多远？
MUST_BE_ON_DISK = [
    os.path.join("face-models", "face_detection_yunet_2023mar.onnx"),
    os.path.join("face-models", "face_recognition_sface_2021dec.onnx"),
]

# 这些文件必须存在（缺一个，装出来的东西就是残的）
MUST_EXIST = [
    "appsettings.json",
    os.path.join("wwwroot", "index.html"),
]

ok = True


def check(name, cond, detail=""):
    global ok
    print(("  ✓ " if cond else "  ✗ ") + name + ("  " + detail if detail else ""))
    if not cond:
        ok = False


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join("AuthServer", "publish")
    if not os.path.isdir(root):
        print("目录不存在：%s" % root)
        return 2

    print("发布目录：%s" % os.path.abspath(root))

    # 安装名与开发名不同（productName 决定 NSIS 的 exe 名）：两种都认，避免"因为改名而误报失败"
    exe = None
    for cand in ("authserver.exe", "AuthServer.exe"):
        p = os.path.join(root, cand)
        if os.path.isfile(p):
            exe = p
            break
    check("单文件 exe 存在", exe is not None, exe or "(authserver.exe / AuthServer.exe 都没有)")
    if exe is None:
        return 1

    for rel in MUST_EXIST:
        check("%s 存在" % rel, os.path.isfile(os.path.join(root, rel)))

    for rel in MUST_BE_ON_DISK:
        p = os.path.join(root, rel)
        size = os.path.getsize(p) if os.path.isfile(p) else 0
        # 判据不只是"文件在"，还要"不是 0 字节" —— 打包器删文件时也可能留个空壳
        check("%s 在磁盘上且非空" % rel, size > 1024, "%.1f MB" % (size / 1048576.0))

    # 关键的一步：确认这些文件名**没有**被写进 exe。
    # 用字节级搜索而不是字符串解码整个 exe（几百 MB 的 exe 解码成 str 很浪费）。
    with open(exe, "rb") as f:
        blob = f.read()
    for rel in MUST_BE_ON_DISK:
        name = os.path.basename(rel).encode("utf-8")
        check("exe 内不含 %s（未被单文件打包器吞掉）" % os.path.basename(rel),
              name not in blob)

    print("\n结果：%s" % ("通过" if ok else "失败"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
