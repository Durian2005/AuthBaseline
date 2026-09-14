#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
安装包完整性验证（不启动界面，只查文件）。

背景：桌面端 Rust 侧会把窗口导航到 sidecar 后端（`http://127.0.0.1:<port>`），
由后端的 wwwroot 提供前端页面。因此安装目录里**必须有**：
    auth-baseline-desktop.exe   主程序
    authserver.exe              后端 sidecar
    appsettings.json            后端配置（连 MongoDB）
    wwwroot/                    前端静态资源（缺了就是白屏）

用法：
    python tools/verify_install.py [安装目录]
    不传目录时自动读取注册表 InstallLocation。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

REQUIRED = [
    ("auth-baseline-desktop.exe", "主程序"),
    ("authserver.exe", "后端 sidecar"),
    ("appsettings.json", "后端配置（连接串等）"),
    ("appsettings.Local.json", "本地配置（SMTP 授权码）"),
    ("wwwroot/index.html", "前端入口页"),
]


def find_install_dir() -> Path | None:
    """从注册表读 InstallLocation（比猜目录可靠）。"""
    ps = (
        "$p=@('HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
        "Get-ItemProperty $p -EA SilentlyContinue"
        " | Where-Object { $_.DisplayName -like '*AuthBaseline*' }"
        " | Select-Object -First 1 -ExpandProperty InstallLocation"
    )
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, timeout=30)
        loc = (r.stdout or "").strip().strip('"')
        if loc and Path(loc).is_dir():
            return Path(loc)
    except Exception as e:
        print("读取注册表失败：", e)
    return None


def main() -> int:
    d = Path(sys.argv[1]) if len(sys.argv) > 1 else find_install_dir()
    if not d:
        print("未找到安装目录，请手动传入路径")
        return 1
    print("安装目录：%s\n" % d)

    ok = True
    for rel, desc in REQUIRED:
        f = d / rel
        if f.is_file():
            size = f.stat().st_size
            print("  [OK]   %-28s %-12s %8d 字节" % (rel, desc, size))
        else:
            print("  [缺失] %-28s %-12s  ← 会导致启动异常" % (rel, desc))
            ok = False

    www = d / "wwwroot"
    if www.is_dir():
        files = [p for p in www.rglob("*") if p.is_file()]
        print("\n  wwwroot 下共 %d 个文件：" % len(files))
        for p in files:
            print("      %s" % p.relative_to(d))

    # 邮件凭证检查：文件存在还不够，Account/Password 为空会静默降级为
    # 控制台发件器 —— 表现是"收不到验证码"，但界面一切正常，很难排查。
    print("\n  邮件发件通道检查：")
    email_ok = True
    local = d / "appsettings.Local.json"
    if not local.is_file():
        print("      [警告] 无 appsettings.Local.json —— 将降级为控制台发件器，邮件不会真实投递")
        email_ok = False
    else:
        try:
            raw = local.read_text(encoding="utf-8-sig")
            # 去掉 // 注释后再解析
            cleaned = "\n".join(l for l in raw.splitlines()
                                if not l.strip().startswith("//"))
            cfg = json.loads(cleaned).get("Email", {})
            acct = (cfg.get("Account") or "").strip()
            pwd = (cfg.get("Password") or "").strip()
            if acct and pwd:
                print("      [OK] 发件邮箱 %s，授权码已填（%d 位）" % (acct, len(pwd)))
            else:
                print("      [警告] Account 或 Password 为空 —— 邮件不会真实投递")
                email_ok = False
        except Exception as e:
            print("      [警告] 解析失败：%s" % e)
            email_ok = False

    # 主程序是否带上了渲染修复参数（additionalBrowserArgs 不在 exe 字符串里，
    # 这里只做存在性提示）
    print("\n结论：%s" % ("安装包完整，具备启动条件" if ok else "安装包不完整，请检查 bundle.resources 配置"))
    if ok and not email_ok:
        print("      注意：邮件功能将走控制台兜底，验证码可在 email-codes.log 查看。")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
