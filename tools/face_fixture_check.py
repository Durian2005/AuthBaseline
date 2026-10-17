#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""人脸动作挑战的**帧回放**回归：把录下来的真实画面重放一遍，比对判定结论。

为什么需要它（这件事过去做不到）
--------------------------------
动作挑战（求基线 → 等转头 → 等回正 → 从回正帧提特征）只能在**真人对着摄像头**时
才有意义。于是每次改阈值或改动判定代码，都只能靠"把人叫过来再试一次"来验证，
而且当时到底发生了什么无法回看 —— 这是整个项目里唯一一块"改完只能祈祷"的地方。

现在：先录一次（`authserver.exe --face-record <目录> <left|right>`），
之后用 `--face-replay` 反复重放。回放走的是 `CvFaceEngine.RunChallenge` 的**同一段代码**，
只把采集源从摄像头换成图片目录 —— 所以 YuNet 检测、SFace 特征、判定时序全都照跑。

⚠️ fixture 里是**真人的脸**（连拍帧）。`tools/fixtures/` 已在 .gitignore 中，
   绝不要提交到公开仓库，也不要拷进 docs/ 或截图目录。

用法：
    python tools/face_fixture_check.py <exe路径> [--root tools/fixtures/face]
退出码：0 全部符合 / 1 有结论不符 / 3 没有可跑的 fixture（先录一次）
"""

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MARKER = "FACE_REPLAY_RESULT="


def find_fixtures(root):
    out = []
    if not os.path.isdir(root):
        return out
    for name in sorted(os.listdir(root)):
        d = os.path.join(root, name)
        if os.path.isdir(d) and os.path.isfile(os.path.join(d, "manifest.json")):
            out.append(d)
    return out


def replay(exe, fixture):
    r = subprocess.run([exe, "--face-replay", fixture],
                       capture_output=True, text=True, errors="replace", timeout=180)
    payload = None
    for line in (r.stdout or "").splitlines():
        if line.startswith(MARKER):
            payload = line[len(MARKER):]
            break
    if payload is None:
        return None, (r.stdout or "") + (r.stderr or "")
    try:
        return json.loads(payload), ""
    except ValueError as ex:
        return None, "回放输出不是合法 JSON：%s" % ex


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    exe = sys.argv[1]
    root = os.path.join(ROOT, "tools", "fixtures", "face")
    if "--root" in sys.argv:
        root = sys.argv[sys.argv.index("--root") + 1]

    if not os.path.isfile(exe):
        print("找不到可执行文件：%s" % exe)
        return 2

    fixtures = find_fixtures(root)
    if not fixtures:
        print("没有可跑的 fixture：%s" % root)
        print("  先录一次（需要真实摄像头）：")
        print("    %s --face-record \"%s\" left" % (os.path.basename(exe),
                                                   os.path.join("tools", "fixtures", "face", "left-ok")))
        print("  提示：坐到摄像头前，按界面提示把头转向一侧并转回正对镜头。")
        return 3

    print("=" * 74)
    print("  人脸动作挑战 · 帧回放回归")
    print("=" * 74)
    print("  exe      : %s" % exe)
    print("  fixture  : %d 个（%s）" % (len(fixtures), root))

    failed = 0
    for d in fixtures:
        name = os.path.basename(d)
        with open(os.path.join(d, "manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f)
        expect = manifest.get("expect") or {}

        print("\n  ── %s · action=%s · %d 帧 · 录制于 %s"
              % (name, manifest.get("action"), manifest.get("frames", 0),
                 manifest.get("recordedAt", "?")))

        got, raw = replay(exe, d)
        if got is None:
            print("     ✗ 回放失败，没有拿到结论。原始输出：")
            for line in raw.strip().splitlines()[-8:]:
                print("        " + line)
            failed += 1
            continue

        print("     期望 passed=%s code=%s" % (expect.get("passed"), expect.get("businessCode") or "(空)"))
        print("     实得 passed=%s code=%s" % (got.get("passed"), got.get("businessCode") or "(空)"))

        ok = (got.get("passed") == expect.get("passed")
              and (got.get("businessCode") or "") == (expect.get("businessCode") or ""))
        print("     %s 判定结论%s" % ("✓" if ok else "✗", "一致" if ok else "不一致"))
        if not ok:
            failed += 1

        # 计数只作提示、不作失败判据：它们与"这次机器读盘 + 检测有多快"有关，
        # 而 passed / businessCode 才是产品语义。硬判计数会把回归变成测机器性能。
        drift = []
        for k in ("samples", "misses", "jumps"):
            if got.get(k) != expect.get(k):
                drift.append("%s %s→%s" % (k, expect.get(k), got.get(k)))
        if drift:
            print("     · 计数与录制时不同（仅提示，不判失败）：%s" % ", ".join(drift))

        if got.get("diagnostic"):
            print("     诊断：%s" % got["diagnostic"])

    print("\n" + "=" * 74)
    print("  %d / %d 个 fixture 判定一致" % (len(fixtures) - failed, len(fixtures)))
    print("=" * 74)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
