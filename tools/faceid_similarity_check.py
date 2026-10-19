#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
纯人脸登录（FaceId）的**识别精度**离线评测：一组模板图 × 一组探针图，算余弦并给判定。

为什么需要它：
  验收时要测的是"同一张脸在不同照片里还认不认得出来"——
  明星青年 vs 老年、双胞胎、不同人种、特殊人群。这些样本**没有真人**，
  只能靠照片（举着手机对着摄像头，或直接喂图片）。
  而界面一次只能录一张，逐张录逐张比太慢：这个脚本直接调后端自己的
  `--faceid-embed` 取特征（**与线上完全同一条管线**，不是另写一份预处理），
  在离线侧把 1 对 N 的比对一次跑完。

判定口径与线上一致（`FaceIdDecision`）：
    余弦 ≥ 阈值 + 灰区      ⇒ Pass
    阈值 - 灰区 ≤ 余弦 < ... ⇒ GrayZone（线上会回退到口令）
    余弦 < 阈值 - 灰区      ⇒ Mismatch

输出：
  · 每个探针图的最佳匹配（1:N，取模板里的最大余弦）与判定
  · 按"模板图 → 探针图"的分组统计（同人 / 不同人），便于手工核对
  · 阈值扫描：把你关心的阈值附近的通过率摊开，而不是只给一个结论

⚠️ 只跑引擎：不连库、不连后端进程、不需要摄像头（`--faceid-embed` 在
   `CreateBuilder` 之前就返回了，不会起 Kestrel）。
⚠️ 这里算的是**同一张图集的离线分数**，不等于线上登录的真实分布；
   线上还受采集分辨率、压缩、姿态影响。
"""

import argparse
import os
import subprocess
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SERVER = os.path.join(ROOT, "AuthServer", "bin", "Debug", "net8.0", "AuthServer.exe")
IMG_EXT = (".jpg", ".jpeg", ".png", ".bmp")


def collect(items):
    """把目录展开成图片列表（递归一层不展开，避免把子目录搞混）。"""
    out = []
    for item in items:
        if os.path.isdir(item):
            for name in sorted(os.listdir(item)):
                if name.lower().endswith(IMG_EXT):
                    out.append(os.path.join(item, name))
        elif os.path.isfile(item):
            out.append(item)
    return out


def embed(server, paths):
    """调后端批量取特征，返回 {path: np.array}；失败的行只打印不中断。"""
    if not os.path.isfile(server):
        print("找不到后端：%s（先 dotnet build）" % server)
        sys.exit(2)

    # 分批发：命令行有长度上限，一次几百张图会超。
    # ⚠️ 按**输入序号**回填，不按回显的路径：中文路径在 GBK 控制台下会被打坏成 U+FFFD。
    feats, batch = {}, 200
    for i in range(0, len(paths), batch):
        chunk = paths[i:i + batch]
        proc = subprocess.run([server, "--faceid-embed"] + chunk,
                              capture_output=True, text=True, encoding="utf-8", errors="replace")
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 3 or "," not in parts[2]:
                continue
            try:
                idx = int(parts[0])
                values = [float(x) for x in parts[2].split(",")]
            except ValueError:
                continue
            if 0 <= idx < len(chunk):
                feats[chunk[idx]] = np.array(values, dtype=np.float64)
        if proc.returncode != 0 and proc.stderr.strip():
            missed = [ln for ln in proc.stderr.splitlines() if ln.strip()]
            print("  （%d 张取特征失败，前 3 条：）" % len(missed))
            for ln in missed[:3]:
                print("    " + ln)
    return feats


def cosine(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return float("nan")
    return float(np.dot(a, b) / (na * nb))


def verdict(cos, threshold, gray_band):
    """与 FaceIdDecision 同口径：两条边界都含，负灰区归一 0（防 fail-open）。"""
    band = max(0.0, gray_band)
    if cos >= threshold + band:
        return "Pass"
    if cos < threshold - band:
        return "Mismatch"
    return "GrayZone"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", nargs="+", required=True, help="模板图 / 目录（可多个）")
    ap.add_argument("--probe", nargs="+", required=True, help="探针图 / 目录（可多个）")
    ap.add_argument("--server", default=DEFAULT_SERVER)
    ap.add_argument("--threshold", type=float, default=0.50)
    ap.add_argument("--gray-band", type=float, default=0.05)
    args = ap.parse_args()

    tmpl_paths = collect(args.template)
    probe_paths = collect(args.probe)
    if not tmpl_paths:
        print("模板侧没有图片")
        return 2
    if not probe_paths:
        print("探针侧没有图片")
        return 2

    print("模板 %d 张 / 探针 %d 张，阈值 %.2f ± %.2f"
          % (len(tmpl_paths), len(probe_paths), args.threshold, args.gray_band))

    feats = embed(args.server, tmpl_paths + probe_paths)
    tmpl = [(p, feats[p]) for p in tmpl_paths if p in feats]
    probe = [(p, feats[p]) for p in probe_paths if p in feats]
    if not tmpl:
        print("模板侧全部取特征失败（检测不到脸？）")
        return 3
    if not probe:
        print("探针侧全部取特征失败（检测不到脸？）")
        return 3

    print("%-34s %-8s %-10s %s" % ("探针图", "最佳余弦", "判定", "最像的模板"))
    print("-" * 92)
    scores = []
    for p, f in probe:
        best_cos, best_p = -1.0, ""
        for tp, tf in tmpl:
            c = cosine(f, tf)
            if c > best_cos:
                best_cos, best_p = c, tp
        v = verdict(best_cos, args.threshold, args.gray_band)
        scores.append((p, best_cos, v))
        print("%-34s %-8.4f %-10s %s" % (os.path.basename(p), best_cos, v, os.path.basename(best_p)))

    a = np.array([s for _, s, _ in scores])
    print("-" * 92)
    print("汇总：n=%d  min=%.4f  中位=%.4f  max=%.4f" % (len(a), a.min(), np.median(a), a.max()))

    # 阈值扫描：同一批分数换阈值会怎么变，一次看清，而不是反复改配置重跑。
    print("\n阈值扫描（含 ±%.2f 灰区后的 Pass / GrayZone / Mismatch 计数）：" % args.gray_band)
    for t in (0.30, 0.40, 0.50, 0.60, 0.70):
        counts = {"Pass": 0, "GrayZone": 0, "Mismatch": 0}
        for _, s, _ in scores:
            counts[verdict(s, t, args.gray_band)] += 1
        print("  %.2f ⇒ Pass %-3d  GrayZone %-3d  Mismatch %-3d"
              % (t, counts["Pass"], counts["GrayZone"], counts["Mismatch"]))

    print("\n⚠️ 这是离线图集上的分数：同一条管线，但没有采集/压缩/姿态的现场影响，"
          "不能直接当线上分布用。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
