#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
faceid_threshold_sweep.py — FaceId P3 阈值定档：比 lfw_eval 更厚的负样本 + 完整 FAR/FRR 曲线。

lfw_eval 回答的是"默认 0.50 下是什么水平"；这个脚本回答的是
**"把阈值定在哪里"** —— 所以它做三件 lfw_eval 不做的事：

  1. 负样本对拉到数万级：1500 对时 FAR=1e-4 只是外推（分母不够），
     5 万对才有 5 个左右的期望误接受，尾部至少看得出形状。
  2. 直接扫 FAR/FRR 曲线，而不是只报 EER 一个点：
     阈值是要贴着"可接受的 FAR"选的，EER 那个点通常过松。
  3. 输出可粘贴的结论块：每个 FAR 档位的阈值与 TAR，以及推荐阈值。

⚠️ 口径：LFW 是**简单集**（正脸、光照正常），这里的数字不是线上 FAR 的估计，
   更不是 PAD/识别认证。它只能回答"我们的管线在这份数据上，阈值取多少能把
   误接受压到 1e-4 以下，代价是拒掉多少本人"。

用法：
  <faceid venv>/python tools/faceid_threshold_sweep.py --pairs 3000 --neg 50000
"""
import argparse
import glob
import os
import random
import sys

import cv2
import numpy as np
import onnxruntime as ort

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FACE_MODELS = os.path.join(ROOT, "AuthServer", "face-models")
DEFAULT_LFW = os.path.join(ROOT, ".workbuddy", "tmp", "lfw", "lfw-deepfunneled", "lfw-deepfunneled")

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "faceid_stage0_check", os.path.join(ROOT, "tools", "faceid_stage0_check.py"))
_s0 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_s0)

ensure_ascii = _s0.ensure_ascii
py_embed = _s0.py_embed
DETECT_SIZE = _s0.DETECT_SIZE


def build_pairs(lfw_root, pos_max, neg_n, seed):
    people = {}
    for d in sorted(glob.glob(os.path.join(lfw_root, "*"))):
        if not os.path.isdir(d):
            continue
        imgs = sorted(glob.glob(os.path.join(d, "*.jpg")))
        if len(imgs) >= 2:
            people[d] = imgs
    if len(people) < 10:
        raise SystemExit("LFW 目录里没有足够的多图人物：%s" % lfw_root)

    rng = random.Random(seed)
    names = sorted(people)

    positives = []
    for name in names:
        imgs = people[name]
        for _ in range(3):
            a, b = rng.sample(imgs, 2)
            positives.append((a, b))
    rng.shuffle(positives)
    positives = positives[:pos_max]

    negatives = []
    for _ in range(neg_n):
        a, b = rng.sample(names, 2)
        negatives.append((rng.choice(people[a]), rng.choice(people[b])))
    return positives, negatives, len(people)


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return 0.0 if na <= 0 or nb <= 0 else float(np.dot(a, b) / (na * nb))


def score_pairs(pairs, detector, session, cache):
    scores, skipped, seen = [], 0, 0
    total = len(pairs) * 2
    for a, b in pairs:
        out = []
        for path in (a, b):
            if path not in cache:
                cache[path] = py_embed(detector, session, path)
                seen += 1
                if seen % 500 == 0:
                    print("    已提特征 %d 张（缓存 %d）" % (seen, len(cache)), flush=True)
            out.append(cache[path])
        ea, eb = out
        if ea is None or eb is None:
            skipped += 1
            continue
        scores.append(cos(ea, eb))
    return np.array(scores), len(pairs) - skipped, skipped


def quantiles(x, qs):
    return [float(np.quantile(x, q)) for q in qs]


def far_curve(genuine, impostor, thresholds):
    """返回每个阈值下的 (FAR, FRR, TAR)。用排序 + searchsorted，避免 2001 次全量比较。"""
    g = np.sort(genuine)
    i = np.sort(impostor)
    far = 1.0 - np.searchsorted(i, thresholds, side="left") / len(i)
    frr = np.searchsorted(g, thresholds, side="left") / len(g)
    return far, frr, 1.0 - frr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lfw-root", default=DEFAULT_LFW)
    ap.add_argument("--pairs", type=int, default=3000, help="正样本对上限")
    ap.add_argument("--neg", type=int, default=50000, help="负样本对数量")
    ap.add_argument("--seed", type=int, default=20261019)
    ap.add_argument("--threshold", type=float, default=0.50, help="当前默认阈值（用于对照）")
    args = ap.parse_args()

    if not os.path.isdir(args.lfw_root):
        raise SystemExit("找不到 LFW 目录：%s" % args.lfw_root)

    yunet = ensure_ascii(os.path.join(FACE_MODELS, "face_detection_yunet_2023mar.onnx"))
    arcface = ensure_ascii(os.path.join(FACE_MODELS, "face_recognition_arcface_w600k_r50.onnx"))
    detector = (cv2.FaceDetectorYN.create(yunet, "", DETECT_SIZE, 0.6, 0.3, 5000)
                if hasattr(cv2.FaceDetectorYN, "create")
                else cv2.FaceDetectorYN.Create(yunet, "", DETECT_SIZE, 0.6, 0.3, 5000))
    session = ort.InferenceSession(arcface, providers=["CPUExecutionProvider"])

    pos, neg, n_people = build_pairs(args.lfw_root, args.pairs, args.neg, args.seed)
    print("[1] 配对：人物 %d 个；正对 %d；负对 %d" % (n_people, len(pos), len(neg)))

    cache = {}
    print("[2] 提特征（正对）…", flush=True)
    gen, gen_ok, gen_skip = score_pairs(pos, detector, session, cache)
    print("[2] 提特征（负对）…", flush=True)
    imp, imp_ok, imp_skip = score_pairs(neg, detector, session, cache)

    if len(gen) == 0 or len(imp) == 0:
        raise SystemExit("有效对数为 0")
    print("[2] 有效：正 %d/%d，负 %d/%d，缓存 %d 张图"
          % (len(gen), len(gen) + gen_skip, len(imp), len(imp) + imp_skip, len(cache)))

    print("\n[3] 分布")
    gq = quantiles(gen, [0.0, 0.01, 0.05, 0.5, 0.95, 1.0])
    iq = quantiles(imp, [0.5, 0.99, 0.9999, 1.0])
    print("  正样本 cos  min=%.4f p1=%.4f p5=%.4f median=%.4f p95=%.4f max=%.4f"
          % tuple(gq))
    print("  负样本 cos  median=%.4f p99=%.4f p99.99=%.4f max=%.4f" % tuple(iq))

    print("\n[4] FAR / FRR 曲线（LFW：正 %d，负 %d）" % (len(gen), len(imp)))
    print("  %-8s %-10s %-10s %-10s" % ("阈值", "FAR", "FRR", "TAR"))
    for thr in (0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60):
        far, frr, tar = far_curve(gen, imp, np.array([thr]))
        print("  %-8.2f %-10.6f %-10.4f %-10.4f" % (thr, far[0], frr[0], tar[0]))

    print("\n[5] 按目标 FAR 反推阈值")
    for target in (1e-2, 1e-3, 1e-4, 1e-5):
        thr = float(np.quantile(imp, 1.0 - target))
        far, frr, tar = far_curve(gen, imp, np.array([thr]))
        note = "" if target >= 1.0 / len(imp) else "  ← 超出负样本分辨率，仅外推"
        print("  FAR<=%-8g 阈值=%.4f  TAR=%.4f  FRR=%.4f%s"
              % (target, thr, tar[0], frr[0], note))

    far0, frr0, tar0 = far_curve(gen, imp, np.array([args.threshold]))
    print("\n[6] 现行默认 %.2f：FAR=%.6f  FRR=%.4f  TAR=%.4f"
          % (args.threshold, far0[0], frr0[0], tar0[0]))
    thr4 = float(np.quantile(imp, 1.0 - 1e-4))
    print("    与 FAR=1e-4 所需阈值 %.4f 相比，现行阈值%s"
          % (thr4, "偏松" if args.threshold < thr4 else "偏紧（保守）"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
