#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
faceid_lfw_eval.py — FaceId（纯人脸登录）P0 的 LFW 子集评测。

要回答的问题：**换掉 SFace 之后，ArcFace（w600k_r50 / Glint360K）这条管线
在我们的场景里到底是什么水平** —— 默认阈值 0.50 下准确率多少、EER 多少、
FAR=1e-4 时 TAR 多少。这些数字是 P3 阈值定档的输入，也是答辩时的证据。

为什么可以在 Python 里评：
  Stage 0（tools/faceid_stage0_check.py）已证明 C# 引擎与本脚本使用的
  Python 参考管线（cv2 YuNet + onnxruntime ArcFace）逐位等价（cos=1.000000），
  所以 Python 侧的数字就是线上引擎的数字。

数据：LFW（lfw-deepfunneled）。官方站点不可达时的下载方式见 tools/README.md
  的 FaceId 一节；解压后目录结构为 lfw-deepfunneled/lfw-deepfunneled/<人物>/<图片>。
  数据只放本机（.workbuddy/ 下），**绝不入库**。

配对：LFW 每人 1~多张。正样本 = 同一人的两张不同图；负样本 = 两个不同人的图。
  默认各取 1500 对（固定随机种子，结果可复现）。

依赖与用法：
  python tools/faceid_lfw_eval.py [--lfw-root DIR] [--pairs 1500] [--min-cos 0.999]
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

# ── 与 Stage 0 脚本共用同一套参考管线（ import 而不是复制，避免两处漂移 ） ──
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "faceid_stage0_check", os.path.join(ROOT, "tools", "faceid_stage0_check.py"))
_s0 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_s0)

ensure_ascii = _s0.ensure_ascii
imread_unicode = _s0.imread_unicode
py_embed = _s0.py_embed
DETECT_SIZE = _s0.DETECT_SIZE


def build_pairs(lfw_root, per_class, seed):
    """按人物目录分组，确定性抽样正/负样本对。"""
    people = {}
    for d in sorted(glob.glob(os.path.join(lfw_root, "*"))):
        if not os.path.isdir(d):
            continue
        imgs = sorted(glob.glob(os.path.join(d, "*.jpg")))
        if len(imgs) >= 2:
            people[d] = imgs
    if len(people) < 10:
        return None, None

    rng = random.Random(seed)
    names = sorted(people.keys())

    positives = []
    for name in names:
        imgs = people[name]
        for _ in range(3):  # 每人最多贡献 3 个正对，避免"照片多的人"主导结果
            a, b = rng.sample(imgs, 2)
            positives.append((a, b))
    rng.shuffle(positives)
    positives = positives[:per_class]

    negatives = []
    for _ in range(per_class * 3):
        a, b = rng.sample(names, 2)
        negatives.append((rng.choice(people[a]), rng.choice(people[b])))
    rng.shuffle(negatives)
    negatives = negatives[:per_class]
    return positives, negatives


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return 0.0 if na <= 0 or nb <= 0 else float(np.dot(a, b) / (na * nb))


def score_pairs(pairs, detector, session, cache):
    """返回 (scores, 有效对数, 跳过对数)。"""
    scores, skipped = [], 0
    for a, b in pairs:
        ea = cache.get(a)
        if ea is None:
            ea = py_embed(detector, session, a)
            if ea is not None:
                cache[a] = ea
        eb = cache.get(b)
        if eb is None:
            eb = py_embed(detector, session, b)
            if eb is not None:
                cache[b] = eb
        if ea is None or eb is None:
            skipped += 1
            continue
        scores.append(cos(ea, eb))
    return scores, len(pairs) - skipped, skipped


def tar_at_far(genuine, impostor, far):
    """给定 FAR，找阈值并返回 TAR（阈值取 impostor 的 (1-far) 分位上侧）。"""
    if impostor is None or len(impostor) == 0:
        return None, None
    thr = float(np.quantile(impostor, 1.0 - far))
    tar = float(np.mean(genuine >= thr)) if (genuine is not None and len(genuine) > 0) else 0.0
    return thr, tar


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lfw-root", default=DEFAULT_LFW)
    ap.add_argument("--pairs", type=int, default=1500)
    ap.add_argument("--threshold", type=float, default=0.50, help="当前 FaceIdOptions 默认阈值")
    ap.add_argument("--seed", type=int, default=20261018)
    args = ap.parse_args()

    if not os.path.isdir(args.lfw_root):
        print(f"找不到 LFW 目录：{args.lfw_root}\n下载方式见 tools/README.md 的 FaceId 一节。", file=sys.stderr)
        return 2

    yunet = ensure_ascii(os.path.join(FACE_MODELS, "face_detection_yunet_2023mar.onnx"))
    arcface = ensure_ascii(os.path.join(FACE_MODELS, "face_recognition_arcface_w600k_r50.onnx"))
    detector = (cv2.FaceDetectorYN.create(yunet, "", DETECT_SIZE, 0.6, 0.3, 5000)
                if hasattr(cv2.FaceDetectorYN, "create")
                else cv2.FaceDetectorYN.Create(yunet, "", DETECT_SIZE, 0.6, 0.3, 5000))
    session = ort.InferenceSession(arcface, providers=["CPUExecutionProvider"])

    positives, negatives = build_pairs(args.lfw_root, args.pairs, args.seed)
    if positives is None:
        print("LFW 目录里没有足够的多图人物", file=sys.stderr)
        return 2

    cache = {}
    gen, gen_ok, gen_skip = score_pairs(positives, detector, session, cache)
    imp, imp_ok, imp_skip = score_pairs(negatives, detector, session, cache)
    if not gen or not imp:
        print("有效对数为 0", file=sys.stderr)
        return 2

    gen, imp = np.array(gen), np.array(imp)
    acc = float(np.mean([(np.mean(gen >= args.threshold) + np.mean(imp < args.threshold)) / 2]))

    # EER：在阈值扫描上找 |FAR - FRR| 最小点
    thresholds = np.linspace(0.0, 1.0, 2001)
    far = np.array([np.mean(imp >= t) for t in thresholds])
    frr = np.array([np.mean(gen < t) for t in thresholds])
    eer_idx = int(np.argmin(np.abs(far - frr)))
    eer = float((far[eer_idx] + frr[eer_idx]) / 2)
    eer_thr = float(thresholds[eer_idx])

    thr4, tar4 = tar_at_far(gen, imp, 1e-4)
    thr5, tar5 = tar_at_far(gen, imp, 1e-5)

    print(f"LFW 子集评测（ArcFace w600k_r50 · Glint360K · 512 维）")
    print(f"  正样本对 {gen_ok}/{gen_ok + gen_skip}，负样本对 {imp_ok}/{imp_ok + imp_skip}"
          f"（无脸/质检失败计跳过），缓存 {len(cache)} 张图")
    print(f"  默认阈值 {args.threshold:.2f} 下的平均准确率：{acc * 100:.2f}%")
    print(f"  EER：{eer * 100:.2f}%（阈值 {eer_thr:.3f}）")
    print(f"  TAR@FAR=1e-4：{tar4 * 100:.2f}%（阈值 {thr4:.3f}）" if thr4 is not None else "  TAR@FAR=1e-4：负样本不足")
    print(f"  TAR@FAR=1e-5：{tar5 * 100:.2f}%（阈值 {thr5:.3f}）" if thr5 is not None else "  TAR@FAR=1e-5：负样本不足")
    print(f"  正样本余弦 min/mean：{gen.min():.3f}/{gen.mean():.3f}；"
          f"负样本余弦 max/mean：{imp.max():.3f}/{imp.mean():.3f}")

    ok = acc >= 0.99
    print(f"\n判据（默认阈值下准确率 >= 99%）：{'通过' if ok else '未通过'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
