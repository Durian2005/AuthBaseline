#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
faceid_pad_check.py — FaceId（纯人脸登录）P1b 的活体判定：等价性对照 + 真机标定。

要回答两件事，分两个模式：

1) `--compare`：**C# 的预处理与参考实现等价吗？**
   C#：AuthServer.exe --faceid-pad <img...>   （Services/FaceId/FaceIdPadCli.cs）
   Python：YuNet 检测 → 2.7 倍中心裁 → resize 80×80 → BGR、**不除 255** → NCHW → onnxruntime
   判据：逐张 |Δlive| ≤ 1e-4（softmax 是连续函数，末位差异来自 float 加法次序）。

   为什么这一层不能省：PAD 的分数对"除不除 255 / 通不通道交换 / 裁多大"极其敏感，
   而错误**不会抛异常** —— 它只会安静地给出一个错数。实测过：除 255 之后，46 帧真人样本
   的 live 从 0.88 掉到 0，全部被判成 replay。这种错只能靠对照抓。

2) `--dist`：**阈值该定在哪？**
   给两组目录（活人帧 / 攻击帧），输出各自的 live 分布与"两组不重叠"的阈值区间。
   攻击帧的采法见 docs/reports/FACEID-P1B-PAD-REPORT.md（手机屏翻拍 / 打印照片 / 视频回放）。

依赖：隔离 venv（numpy / opencv-python<5 / onnxruntime），见 tools/README.md A4。
模型与 C# 用的是同一份：AuthServer/face-models/minifasnet_v2_80x80.onnx。

用法：
  python tools/faceid_pad_check.py --compare [--images DIR...] [--tol 1e-4]
  python tools/faceid_pad_check.py --dist --live DIR --spoof DIR
"""
import argparse
import glob
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

import cv2
import numpy as np
import onnxruntime as ort

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FACE_MODELS = os.path.join(ROOT, "AuthServer", "face-models")
DEFAULT_SERVER = os.path.join(ROOT, "AuthServer", "bin", "Debug", "net8.0", "AuthServer.exe")
DEFAULT_IMAGES = os.path.join(ROOT, "tools", "fixtures", "face")

DETECT_SIZE = (640, 480)      # 与 CvFaceIdEngine 的 FaceDetectorYN 预设一致
INPUT_SIZE = 80               # MiniFASNetV2 固定输入
CROP_SCALE = 2.7              # 上游文件名里的 2.7 —— 红线，别改
LIVE_INDEX = 1                # 三分类 [print, live, replay]


def ensure_ascii(path):
    """OpenCV 读不了非 ASCII 路径（模型与图片都一样）：先镜像到临时 ASCII 目录。"""
    if all(ord(c) < 128 for c in path):
        return path
    if not os.path.exists(path):
        return path
    dst_dir = os.path.join(tempfile.gettempdir(), "faceid-models")
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, os.path.basename(path))
    if not (os.path.exists(dst) and os.path.getsize(dst) == os.path.getsize(path)):
        shutil.copyfile(path, dst)
    return dst


def mirror_images(paths):
    """把待测图片复制到 ASCII 目录，返回 [(原路径, 镜像路径)]。

    C# 侧用 Cv2.ImRead，中文目录会读成空 Mat（报 "read failed"），
    所以对照实验必须走镜像；Python 侧则用 imdecode，两个都能读。
    """
    dst_dir = os.path.join(tempfile.gettempdir(), "faceid-pad-imgs")
    os.makedirs(dst_dir, exist_ok=True)
    out = []
    for i, p in enumerate(paths):
        tag = hashlib.sha1(p.encode("utf-8")).hexdigest()[:10]
        dst = os.path.join(dst_dir, "%03d_%s%s" % (i, tag, os.path.splitext(p)[1]))
        if not os.path.exists(dst):
            shutil.copyfile(p, dst)
        out.append((p, dst))
    return out


def imread_u(path):
    return cv2.imdecode(np.fromfile(path, dtype=np.uint8), cv2.IMREAD_COLOR)


def crop_27(img, box):
    """以框中心扩 2.7 倍并夹到画面内。取整用 int()（向零截断），与 C# 的 (int) 一致。"""
    x, y, w, h = box
    cx, cy = x + w / 2.0, y + h / 2.0
    hw, hh = w * CROP_SCALE / 2.0, h * CROP_SCALE / 2.0
    x1 = max(0, int(cx - hw))
    y1 = max(0, int(cy - hh))
    x2 = min(img.shape[1], int(cx + hw))
    y2 = min(img.shape[0], int(cy + hh))
    if x2 - x1 < 8 or y2 - y1 < 8:
        return None
    return img[y1:y2, x1:x2]


def softmax(v):
    e = np.exp(v - v.max())
    return e / e.sum()


class Reference:
    """Python 侧参考实现。预处理必须与 CvFaceIdLiveness 逐条对应。"""

    def __init__(self):
        self.det = cv2.FaceDetectorYN.create(ensure_ascii(os.path.join(
            FACE_MODELS, "face_detection_yunet_2023mar.onnx")), "", DETECT_SIZE, 0.6, 0.3, 5000)
        self.sess = ort.InferenceSession(
            ensure_ascii(os.path.join(FACE_MODELS, "minifasnet_v2_80x80.onnx")),
            providers=["CPUExecutionProvider"])
        self.input_name = self.sess.get_inputs()[0].name

    def largest(self, img):
        self.det.setInputSize((img.shape[1], img.shape[0]))
        _, faces = self.det.detect(img)
        if faces is None or len(faces) == 0:
            return None
        return max(faces, key=lambda r: r[2] * r[3])[:4]

    def live(self, img):
        box = self.largest(img)
        if box is None:
            return None
        crop = crop_27(img, box)
        if crop is None:
            return None
        v = cv2.resize(crop, (INPUT_SIZE, INPUT_SIZE)).astype(np.float32)
        # ⚠️ 不除 255（红线）：保持 0–255、BGR、NCHW
        v = np.transpose(v, (2, 0, 1))[None, ...]
        probs = softmax(self.sess.run(None, {self.input_name: v})[0][0])
        return float(probs[LIVE_INDEX])


def collect(images):
    out = []
    for item in images:
        if os.path.isdir(item):
            out.extend(sorted(glob.glob(os.path.join(item, "*.jpg"))))
            out.extend(sorted(glob.glob(os.path.join(item, "*.jpeg"))))
            out.extend(sorted(glob.glob(os.path.join(item, "*.png"))))
        else:
            out.append(item)
    return [p for p in out if os.path.isfile(p)]


def cmd_compare(args):
    imgs = collect(args.images or [DEFAULT_IMAGES])
    if not imgs:
        print("没有找到图片")
        return 2

    server = args.server
    if not os.path.isfile(server):
        print("找不到后端：%s（先 dotnet build）" % server)
        return 2

    pairs = mirror_images(imgs)
    proc = subprocess.run([server, "--faceid-pad"] + [b for _, b in pairs],
                          capture_output=True)
    if proc.returncode != 0:
        print("C# 侧失败（exit=%d）：" % proc.returncode)
        print(proc.stderr.decode("utf-8", errors="replace")[:2000])
        return 3

    csharp = {}
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        parts = line.rsplit("\t", 1)
        if len(parts) == 2:
            csharp[parts[0]] = float(parts[1])

    ref = Reference()
    ok = 0
    bad = 0
    missing = 0
    worst = 0.0
    for original, mirrored in pairs:
        want = csharp.get(mirrored)
        img = imread_u(original)
        got = None if img is None else ref.live(img)
        if want is None or got is None:
            missing += 1
            print("  [SKIP] %s（C#=%s / py=%s）" % (os.path.basename(original), want, got))
            continue
        delta = abs(want - got)
        worst = max(worst, delta)
        if delta <= args.tol:
            ok += 1
        else:
            bad += 1
            print("  [DIFF] %s  C#=%.6f  py=%.6f  Δ=%.2e" %
                  (os.path.basename(original), want, got, delta))

    print("\n对照：一致 %d / 超差 %d / 跳过 %d   max|Δ|=%.3e  判据 %.0e" %
          (ok, bad, missing, worst, args.tol))
    return 0 if bad == 0 and ok > 0 else 1


THRESHOLDS = (0.30, 0.50, 0.70, 0.80)


def stats(values):
    a = np.array(values)
    return dict(n=len(a), min=float(a.min()), median=float(np.median(a)),
                max=float(a.max()), mean=float(a.mean()))


def _load(group, ref):
    """读一组图的 live 分数；检不到脸的帧不参与统计（它们在闸门里会被 NoFace 拒掉）。"""
    scores, skipped = [], 0
    for p in collect([group]):
        img = imread_u(p)
        if img is None:
            skipped += 1
            continue
        s = ref.live(img)
        if s is None:
            skipped += 1
            continue
        scores.append(s)
    return sorted(scores), skipped


def cmd_dist(args):
    if not args.live or not os.path.isdir(args.live):
        print("缺少活人目录 --live")
        return 2
    spoof_dirs = [d for d in (args.spoof or []) if d]
    if not spoof_dirs:
        print("缺少攻击目录 --spoof")
        return 2
    for d in spoof_dirs:
        if not os.path.isdir(d):
            print("攻击目录不存在：%s" % d)
            return 2

    ref = Reference()
    live_scores, live_skipped = _load(args.live, ref)
    if not live_scores:
        print("活人组没有任何可用帧（检测不到人脸？）")
        return 3

    # 活人侧单独报，攻击侧**按类型分组**报 —— 三类攻击的难度并不一样，
    # 合成一个总数会掩盖"哪一类最危险"这个唯一有价值的信息。
    groups = []
    for d in spoof_dirs:
        s, skipped = _load(d, ref)
        groups.append((os.path.basename(os.path.normpath(d)), s, skipped))
        if not s:
            print("攻击组 %s 没有任何可用帧" % d)
            return 3

    print("%-18s %-5s %-8s %-8s %-8s %-8s %s" % ("组", "n", "min", "p5", "median", "max", "≥阈值占比"))
    print("-" * 74)

    def row(label, s):
        a = np.array(s)
        print("%-18s %-5d %-8.4f %-8.4f %-8.4f %-8.4f %s" % (
            label, len(a), a.min(), np.percentile(a, 5), np.median(a), a.max(),
            " ".join("%.0f%%" % (x * 100) for x in [(a >= t).mean() for t in THRESHOLDS])))

    row("live", live_scores)
    for label, s, _ in groups:
        row("spoof:" + label, s)

    all_spoof = sorted(s for _, s, _ in groups for s in s)
    live_min = live_scores[0]
    spoof_max = all_spoof[-1]
    print("-" * 74)
    print("阈值候选：" + " / ".join("%.2f" % t for t in THRESHOLDS)
          + "  （每列 = 该组分数 ≥ 该阈值的比例）")
    print("活人最低 %.4f，攻击最高 %.4f（n=%d）" % (live_min, spoof_max, len(all_spoof)))

    if live_min > spoof_max:
        print("⇒ 两组在单帧层面完全不重叠，阈值区间 (%.4f, %.4f]" % (spoof_max, live_min))
    else:
        # 重叠只可能来自活人侧的少数坏帧（糊/侧脸）。它们本来就该被拒，
        # 且录入是"任一帧通过即可"，所以单帧重叠不等于不可用。
        below = [s for s in live_scores if s <= spoof_max]
        print("⚠️ 单帧层面重叠：活人组有 %d/%d 帧落在攻击组最高分之下（%.1f%%）"
              % (len(below), len(live_scores), 100.0 * len(below) / len(live_scores)))
        print("   这些帧通常是糊/侧脸的废帧；录入侧「任一帧通过即可」⇒ 影响的是单帧通过率，不是整次录入")

    # 会话级：录入只要**一帧**过阈值就成功，所以真正该看的是这个数
    print("-" * 74)
    for t in THRESHOLDS:
        live_pass = sum(1 for s in live_scores if s >= t) / len(live_scores)
        spoof_pass = [sum(1 for s in g if s >= t) for _, g, _ in groups]
        print("阈值 %.2f ⇒ 单帧：活人过 %.0f%%；攻击通过 %s（各自 0/%d 即理想）"
              % (t, live_pass * 100,
                 " / ".join("%d" % x for x in spoof_pass),
                 len(groups[0][1])))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--compare", action="store_true", help="C# 与 Python 参考实现的等价性对照")
    ap.add_argument("--dist", action="store_true", help="活人/攻击两组的分数分布与阈值建议")
    ap.add_argument("--images", nargs="*", help="compare 模式下的图片或目录")
    ap.add_argument("--live", help="dist 模式：活人帧目录")
    ap.add_argument("--spoof", nargs="+", help="dist 模式：攻击帧目录（可多个，逐组统计）")
    ap.add_argument("--tol", type=float, default=1e-4)
    ap.add_argument("--server", default=DEFAULT_SERVER)
    args = ap.parse_args()

    if args.compare:
        return cmd_compare(args)
    if args.dist:
        return cmd_dist(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
