#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
faceid_stage0_check.py — FaceId（纯人脸登录）P0 Stage 0 对照实验。

要证明的一件事：**C# 引擎（OpenCvSharp 的 YuNet + CvDnn ArcFace）与 Python 参考管线
（cv2 FaceDetectorYN + onnxruntime）对同一张图算出的嵌入逐位等价。**

为什么必须有它：
  P2 起，登录判定、审计、阈值全部建立在"C# 引擎输出的特征"之上。
  如果 C# 的预处理（对齐参考点 / (x-127.5)/128 / RGB 序）与参考实现有偏差，
  公开基准上 ArcFace 的分数就**不属于我们** —— 那是一条会骗人的证据链。

做法：
  每张图跑两遍 ——
    C#    ：AuthServer.exe --faceid-embed <img>   （ Services/FaceId/FaceIdEmbedCli.cs ）
    Python：cv2 检测 + LMEDS 五点对齐 + onnxruntime 前传
  两者对齐到 112x112 后提特征，比余弦。判据：min(cos) >= 0.999（SFace 上的既有结论是 0.9999，
  ArcFace 同为 ResNet 骨干，预期同量级）。

依赖：仅本脚本自身用到的 Python 环境（隔离 venv，见 tools/README.md 的 FaceId 一节）：
  numpy / opencv-python / onnxruntime。模型文件从 AuthServer/face-models/ 读，
  与后端用的是同一份（YuNet + w600k_r50）。

用法：
  python tools/faceid_stage0_check.py [--images DIR_OR_FILES...] [--min-cos 0.999]
默认图片源是 tools/fixtures/face/ 下的帧回放样本（真人脸，仅本机使用，绝不入库）。
"""
import argparse
import glob
import os
import subprocess
import sys

import cv2
import numpy as np
import onnxruntime as ort

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FACE_MODELS = os.path.join(ROOT, "AuthServer", "face-models")
DEFAULT_SERVER = os.path.join(ROOT, "AuthServer", "bin", "Debug", "net8.0", "AuthServer.exe")
DEFAULT_IMAGES = os.path.join(ROOT, "tools", "fixtures", "face")

# insightface 的 arcface_dst：112x112 画布上的标准五点（与 CvFaceIdEngine.ArcfaceRefPoints 一致）
ARCFACE_DST = np.array([
    [38.2946, 51.6963],
    [73.5318, 51.5014],
    [56.0252, 71.7366],
    [41.5493, 92.3655],
    [70.7299, 92.2041],
], dtype=np.float32)

DETECT_SIZE = (640, 480)   # 必须与 CvFaceIdEngine 的 FaceDetectorYN 预设一致


def ensure_ascii(path):
    """OpenCV 读不了非 ASCII 路径下的 ONNX（与 CvFaceIdEngine.EnsureAsciiModel 同原因：
    路径按 ANSI 编组后变乱码）。本项目目录名含中文，所以先把模型镜像到 ASCII 临时目录。"""
    if all(ord(c) < 128 for c in path):
        return path
    if not os.path.exists(path):
        return path
    import tempfile
    dst_dir = os.path.join(tempfile.gettempdir(), "faceid-models")
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, os.path.basename(path))
    if not (os.path.exists(dst) and os.path.getsize(dst) == os.path.getsize(path)):
        import shutil
        shutil.copyfile(path, dst)
    return dst


def collect_images(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "**", "*.jpg"), recursive=True))
            files += sorted(glob.glob(os.path.join(p, "**", "*.png"), recursive=True))
        else:
            files.append(p)
    return files


def cs_embed(server, image):
    """调 C# CLI 拿嵌入；失败返回 None。"""
    try:
        # 不用 text=True：C# 控制台在中文 Windows 下按 GBK 输出启动横幅，
        # 以 UTF-8 严格解码会炸。嵌入行本身是纯 ASCII，容错解码即可。
        out = subprocess.run([server, "--faceid-embed", image],
                             capture_output=True, timeout=120)
        stdout = out.stdout.decode("utf-8", errors="replace")
        stderr = out.stderr.decode("utf-8", errors="replace")
    except Exception as ex:  # noqa: BLE001
        print(f"  [cs] 调用失败：{ex}", file=sys.stderr)
        return None
    # 解析时不依赖回显的路径：C# 控制台在中文 Windows 下按 GBK 输出，
    # 含中文的图片路径回显后会被 errors="replace" 打成 U+FFFD，精确比对必然失败。
    # 每次只调用一张图，输出里恰好一行 TSV，按形状识别即可。
    for line in stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and "," in parts[2]:
            try:
                return np.array([float(x) for x in parts[2].split(",")], dtype=np.float64)
            except ValueError:
                continue
    print(f"  [cs] 无输出：{stderr.strip()[:200]}", file=sys.stderr)
    return None


def imread_unicode(path):
    """cv2.imread 在 opencv-python 的 Windows 构建上读不了中文路径（窄字符 fopen）。
    用 np.fromfile（Python 侧宽字符 API）+ imdecode 绕开 —— 与 C# 侧读同一份文件。"""
    try:
        data = np.fromfile(path, dtype=np.uint8)
    except Exception:
        return None
    if data.size == 0:
        return None
    return cv2.imdecode(data, cv2.IMREAD_COLOR)


def py_embed(detector, session, image):
    """Python 参考管线：与 CvFaceIdEngine 的每一步逐一对应。"""
    img = imread_unicode(image)
    if img is None or img.size == 0:
        return None
    oh, ow = img.shape[:2]

    # ① 检测：C# 在尺寸不符时先缩放到预设尺寸再检测，随后把坐标映射回原图。
    small = cv2.resize(img, DETECT_SIZE) if (ow, oh) != DETECT_SIZE else img
    _, faces = detector.detect(small)
    if faces is None or len(faces) == 0:
        return None
    best = max(faces, key=lambda f: f[2] * f[3])

    sx, sy = ow / DETECT_SIZE[0], oh / DETECT_SIZE[1]
    src = np.array([
        [best[4] * sx, best[5] * sy],
        [best[6] * sx, best[7] * sy],
        [best[8] * sx, best[9] * sy],
        [best[10] * sx, best[11] * sy],
        [best[12] * sx, best[13] * sy],
    ], dtype=np.float32)

    # ② 对齐：LMEDS + WarpAffine 112x112（与 C# 的 EstimateAffinePartial2D(LMEDS) 对应）
    m, _ = cv2.estimateAffinePartial2D(src, ARCFACE_DST, method=cv2.LMEDS)
    if m is None:
        return None
    aligned = cv2.warpAffine(img, m, (112, 112))

    # ③ 特征：RGB 序 + (x-127.5)/128 + NCHW（与 CvDnn.BlobFromImage(1/128, mean=127.5, swapRB=true) 对应）
    rgb = cv2.cvtColor(aligned, cv2.COLOR_BGR2RGB).astype(np.float32)
    blob = ((rgb - 127.5) / 128.0).transpose(2, 0, 1)[np.newaxis, ...]
    name = session.get_inputs()[0].name
    out = session.run(None, {name: blob})[0]
    return out.flatten().astype(np.float64)


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na <= 0 or nb <= 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--images", nargs="*", default=None)
    ap.add_argument("--server", default=DEFAULT_SERVER)
    ap.add_argument("--min-cos", type=float, default=0.999)
    args = ap.parse_args()

    images = collect_images(args.images or [DEFAULT_IMAGES])
    if not images:
        print("没有找到任何图片", file=sys.stderr)
        return 2
    if not os.path.exists(args.server):
        print(f"找不到 AuthServer.exe：{args.server}\n先 dotnet build AuthServer/AuthServer.csproj", file=sys.stderr)
        return 2

    yunet = ensure_ascii(os.path.join(FACE_MODELS, "face_detection_yunet_2023mar.onnx"))
    arcface = ensure_ascii(os.path.join(FACE_MODELS, "face_recognition_arcface_w600k_r50.onnx"))
    for f in (yunet, arcface):
        if not os.path.exists(f):
            print(f"缺少模型：{f}", file=sys.stderr)
            return 2

    # cv2 5.x 起方法名改为小写 create；老版本（4.x）是 Create。两种都试，保持脚本通用。
    detector = (cv2.FaceDetectorYN.create(yunet, "", DETECT_SIZE, 0.6, 0.3, 5000)
                if hasattr(cv2.FaceDetectorYN, "create")
                else cv2.FaceDetectorYN.Create(yunet, "", DETECT_SIZE, 0.6, 0.3, 5000))
    session = ort.InferenceSession(arcface, providers=["CPUExecutionProvider"])

    print(f"Stage 0 对照：{len(images)} 张图 · 判据 min(cos) >= {args.min_cos}")
    print(f"{'image':<58} {'dim':>4} {'cos(C#,Py)':>12}")
    worst, worst_img, skipped, ok = 2.0, "", 0, 0
    for img in images:
        cs = cs_embed(args.server, img)
        py = py_embed(detector, session, img)
        if cs is None or py is None:
            print(f"{os.path.relpath(img, ROOT):<58} {'skip':>4} {'—':>12}")
            skipped += 1
            continue
        c = cos(cs, py)
        ok += 1
        if c < worst:
            worst, worst_img = c, img
        flag = "" if c >= args.min_cos else "  ← 低于判据"
        print(f"{os.path.relpath(img, ROOT):<58} {len(cs):>4} {c:>12.6f}{flag}")

    print(f"\n有效 {ok} 张，跳过 {skipped} 张；min(cos) = {worst:.6f}（{os.path.basename(worst_img)}）")
    if ok == 0:
        return 2
    return 0 if worst >= args.min_cos else 1


if __name__ == "__main__":
    sys.exit(main())
