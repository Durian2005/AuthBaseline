# face-models/ — 人脸模型文件（随发布产物与安装包一并分发）

本目录的 ONNX 模型来自上游开源项目，**版权归原作者所有，遵循各自的上游许可证**，
不在本仓库 MIT 授权的覆盖范围内。

| 文件 | 大小 (字节) | 用途 | 许可证 | 随仓库分发 |
|---|---|---|---|---|
| `face_detection_yunet_2023mar.onnx` | 232,589 | 人脸检测（YuNet，2FA 与 FaceId 两个模块共用） | MIT | 是 |
| `face_recognition_sface_2021dec.onnx` | 38,696,353 | 人脸 2FA 的特征提取（SFace） | Apache-2.0 | 是 |
| `face_recognition_arcface_w600k_r50.onnx` | 174,383,860 | FaceId（纯人脸登录）的特征提取（ArcFace，Glint360K 训练，512 维） | **仅限非商业研究** | **否，见下文** |

许可证原文已随模型一并放在本目录：

- `LICENSE_yunet.txt` — MIT，`Copyright (c) 2020 Shiqi Yu <shiqi.yu@gmail.com>`
- `LICENSE_sface.txt` — Apache License 2.0（上游文件中的版权人为未填写的占位符，照原样保留）

**再分发时请一并保留这两个许可证文件。**

## 校验值（SHA-256）

```
8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4  face_detection_yunet_2023mar.onnx
0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79  face_recognition_sface_2021dec.onnx
4c06341c33c2ca1f86781dab0e829f88ad5b64be9fba56e56bc9ebdefc619e43  face_recognition_arcface_w600k_r50.onnx
```

## ArcFace 权重：研究许可，**不入库**

`face_recognition_arcface_w600k_r50.onnx` 来自 [insightface](https://github.com/deepinsight/insightface)
模型 zoo 的 buffalo_l 包（w600k_r50：WebFace600K/Glint360K 训练）。
上游声明 **these models are only used for non-commercial research purposes**，
与 YuNet/SFace 的 MIT/Apache-2.0 不同，因此：

- 它**不在 git 里**（`.gitignore` 已挡住），本仓库只分发许可友好的两个模型；
- 需要它的人按下面的说明自行下载并校验 SHA-256；
- 文件缺失时 FaceId 引擎判"不可用"并显式降级留痕（启动不拒绝、接口 fail closed），
  不影响人脸 2FA 与其余任何功能。

### 下载（任选其一，校验值以本节 SHA-256 为准）

```bash
# 上游发布页（canonical）：
curl -L -o face_recognition_arcface_w600k_r50.onnx \
  https://github.com/deepinsight/insightface/releases/download/v0.7/w600k_r50.onnx

# 镜像（本机实测 GitHub Releases 走代理 502 时可用；文件与上游逐字节同源）：
curl -L -o face_recognition_arcface_w600k_r50.onnx \
  "https://modelscope.cn/api/v1/models/cunkai/ComfyUI_Notebook/repo?Revision=master&FilePath=buffalo_l/w600k_r50.onnx"

sha256sum face_recognition_arcface_w600k_r50.onnx
# 期望：4c06341c33c2ca1f86781dab0e829f88ad5b64be9fba56e56bc9ebdefc619e43
```

## 需要重新下载时（YuNet / SFace）

模型在 OpenCV Zoo 仓库里由 **Git LFS** 托管，直接访问 `raw.githubusercontent.com`
只会拿到 LFS 指针文件（131 字节）而不是模型本体。下载后请用上面的 SHA-256 校验。

## 本项目怎么用这两个文件

- 路径由 `AuthServer/Services/Face/FaceOptions.cs` 的 `DetectorModel` / `RecognizerModel` 指定，
  默认就是本目录下的相对路径。`Resolve()` 按 **`AppContext.BaseDirectory`**（即 exe 所在目录）
  展开成绝对路径，**不是**按当前工作目录 —— 这样"双击 exe"与"被 Tauri 当 sidecar 拉起"
  两种启动方式看到的是同一份模型。
- 因此模型目录**必须与可执行文件同级的 `face-models/`**：
  - 开发态：`AuthServer/AuthServer.csproj` 用
    `<None Include="face-models\**" CopyToOutputDirectory="PreserveNewest">`
    复制到 `bin/Debug/net8.0/face-models/`；
  - 装机态：`src-tauri/tauri.conf.json` 的 `bundle.resources` 把它映射到安装目录的 `face-models/`
    （`externalBin` 只搬 exe，模型目录必须走 `resources`，否则发布产物里没有模型）。
- ⚠️ 目录名刻意叫 `face-models` 而**不是** `models`：Windows 下 `AuthServer/models`
  与 C# 源码目录 `AuthServer/Models` 是**同一个目录**（大小写不敏感，MSBuild 通配符同样不敏感），
  取名 `models` 会让模型文件混进源码目录。
- ⚠️ OpenCV 无法从**非 ASCII 路径**读取 ONNX：中文路径下 YuNet 的 `Create` 会失败
  （路径按 ANSI 编组后变成乱码）。`CvFaceEngine.EnsureAsciiModel()` 会先把模型镜像到
  `%LOCALAPPDATA%\AuthBaselineData\face-models\<路径哈希>\` 再加载，因此本项目
  **不需要**任何环境变量来指定模型位置。
