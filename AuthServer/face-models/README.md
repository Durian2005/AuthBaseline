# face-models/ — 人脸模型文件（随发布产物与安装包一并分发）

这两个 ONNX 模型来自 [OpenCV Zoo](https://github.com/opencv/opencv_zoo)，
**版权归原作者所有，遵循各自的上游许可证**，不在本仓库 MIT 授权的覆盖范围内。

| 文件 | 大小 (字节) | 用途 | 许可证 |
|---|---|---|---|
| `face_detection_yunet_2023mar.onnx` | 232,589 | 人脸检测（YuNet） | MIT |
| `face_recognition_sface_2021dec.onnx` | 38,696,353 | 人脸识别 / 特征提取（SFace） | Apache-2.0 |

许可证原文已随模型一并放在本目录：

- `LICENSE_yunet.txt` — MIT，`Copyright (c) 2020 Shiqi Yu <shiqi.yu@gmail.com>`
- `LICENSE_sface.txt` — Apache License 2.0（上游文件中的版权人为未填写的占位符，照原样保留）

**再分发时请一并保留这两个许可证文件。**

## 校验值（SHA-256）

```
8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4  face_detection_yunet_2023mar.onnx
0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79  face_recognition_sface_2021dec.onnx
```

## 需要重新下载时

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
