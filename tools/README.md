# tools/ —— 验证、运维与构建脚本

> 这个目录的定位是「**用真机证明结论**」：起真后端、打真 HTTP、直连真库看落地结果。
> 结论只认实测，不认代码推断。
>
> 相关文档：报告与设计稿在仓库根目录；操作细则见 `~/.workbuddy/skills/authbaseline-backend-probe`；
> 历史决策见 `.workbuddy/memory/`。

## 三条铁律

1. **破坏性实验一律用测试库**（库名必须**含** `Probe`），绝不动 `AuthBaselineDb`。
   - **探针**：`_guard()` 对真实库**硬拒**，逃生舱是环境变量 `AUTHBASELINE_ALLOW_REAL_DB=1`。
   - **管理 / 验收脚本**：真实库是**合法目标**，但必须显式加 `--i-know-this-is-the-real-db`。
   - ⚠️ 这两套库名规则**刻意不合并**：探针打真实库是 *bug*（参数错位），验收脚本打真实库是*设计意图*。
     同一条规则罩不住两种相反的意图。改动任何一边前，先读 `_probe_common.py` 顶部说明。
2. **起后端必须走 `_probe_common`**（`start_backend` / `http_call` / `wait_backend_ready` / `stop_backend`），
   不要自己拼 `subprocess` 和环境变量。
   **唯一例外是测 TLS 的脚本** —— `start_backend` 为了探针安全硬编码了 `http://` 并强制注入测试库，
   拿它测不出加密。
3. **`stdout` 必须重定向到文件或 `DEVNULL`** —— 给 .NET 后端接 `PIPE` 而父进程不读会**假死**（已实测）。

## 公共基础层（其余脚本的底座）

| 文件 | 作用 |
|---|---|
| `_probe_common.py` | 所有探针的**唯一**基础设施出口：库名守卫、起停后端、HTTP 调用（带代理绕过）、就绪探测、`require_real_db_optin()` |
| `_probe_common_selftest.py` | 守卫自测 **37 项**。**改守卫必须同步加用例**，否则等于把安全设施降到"没人验证"的状态 |
| `_toolchain.py` | 定位托管 node / npm（`find_node()` / `find_npm()`）。**任何脚本都别写死版本目录** —— 目录名带构建号会漂移（实测 `22.22.2-3` → `-6`），写死的后果是构建链与界面检查脚本一起 `FileNotFoundError`，而报错只说"系统找不到指定的文件" |

## 分类清单

「公共层」= 是否已改为从 `_probe_common` 取基础设施；「真实库」= 是否会触碰 `AuthBaselineDb`。

### A. 真机探针（回归套件主力 · 打测试库）

| 文件 | 作用 | 公共层 | 真实库 |
|---|---|---|---|
| `role_separation_test.py` | 角色分离：管账号的看不到日志、看日志的管不了账号；Admin 可建普通用户/用户管理员/审计管理员（**不可建 Admin**）且邮箱可选（**92 项**） | ✓ | — |
| `sod_detect_probe.py` | 职责分离**绕过检测层**：admin 造审计管理员 → 借它读审计必须报 `ATTRIBUTED`；造号不用 → `DORMANT`；自助改密 → `SEALED`；admin 打同接口 403 且留痕；接口结论与 `sod_trace.py` 独立复算**逐链对账**（**50 项**） | ✓ | — |
| `lockout_clock_probe.py` | 锁定能否靠拨钟解开、失败计数窗口（3 分钟内 3 次）、未锁定阶段拨钟的留痕与加固后还剩哪些边界（**40 项**） | ✓ | — |
| `ticket_hash_probe.py` | 会话票据哈希化（存储安全 S1）（**27 项**） | ✓ | — |
| `pepper_probe.py` | 口令 pepper + 渐进迁移（存储安全 S2）（**45 项**，最完整的一份） | ✓ | — |
| `dormant_account_probe.py` | 沉睡（僵尸）账号治理（**37 项**）。默认测试库；`--real` 才碰真实库 | ✓ | 需 `--real` |
| `race_storm_test.py` | 并发「写审计」与「完整性校验」风暴的竞态复现/回归 | — | — |
| `password_event_probe.py` | admin 改密失败（弱口令）有没有进审计日志 | — | ✓ 只读 + 只走失败分支 |
| `verify_chain_independent.py` | 独立复算哈希链：用 Python 从零重算，**不依赖后端代码** | — | 只读 |
| `face_second_factor_probe.py` | 人脸第二因子十一组：骨架（未录人脸行为不变）/ 两步式录入与挑战绑定 / 口令后只发挑战 / 降级闸门 / 处置（重置 + 注销连带）/ **识别画面（预览门禁：无票 404、票据不能当预览凭据、采集结束即失效、拉帧不写审计）** / fail-closed 503 / B 组不计次 / A 组计次触发锁定 / 模板密文与审计无特征（**93 项**）。**自带假引擎环境变量，无需摄像头** | ✓ | — |
| `poller_test.mjs` | 前端轮询器语义单元回归（**15 项**，`node` 直跑，不启后端） | — | — |

### A2. 装机产物校验（**Release / 单文件 / NSIS 布局**）

Debug 构建与发布链路隔着 Publish 与 NSIS 两层，行为**不保证一致**（已踩：单文件打包器
把 YuNet 的 `.onnx` 吞进 exe 并从发布目录删掉 ⇒ 装机后已录人脸账号全部 fail closed）。

两种模式，判据相同、证据强度不同：

- **自建镜像**（默认）—— 按 NSIS 的 `File /oname=` 布局镜像一份产物到
  `.workbuddy/tmp/install_mirror/`。**必须先跑过 `publish:backend` + `sync:sidecar`**。
  改完 publish 就能跑，不必真的安装。
- **真实装机目录**——`--install-dir <%LOCALAPPDATA%>\AuthBaseline`，装完 NSIS 之后跑。
  多验一层：装机 exe 的 md5 应与 `publish` 一致、`uninstall.exe` 已写出（安装完成判据）。
  ⚠️ 空目录/半成品目录会被拦（exe 为 0 字节 ⇒ 安装被中断）。

| 文件 | 作用 | 公共层 | 真实库 |
|---|---|---|---|
| `verify_publish_layout.py` | **CI 用的轻量版**布局校验：face-models 两文件在磁盘上且非空、exe 内**不含**这些文件名、`wwwroot/index.html` 与 `appsettings.json` 存在。不启动后端、不连库 —— 它守的是"构建配置被改坏"，完整验收仍走 `face_release_probe.py` | — | — |
| `face_release_probe.py` | 装机产物校验：① 布局（face-models 5 文件 / exe **非空** / exe 内**未**内嵌 onnx）；② 真引擎（`=cv`）能从目标目录的 `face-models` 加载；③ 把 `face_second_factor_probe.py` 的全部断言打到目标 exe 上（共 **14 项 + 内嵌 93 项**） | ✓ | — |

### A3. 人脸动作挑战的帧回放（不连库、不连后端）

录制命令在服务端：`authserver.exe --face-record <目录> <left|right>`（**需要摄像头**）。
回放与对账：

| 文件 | 作用 | 需要什么 |
|---|---|---|
| `face_fixture_check.py` | 逐个回放 `tools/fixtures/face/*`，比对 `passed` 与 `businessCode`。回放走 `CvFaceEngine.RunChallenge` 的同一段代码，只把采集源换成图片目录 | 模型文件（无需摄像头） |

⚠️ `tools/fixtures/` 里是**真人的脸**，已列入 `.gitignore`，不得入库。

### A4. 纯人脸登录（FaceId）P0 评测（不连库、不连后端）

对应 `AuthServer/Services/FaceId/`（YuNet + ArcFace w600k_r50，**无活体、独立模块**）。
结论与证据见 `docs/reports/FACEID-P0-BASELINE-REPORT.md`。

**独立 Python 环境**（与系统 Python 隔离；`opencv-python` 必须 <5，5.x 移除了
`FaceDetectorYN.create` 小写入口）：

```bash
python -m venv .venv-faceid
.venv-faceid/Scripts/pip install numpy onnxruntime "opencv-python<5" pymongo
```

| 文件 | 作用 | 需要什么 |
|---|---|---|
| `faceid_stage0_check.py` | **Stage 0 对照**：C# CLI（`AuthServer.exe --faceid-embed <图...>`）与 Python 参考管线逐位等价，判据 min(cos) ≥ 0.999。默认图片源 `tools/fixtures/face/` | Debug 构建 + 两个 onnx |
| `faceid_lfw_eval.py` | **LFW 子集评测**：1500 正 + 1500 负对（固定种子），出 acc@阈值 / EER / TAR@FAR。import Stage 0 脚本复用参考管线（不复制，防两处漂移） | 同左 + LFW 数据 |

数据与模型（**都不入库**）：

- LFW：官方站点不可达时从 ModelScope `Composable/labeled_faces_in_the_wild` 下载，
  解压到 `.workbuddy/tmp/lfw/`（结构 `lfw-deepfunneled/lfw-deepfunneled/<人物>/<图片>`）。
- ArcFace 权重：`AuthServer/face-models/face_recognition_arcface_w600k_r50.onnx`
  （174,383,860 字节，sha256 `4c06341c33c2ca1f86781dab0e829f88ad5b64be9fba56e56bc9ebdefc619e43`），
  上游仅授权**非商业研究**用途，下载与校验方式见 `AuthServer/face-models/README.md`。

⚠️ 两个坑（脚本内已处理，改脚本前先读）：① OpenCV 读不了**中文路径**下的 onnx
（本仓库目录名就含中文）—— 先镜像到 ASCII 目录再加载；② .NET 控制台按 GBK 回显，
Python 侧按字节接、`errors="replace"` 容错解码。

### A5. 纯人脸登录（FaceId）P1 录入闸门（假引擎 / 独立测试库）

对应 `AuthServer/Services/FaceId/` 的录入链路（P1a）。两份脚本**都不需要摄像头**：
假引擎的行为由环境变量切换（`AUTHBASELINE_FACEID_STUB_BEHAVIOR`），
所以多脸 / 侧脸 / 糊 / 引擎不可用这些分支可以被确定性地覆盖。

| 文件 | 作用 | 需要什么 |
|---|---|---|
| `faceid_enroll_probe.py` | **接口 + 库级回归（75 项，10 组）**：状态、口令二次确认（计次）、五条质量拒绝路径、模板密文落库、审计不含特征、上限淘汰、模型作废、删除、注销连带清理、**活体闸门（I 组：spoof 拒 + 计次 / 模型缺失 503 / 关闭后放行）**、**人脸登录（J 组：签票可用 / `SecondFactor=FACEID` / 未录入不计次 / 判错计次 / 不存在账号同码）** | Debug 构建 + 系统 Python（pymongo） |
| `ui_faceid_check.py` | **界面自验（17 项）**：headless Edge + CDP 登录态 → 账号页截图，断言「刷脸登录」与「纯人脸登录」是两张独立卡片、状态/模型/二次口令文案齐备；**再验新建账号弹窗初始口令固定为 `Abc12345` 且只剩一个口令框**；**退出后验登录页「人脸登录」页签与表单** | venv（`pip install "websockets<14"`）+ `AuthServer/wwwroot` |

```bash
# 接口回归（库名必须含 Probe，脚本已守卫）
python tools/faceid_enroll_probe.py AuthServer/bin/Debug/net8.0/AuthServer.exe 5391
# 界面自验（产物 tools/evidence/faceid_p{1_account,2_create_account,2_login}_ui.png，
#           证据目录不入库）
<faceid venv>/python tools/ui_faceid_check.py
```

⚠️ 三个坑：① 探针必须 `AUTHBASELINE_REQUIRE_HTTPS=false`；② `faceid_enroll_probe.py`
用**系统** Python（pymongo 只装在那里），`ui_faceid_check.py` 用 faceid venv
（依赖 websockets）；③ `dotnet build` **不复制** `wwwroot` ⇒ 界面脚本显式设
`ASPNETCORE_CONTENTROOT` 指向 `AuthServer/`，否则页面 404。
⚠️ J 组测「判错」必须换 **`AUTHBASELINE_FACEID_STUB_IDENTITY`**：默认它等于探针用户，
同一身份算出的特征余弦恒 1.0，判错永远测成 200（本组曾因此假通过过一轮）。

⚠️ 质量闸门的四个阈值（最小脸宽 0.12 / 清晰度 60 / 偏航 0.35 / 滚转 0.30）只是**起点**，
不是标定结论：真机标定属于 P1b（与 P3 的阈值定档同批做）。

### A6. 纯人脸登录（FaceId）P1b 活体判定：对照与标定

对应 `AuthServer/Services/FaceId/CvFaceIdLiveness.cs`（MiniFASNetV2，**被动、单帧**，无动作挑战）。
两份工作都靠一个脚本，按模式切换。

| 模式 | 作用 | 需要什么 |
|---|---|---|
| `--compare` | **预处理等价**：C#（`--faceid-pad`）与 Python 参考管线逐张比 `live` 分数，判据 Δ ≤ 1e-4。实测 46 帧 max\|Δ\| = 9e-7 | Debug 构建 + 模型 |
| `--dist` | **阈值标定**：`--spoof` 收多个目录，**按攻击类型逐组**报分布（手机 / 打印 / 回放难度不同，合并会掩盖最危险的那类），并按 0.30/0.50/0.70/0.80 四个候选阈值给出各组通过率 | 活人帧 + 至少一组攻击帧 |

```bash
# 等价性对照（改任何预处理之前先跑它 —— 除 255 这类错误不会报错，只会给错分数）
<faceid venv>/python tools/faceid_pad_check.py --compare --images tools/fixtures/face/left-ok

# 阈值标定（推荐：三类攻击分组报数）
<faceid venv>/python tools/faceid_pad_check.py --dist \
  --live tools/fixtures/face/left-ok \
  --spoof tools/fixtures/pad/spoof-phone tools/fixtures/pad/spoof-print tools/fixtures/pad/spoof-replay
```

实测（46 活人 + 120 攻击）：活人中位 0.968，三类攻击 max ≤ 0.0030，
**阈值 0.70 下攻击通过 0/120、活人单帧通过 91%**。数据与口径见
`docs/reports/FACEID-P1B-PAD-REPORT.md`。

⚠️ **活体默认是关的**（`FaceIdOptions.PadEnabled = false`）：本项目的验收方式就是
手举照片对着镜头测，默认开着会把流程整个堵死。上面的标定是"打开时"的效果；
要演示反欺骗就设 `AUTHBASELINE_FACEID_PAD_ENABLED=true` 重启后端。
同理，举手机时操作者自己容易同框，需要时用 `AUTHBASELINE_FACEID_ALLOW_MULTI_FACE=true`
放行多脸（取最大那张）。

采样用后端自己的命令（**不提示动作**，因为举照片的人没法配合"转头"）：

```bash
AuthServer/bin/Debug/net8.0/AuthServer.exe --faceid-capture <目录> [帧数=60] [间隔ms=120]
```

⚠️ 五个坑：① 采集走 `ImEncode + WriteAllBytes`（`ImWrite` 在中文目录会失败）；
② 活人侧可以直接复用 `tools/fixtures/face/left-ok`（同一摄像头、同一分辨率）；
③ **样本里有真人的脸，目录必须落在 `tools/fixtures/`（已 gitignore）**；
④ **攻击样本必须"人不出镜、只有攻击载体"** —— 本人的真脸一旦同框，YuNet 取最大框拿到的是真脸，
量到的是"多脸闸门"而不是活体模型（首次采样就栽在这里：40 帧里 23 帧同框）；
⑤ 采集命令要在**项目根目录**下跑，或路径写全 —— 相对路径按当前工作目录解析，
在 `C://Users//<你>` 下会报"不是内部或外部命令"。

### A7. 纯人脸登录（FaceId）识别精度：用照片做 1:N 比对

验收要覆盖"不同人种 / 明星各年龄段 / 双胞胎 / 特殊人群"，这些**找不到真人**，
只能拿照片测。这个脚本直接调后端自己的 `--faceid-embed`（**与线上同一条管线**）
算余弦，比在界面上逐张录入快一个数量级。

```bash
<faceid venv>/python tools/faceid_similarity_check.py \
  --template <模板图目录> --probe <探针图目录> [--threshold 0.50] [--gray-band 0.05]
```

输出：每张探针图的最佳匹配与判定（Pass / GrayZone / Mismatch）、汇总分布，
以及 0.30–0.70 的**阈值扫描计数**（换阈值会怎么变，一次看清）。

实测参考（同一台机器）：

| 组 | n | min | 中位 | max |
|---|---|---|---|---|
| 同一个人（`left-ok` 前 20 张当模板、后 26 张当探针） | 26 | 0.0025 | 0.8601 | 0.9675 |
| 不同人（模板=本人，探针=鲍喜顺翻拍） | 40 | 0.1804 | 0.2076 | 0.2340 |

⚠️ 三个坑：
① **中文路径不能靠回显匹配** —— C# 控制台在中文 Windows 下按 GBK 输出，路径回显到管道会被打成
`U+FFFD`。所以 `--faceid-embed` 的第一列是**输入序号**，调用方自己按顺序映射回路径；
② 同人组里余弦接近 0 的帧是**转头/糊掉的废帧**，不是阈值问题，看中位数而不是看 min；
③ 双胞胎会落在灰区甚至误通过 —— ArcFace 类模型的已知边界，别拿"准确率 96.83%"去暗示能分开。

### A8. 阈值定档：FAR/FRR 曲线（P3）

`faceid_similarity_check.py` 用真实照片量"能不能分开"；这个脚本用 LFW 量
**"阈值该定在哪"** —— 负样本拉到数万级才看得出尾部，只报 EER 一个点会定得过松。

```bash
<faceid venv>/python tools/faceid_threshold_sweep.py --pairs 3000 --neg 50000
```

输出：正/负样本余弦分布（含 p1 / p99.99）、0.20–0.60 的 FAR/FRR 表、
按目标 FAR（1e-2 / 1e-3 / 1e-4 / 1e-5）反推的阈值，以及与现行默认值的对比。

⚠️ 三个坑：
① **LFW 是简单集**，正样本 p1 只有 0.054（约 1% 的"同人对"是错标或极端姿态）
⇒ TAR 天花板约 98.3%，别拿它当线上估计；
② **1e-5 档位是外推**：5 万负对的分辨率到 1e-4 就到头了，脚本会打「仅外推」提示；
③ 跑一次约 **11 分钟**（约 8000 张图，ArcFace CPU 推理），中途每 500 张打一次进度。

### B. 端到端 / 验收

| 文件 | 作用 | 门禁 |
|---|---|---|
| `audit_e2e_test.py` | 实验二「让所有安全事件可追责」端到端验收（会**删改审计文档**模拟篡改） | `--i-know-this-is-the-real-db` |
| `tamper_helper.py` | 手动测「改不掉」的辅助工具（`restore` 会改写审计记录） | 仅 `restore` 需门禁 |
| `run_audit_e2e.py` | 在同一进程里起后端 → 串起四组验收脚本 → 关后端 | — |
| `email_e2e_test.py` | 邮箱验证码功能端到端（后端接口级） | — |
| `verify_email.py` | 「忘记密码」的验证码能否真实投递到邮箱 | — |
| `transport_func_check.py` | 生产态 HTTPS 业务回归（**9 项**）—— 证明加密后业务仍全通 | — |
| `transport_tls_probe.py` | TLS 链路断言（**A–E 五项**）—— 证明加密**不是装饰** | 需信任锚 `server.crt` |

### C. 界面级检查（起真实桌面端 + WebView2 CDP）

`*_check.py` 是「起进程 → 跑断言 → 收尾」的外壳（必须同进程，沙箱里调用方退出会回收 GUI 子进程）；
`*_events.mjs` 是真正通过 CDP 驱动界面的断言体。

| 外壳 | 断言体 | 验证内容 |
|---|---|---|
| `ui_tls_check.py` | `ui_tls_events.mjs` | 全链路走 TLS 且功能正常（**10 项**） |
| `ui_audit_check.py` | `ui_audit_events.mjs` | 审计员能在界面上单独捞出「改密失败」等失败类事件 |
| `ui_readonly_check.py` | `ui_readonly_events.mjs` | 审计日志页**不存在任何"清空/删除日志"入口** |
| `ui_e2e.mjs` | （自带） | 注册绑定邮箱 / 忘记密码全流程（**11 项**） |
| `desktop_e2e.py` | （自带） | 桌面端登录 + 截图 + 可选制造篡改并截告警弹窗（`tamper` 步骤需门禁） |
| `desktop_shot.py` | （自带） | 启动桌面端截取窗口真实画面并驱动界面 |
| `ui_faceid_check.py` | （自带，Python 内联 CDP） | 账号页「纯人脸登录」卡片 + 新建账号弹窗固定初始口令 + 登录页「人脸登录」页签（**17 项**）—— headless Edge，不需要装桌面端（见 A5） |

截图统一写入 `tools/evidence/`（可用环境变量 `E2E_SHOTDIR` 覆盖）。
例外：`ui_e2e.mjs` 的输出名由**命令行参数**给定（见 `docs/guides/EMAIL-VERIFY-README.md`），要归入证据目录请先 `cd tools/evidence`。

### D. 数据库管理 / 运维（会写库，保护比通用门禁更严）

| 文件 | 作用 | 保护措施 |
|---|---|---|
| `db_cleanup.py` | 清理冗余信息与日志痕迹 | `--i-know-this-is-the-real-db` **且**备份核对通过 |
| `db_restore.py` | 从 `db_cleanup.py` 生成的备份目录恢复 | `--i-know-this-is-the-real-db` |
| `consolidate_shards.py` | 把散落在分片里的审计记录合并回月度分片并整链重签 | 默认 dry-run，`--apply` 才写 |
| `renumber_chain.py` | 重排序号并重签（清理已删记录的序号空洞） | 默认 dry-run，`--apply` 才写 |
| `repair_chain.py` | 修复审计哈希链 | 默认 dry-run，`--apply` 才写 |

> ⚠️ 这些脚本**不要**往通用门禁上合并 —— 它们比通用规则更严格（含备份核对、dry-run 预览），
> 合并会**削弱**保护。

### E. 只读诊断（不加门禁，加了就失去用途）

| 文件 | 作用 |
|---|---|
| `db_survey.py` | 列出真实库全部集合、文档数、用户与链头等关键内容 |
| `query_tamper_trace.py` | 查询篡改告警痕迹（字段是 camelCase） |
| `git_health_check.py` | Git 仓库体检，**不执行任何写操作** |
| `sod_trace.py` | 职责分离绕过线索的**独立复算**：直连 Mongo 用另一份实现重算归因链（只读，故不加门禁）。`--json` 字段名与 `/api/audit/sod` 一致，`--strict` 有 ATTRIBUTED 时退出码 1 |

### F. 构建 / 打包 / 部署

| 文件 | 作用 |
|---|---|
| `build_all.py` | 编译后端 + 前端（**两套产物**）并只打印关键行 |
| `reinstall_desktop.py` | 卸载旧版 → 静默安装新版 → **md5 核验**产物确实被替换 |
| `deploy_hotswap.py` | 热替换已安装的桌面端前后端，免去重新打安装包 |
| `verify_install.py` | 安装包完整性验证（不启动界面，只查文件） |
| `privacy_scan.py` | **入库前隐私扫描**（GitHub 发布前必跑）。`--gate` 是 CI 门禁：只对 `privacy_baseline.json` 之外的新增命中失败；不加 `--gate` 时永远退出 0（它是给人看的报告） |

### G. 进程与连通性诊断

| 文件 | 作用 |
|---|---|
| `cs_connect_check.py` | 客户端窗口 ←→ 后端 sidecar ←→ MongoDB 连通性 |
| `cs_process_check.py` | C/S 的进程关系与端口绑定 |
| `launch_desktop.py` | 启动桌面端并输出 sidecar 动态端口 |
| `port_watch.py` | 实时验证「桌面壳起来 → sidecar 起来 → 端口在 LISTENING」 |

### H. 一次性诊断（历史遗留，**建议归档**）

| 文件 | 情况 |
|---|---|
| `verify_api.py` | 起后端调 `/api/audit/verify`。功能已被 `transport_func_check.py` 与审计探针覆盖 |
| `diag_api.py` | 起后端拉用户列表与审计统计。与 `verify_api.py` 重叠，无独有能力 |

> 这两个脚本硬编码 `admin/Admin123` 且不接库名门禁 —— 若继续保留，至少要补上门禁；
> 若确认不再使用，建议连同历史一起归档（需先确认无人引用）。

## 目录

| 目录 | 内容 | 是否入库 |
|---|---|---|
| `evidence/` | 运行证据：截图、链快照、库导出 | **整个目录一律不入库**（含真实用户名与本机 UA） |
| `backup/` | 数据库备份 | 不入库（含真实用户数据） |
| `fixtures/` | 人脸动作挑战的录制帧 | 不入库（**真人的脸**，连拍） |
| `buildlogs/` | 最近一次构建/探针的日志 | 不入库 |
| `__pycache__/` | Python 字节码缓存 | 不入库 |

当证据需要随提交一起走时，用 `git add -f` 显式指定单个文件，不要放开目录。

## 发布产物布局（易混淆，记一下）

| 路径 | 说明 |
|---|---|
| `AuthServer/publish/AuthServer.exe` | **正品**：与安装版 `%LOCALAPPDATA%\AuthBaseline\authserver.exe` md5 一致 |
| `AuthServer/bin/Release/net8.0/AuthServer.exe` | 框架依赖构建，md5 与发布版**不同** |
| `AuthServer/bin/Release/net8.0/publish/publish/` | ⚠️ 一次误操作（在 publish 目录里又 publish 了一次）留下的**嵌套垃圾**，可清理 |
| `AuthServer/bin/Debug/` | 陈旧的调试构建 |

## 待办

- [x] 成功转头样本（`left-ok`，10-17 真机录制，46 帧）
- [ ] 仍缺两份真机样本：**动作后不回正**（`FACE_NOT_RETURNED`）、**另一方向 right**（验证左右对称）
- [ ] H 组两个脚本：补门禁或归档（需确认无引用）
- [ ] 未走公共层的活跃脚本逐步收口：`cs_connect_check.py` / `cs_process_check.py` / `run_audit_e2e.py` / `email_e2e_test.py` / `verify_email.py`
- [ ] 截图之外，`buildlogs/` 也应按月份清理（目前无轮转策略）
