# FaceId P1a · 录入闸门与模板存储 交付报告

> 范围：`AuthServer/Services/FaceId/` 的**录入链路**（P1a，全程不需要摄像头）。
> P1b（PAD 反欺骗 + CLIP 真人判定 + 真机阈值标定）尚未开始，见文末「待办」。
> 上一阶段：`docs/reports/FACEID-P0-BASELINE-REPORT.md`（引擎层与公开基准）。

## 一、结论速览

| 项 | 结果 |
|---|---|
| 录入接口 | `GET /api/faceid/status`、`POST /api/faceid/enroll`、`POST /api/faceid/delete` |
| 模板存储 | 独立集合 `FaceIdTemplates`，AES-256-GCM，**密钥与 2FA 分开**（`faceid.key`） |
| 质量闸门 | 单脸 / 最小尺寸 / 正脸度 / 清晰度，**纯函数**，阈值可配置 |
| 模型绑定 | 模板记 `modelId`（含权重 sha256 前 16 位），换模型 ⇒ 旧模板**作废**而非误比 |
| 每人上限 | **3 张**（2FA 是 8 张；本模块是唯一登录因子，上限是安全参数） |
| 单测 | **195/195**（基线 127 + 新增 68） |
| 接口探针 | **56/56**（`tools/faceid_enroll_probe.py`，假引擎 + 独立测试库） |
| 引擎回归 | Stage 0 复跑 **58/58，min(cos)=1.000000**（检测循环重构未改数值） |
| 界面自验 | **7/7** + 截图 `tools/evidence/faceid_p1_account_ui.png` |

## 二、交付清单

| 文件 | 作用 |
|---|---|
| `Models/FaceIdTemplate.cs` | 模板文档（密文 / nonce / tag / dim / **modelId** / createdAt） |
| `Models/FaceIdDtos.cs` | 状态与口令二次确认的 DTO（**不含任何画面或特征字段**） |
| `Services/FaceId/FaceIdTemplateCrypto.cs` | AES-256-GCM；密钥 `%LOCALAPPDATA%\AuthBaselineData\faceid.key`（DPAPI） |
| `Services/FaceId/FaceIdTemplateStore.cs` | 存取、模型过滤、上限淘汰、按用户名清理（实现 `IUserDataPurger`） |
| `Services/FaceId/FaceIdModelIdentity.cs` | 模型身份 = 引擎类型 + 权重文件名 + sha256 前 16 位 + 维度 |
| `Services/FaceId/FaceIdQuality.cs` | 质量闸门纯函数 + 正脸度/滚转估算 |
| `Services/FaceId/FaceIdCodes.cs` | 业务码 ↔ 审计码映射、计次规则、话术 |
| `Services/FaceId/FaceIdEnrollService.cs` | 采集编排：开摄像头 → 采一小段 → 闸门 → 特征 → 写模板 |
| `Services/IUserDataPurger.cs` | 注销时的模块自清入口（账号域不认识具体模块） |
| `Controllers/FaceIdController.cs` | 三条自助接口（票据 + 二次口令） |
| `AuthServer.Tests/FaceIdQualityTests.cs` / `FaceIdCodesTests.cs` | 68 项纯逻辑回归 |
| `tools/faceid_enroll_probe.py` / `tools/ui_faceid_check.py` | 接口回归 / 界面截图自验 |

配套改动：`IFaceIdEngine` 增加 `DetectAll` / `Sharpness`（两个引擎各自实现）；
`MongoDbService` 注册集合与索引；`Program.cs` 接线；`UserAdminController` 注销时遍历
`IUserDataPurger`；`BusinessCodes.cs` / `AuditLog.cs` 新增 `FACEID_*` 两套码。

## 三、关键设计决策

| 决定 | 理由 | 代价（必须承认） |
|---|---|---|
| 与 2FA **零共用**：独立集合 / 独立密钥 / 独立码 / 独立控制器 | 删掉任一模块不影响另一个；一把密钥损坏只降级一条链路 | 约 300 行"重复"代码 |
| 录入**单步**（不做 2FA 那样的挑战两步式） | 本模块没有活体动作，没有需要协商的内容；多一张 token 只多一处过期逻辑 | 用户点下按钮后需正对镜头约 1 秒，文案必须说清 |
| 采集一小段（默认 15 帧）取**第一张过闸门**的帧 | 一帧定生死会让首次录入失败率高得离谱；逐帧打分则要多次前向，低配机很慢 | 不追求"最优帧"，但"可用"已被闸门保证 |
| 闸门顺序：没人脸 → **多脸** → 太小 → 侧脸 → 糊 | 多脸涉及"存进去的是谁"，属于隐私风险，优先于可用性问题 | 多脸时不会顺带提示"离远/离近" |
| 清晰度**测不出来就跳过**（返回 null） | 假引擎没有像素；把"测不了"当"不合格"会让 stub 永远录不进去 | 假引擎下"糊"这条判据不被覆盖（由 `behavior=blurry` 单独覆盖） |
| 录入失败**不计次**，只有二次口令错计次 | 录入发生在已登录之后，一次录不上没有安全含义；口令错是对口令的在线猜测 | 与 2FA 的 A 组划分不同（那边登录路径上宁可多计） |
| 上限 3 张，超出淘汰最旧 | 纯人脸是**唯一**因子，模板数直接乘在 FAR 上 | 极端光照变化下误拒率略高于 8 张 |
| 模板绑 `modelId`，不符即作废；再录时顺手清掉旧模型模板 | 不同特征空间的余弦是"合法但无意义"的数字，静默误比最难归因 | 换权重后用户必须重录一次（状态接口会明确告知） |

## 四、质量闸门（阈值均为**起点**，真机标定属 P1b）

| 判据 | 默认阈值 | 说明 |
|---|---|---|
| 单脸 | 脸数 == 1 | 多一张脸 ⇒ 拒绝（无法确认存的是谁） |
| 最小尺寸 | 脸宽 / 帧宽 ≥ 0.12 | 640 宽约 77 px |
| 正脸度（偏航） | \|鼻尖水平偏移 / 双眼间距\| ≤ 0.35 | 约左右转头 30° |
| 滚转（歪头） | \|双眼 dy\| / \|dx\| ≤ 0.30 | 约 17° |
| 清晰度 | 脸框内灰度拉普拉斯方差 ≥ 60 | 只在能测时生效 |

边界语义一律"含"（= 放行），与 `FaceIdDecision` 的取向一致：误差落在用户一侧时，
宁可多让用户重试一次，也不要把一次正常录入判死。所有几何量出现 NaN ⇒ fail closed。

## 五、验证方法与证据

1. **单测**：`dotnet test` → 195/195。新增覆盖闸门每条边界、NaN/退化输入、
   "清晰度不可测 ⇒ 跳过"、码映射、计次规则、模型身份。
2. **接口探针**：`python tools/faceid_enroll_probe.py <Debug exe> 5391` → 56/56。
   逐条验证：无票据 401、空/错口令（错口令 `failedAttempts=1`）、
   五种质量拒绝路径（**模板数不变 + 不计次 + 审计原因码正确**）、
   密文长度 2048（512×4）/ nonce 12 / tag 16、审计 request/response 无长数组、
   上限 2 时连录 3 次只剩 2、改 `modelId` 后 `usableCount=0`、再录 `purgedForeign=2`、
   删除需口令、注销后 `FaceIdTemplates` 无残留。
3. **引擎回归**：`faceid_stage0_check.py` → 58/58，min(cos)=1.000000。
   这一步是**检测循环重构（DetectAll 抽取）**的安全网：数值一位都没变。
4. **界面**：`ui_faceid_check.py` → 7/7，截图见 `tools/evidence/faceid_p1_account_ui.png`
   （账号页同时存在「刷脸登录（可选）」与「纯人脸登录（独立登录方式）」两张卡）。

## 六、口径（答辩/报告里不许说满的地方）

- 模板是**可逆加密**（AES-GCM），不是哈希。防的是"库文件被拿走"，
  **不防**"进程被注入 / 调试器附加"。不许写成"人脸也不可逆"。
- 本模块**没有活体检测**：一张照片（在摄像头前）目前可以录入与登录。
  这正是 P1b（PAD）要解决的问题；在此之前"纯人脸登录"只能当研究/演示功能。
- 模型身份只证明"权重或引擎种类变了"，**不证明**新模型一定更好；阈值 0.50 仍是起点。
- 上限 3 张、闸门四个阈值都是**安全/体验折中的起点**，不是标定结论。

## 七、待办（P1b 与收尾）

1. **P1b**：MiniFASNetV2 反欺骗（阈值需真机样本校准）、CLIP 零样本真人判定（选型待拍板）。
2. **真机标定**：用 `_static` 12 帧 + 新录样本量一遍清晰度/偏航分布，再定闸门阈值。
3. **界面验收**：需用户过一眼（`FaceIdPanel.vue`）。
4. **管理员 `reset-face` 目前只清 2FA 模板**，不清 FaceId；是否合并为"重置全部人脸"待定
   （合并会改变既有审计语义，需单独评估）。
5. **发布链**：`publish:backend → sync:sidecar → tauri build` 后，用装机产物复跑
   `faceid_enroll_probe.py`（Debug 探针覆盖不到 Publish/NSIS）。
6. **提交**：P0 与 P1a 改动目前都在工作区未提交，需按约定分批提交（推送前须用户同意）。
