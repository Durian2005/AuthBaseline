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
| `lockout_clock_probe.py` | 锁定能否靠拨钟解开、失败计数窗口（3 分钟内 3 次）、未锁定阶段拨钟的留痕与加固后还剩哪些边界（**40 项**） | ✓ | — |
| `ticket_hash_probe.py` | 会话票据哈希化（存储安全 S1）（**27 项**） | ✓ | — |
| `pepper_probe.py` | 口令 pepper + 渐进迁移（存储安全 S2）（**45 项**，最完整的一份） | ✓ | — |
| `dormant_account_probe.py` | 沉睡（僵尸）账号治理（**37 项**）。默认测试库；`--real` 才碰真实库 | ✓ | 需 `--real` |
| `race_storm_test.py` | 并发「写审计」与「完整性校验」风暴的竞态复现/回归 | — | — |
| `password_event_probe.py` | admin 改密失败（弱口令）有没有进审计日志 | — | ✓ 只读 + 只走失败分支 |
| `verify_chain_independent.py` | 独立复算哈希链：用 Python 从零重算，**不依赖后端代码** | — | 只读 |
| `face_second_factor_probe.py` | 人脸第二因子十组：骨架（未录人脸行为不变）/ 两步式录入与挑战绑定 / 口令后只发挑战 / 降级闸门 / 处置（重置 + 注销连带）/ fail-closed 503 / B 组不计次 / A 组计次触发锁定 / 模板密文与审计无特征（**77 项**）。**自带假引擎环境变量，无需摄像头** | ✓ | — |
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
| `face_release_probe.py` | 装机产物校验：① 布局（face-models 5 文件 / exe **非空** / exe 内**未**内嵌 onnx）；② 真引擎（`=cv`）能从目标目录的 `face-models` 加载；③ 把 `face_second_factor_probe.py` 的全部断言打到目标 exe 上（共 **14 项 + 内嵌 77 项**） | ✓ | — |

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

### F. 构建 / 打包 / 部署

| 文件 | 作用 |
|---|---|
| `build_all.py` | 编译后端 + 前端（**两套产物**）并只打印关键行 |
| `reinstall_desktop.py` | 卸载旧版 → 静默安装新版 → **md5 核验**产物确实被替换 |
| `deploy_hotswap.py` | 热替换已安装的桌面端前后端，免去重新打安装包 |
| `verify_install.py` | 安装包完整性验证（不启动界面，只查文件） |
| `privacy_scan.py` | **入库前隐私扫描**（GitHub 发布前必跑） |

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

- [ ] H 组两个脚本：补门禁或归档（需确认无引用）
- [ ] 未走公共层的活跃脚本逐步收口：`cs_connect_check.py` / `cs_process_check.py` / `run_audit_e2e.py` / `email_e2e_test.py` / `verify_email.py`
- [ ] 截图之外，`buildlogs/` 也应按月份清理（目前无轮转策略）
