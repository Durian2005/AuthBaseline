# 存储「哈希 + 盐」与传输「TLS」验收步骤

> 面向课程验收的**照着走**清单：左边是要证明的主张，右边是证据与命令，末尾是话术与追问。
> 设计依据：`docs/design/TRANSPORT-STORAGE-SECURITY-DESIGN.md`　·　工具索引：`tools/README.md`
> 所有命令按 **cmd** 写（在 PowerShell 里请改 `set X=Y` → `$env:X='Y'`）。
>
> ⚠️ **本文件已脱敏**（仓库是 public）：原本的本机路径与 Windows 用户名已替换为
> `<系统 Python 的完整路径>` / `<仓库根目录>` 两个占位符。演示前在命令块里**填一次**即可，
> 例如 `set PY=C:\Python313\python.exe` 与 `cd /d <项目目录>\AuthBaseline`。
>
> 文中所有 `%PY%` 都指"**装了 `pymongo` / `bcrypt` 的那个系统 Python**" ——
> 不是 WorkBuddy 自带的托管解释器（它没有这两个包，已实测）。

---

## 零、先记住两条主张

| 层 | 要证明的一句话 | 用的原语 | 关键区别 |
|---|---|---|---|
| **存储** | 库里拿不到口令，只有**哈希**；哈希带**随机盐**，并掺了 **pepper** | bcrypt | 哈希**不可逆**，没有"解密" |
| **传输** | 客户端 → 后端这一跳**真的被 TLS 保护**，且不可静默降级 | TLS 1.3 | 加密**可逆**，但无会话密钥读不了 |

⚠️ 全场最容易翻车的一句话：**别说"存储是加密的"**。
库里是哈希 —— 老师说"那你把哈希解回口令看看"，答不上来就是硬伤。

**两条主张的证据分层**（这张表就是验收的骨架）：

| 主张 | 弱证据（会被追问） | 强证据（本项目实际用） |
|---|---|---|
| 存储 | "代码里调了 bcrypt" | 直连库看字段 + **独立复算** + **证伪（剥标记必失败）** |
| 传输 | "地址是 https 开头" | `Request.IsHttps` + **反向断言（必失败）** + 实际协商版本 |

**「证实」永远不如「证伪」** —— 这是本清单反复用到的同一条方法论。

---

## 一、前置准备（一次性）

| 项 | 检查命令 | 期望 |
|---|---|---|
| MongoDB 在跑 | `netstat -ano \| findstr :27017` | 有 LISTENING |
| 后端产物 | `dir AuthServer\publish\AuthServer.exe` | 存在（21,411,012 字节，与装机版 md5 一致） |
| 本机证书 | `dir "%LOCALAPPDATA%\AuthBaselineData\certs"` | 有 `server.crt`（**信任锚 = CA 公钥**）+ `ca.pfx.dpapi` + `certs.json` |
| 系统 Python | `%PY% -c "import pymongo,bcrypt;print('ok')"` | `ok` |

⚠️ **三条环境铁律**：

1. **探针必须用系统 Python** `%PY%` —— `pymongo` 只装在这一个解释器里。
2. **跑探针必须 `set AUTHBASELINE_REQUIRE_HTTPS=false`** —— 探针的 `start_backend` 硬编码 `http://` 地址（`tools/_probe_common.py:408`），不关掉加密会连不上。
3. **探针一律打测试库**（库名必须含 `Probe`）。探针带库名守卫，误传 `AuthBaselineDb` 会直接抛错拦住（`tools/_probe_common.py:107`）——**这是保护，不是故障**。

```cmd
cd /d <仓库根目录>
set AUTHBASELINE_REQUIRE_HTTPS=false
set PY=<系统 Python 的完整路径>
```

---

## 二、存储层验收（S1 → S6）

### S1 · 库里存的是哈希，不是明文

```cmd
%PY% tools\db_survey.py
```

（或 Compass 打开 `AuthBaselineDb` → `Users` 集合）

**看三样**：

| 看什么 | 期望 | 说明 |
|---|---|---|
| `Users.passwordHash` | `v2$...` 或 `$2a$...` 开头的长串 | **绝不是** `Admin123` 这种原文 |
| `Users` 有没有独立 salt 列 | **没有** | 盐是**内嵌**在 bcrypt 串里的（`$2a$11$` + 22 字符盐 + 31 字符摘要） |
| `Sessions.ticket` | 字段**不存在**，只有 `ticketHash` | 见 S5 |

**讲这句话**：
> 库里存的是口令哈希。注意它**没有单独的盐字段** —— 盐是内嵌在哈希串里的（`$2a$11$` 后面那 22 个字符就是），所以验证时能自动取到，这也是 bcrypt 的自解释设计。

⚠️ **别把"没有 salt 列"说成"漏了盐"**。`Models/User.cs` 里没有 salt 列是**设计**，不是缺陷（`Services/PasswordHasher.cs`）。

---

### S2 · 哈希带**随机盐**（你最想演示的那条）

**思路**：同一个口令算两次，结果不同 ⇒ 一定有随机盐。**不碰数据库、不用起后端、不用 cd 到项目目录** —— 只要有 Python + bcrypt 就能跑。

#### 怎么跑（两个方式，选一个）

**方式 ① 交互式逐行（推荐课堂演示 —— 敲一行、结果当场出来）**

```cmd
%PY%
```

进入 `>>>` 提示符后，逐行粘贴（**每次回车立刻出结果**）：

```python
import bcrypt
h1 = bcrypt.hashpw(b'Admin123', bcrypt.gensalt(rounds=11, prefix=b'2a'))
h2 = bcrypt.hashpw(b'Admin123', bcrypt.gensalt(rounds=11, prefix=b'2a'))
h1.decode()
h2.decode()
h1 == h2
bcrypt.checkpw(b'Admin123', h1)
bcrypt.checkpw(b'Admin123', h2)
h1[:29]        # 可选：把 `$2a$11$` 后面那 22 位盐单独切出来给老师看
```

`>>> '$2a$11$...'` 这种带引号的回显，就是 REPL 在把**表达式的值**打出来（不是 print）。
退出用 `exit()`；想再跑一次按 ↑ 调回上一行。

**方式 ② 一行命令（复制粘贴即可）**

```cmd
%PY% -c "import bcrypt;h1=bcrypt.hashpw(b'Admin123',bcrypt.gensalt(rounds=11,prefix=b'2a'));h2=bcrypt.hashpw(b'Admin123',bcrypt.gensalt(rounds=11,prefix=b'2a'));print(h1.decode());print(h2.decode());print('same?',h1==h2);print('verify1',bcrypt.checkpw(b'Admin123',h1));print('verify2',bcrypt.checkpw(b'Admin123',h2))"
```

⚠️ 上面写的是**全路径**而不是 `%PY%`，这是故意的：`%PY%` 只有在**同一个 cmd 窗口**里先执行过 `set PY=...` 才有效，换个窗口、或误在 PowerShell 里跑，都会原样回显 `%PY%` 而报"找不到命令"。**写全路径永远不错。**

#### 四个必踩的坑

| 坑 | 现象 | 正确做法 |
|---|---|---|
| **用错 Python** | `ModuleNotFoundError: No module named 'bcrypt'` | 必须用 **`%PY%`**（3.13.2，带 bcrypt 5.0.0）。WorkBuddy 自带那个托管 Python **没有** bcrypt（已实测） |
| **在 PowerShell 里跑 `%PY%`** | 原样回显 `%PY%` | `%VAR%` 是 **cmd** 语法。PowerShell 用 `$env:PY`，或直接写全路径 |
| **引号反了** | cmd 把参数吃掉、Python 报语法错 | 外层**双引号**包 `-c` 的内容，里面字符串用**单引号** |
| **省掉 `rounds=11, prefix=b'2a'`** | 得到 `$2b$` 开头 | 这两个参数是**故意与项目对齐**的（`Services/PasswordHasher.cs` 用 `2a`）。省了默认就是 `2b`，跟库里那批对不上，会被追问 |

**期望输出**（真实结果，已跑过）：

| 观察 | 结果 | 说明 |
|---|---|---|
| 两次哈希串 | `$2a$11$ipdeHnlP…` vs `$2a$11$oqlgn8bo…` | ✅ **不同** ⇒ 盐是随机的 |
| `same?` | `False` | 你的方法成立 |
| 两次 `checkpw(原文)` | 都 `True` | 盐不同不影响验证 |

**对照组（把"不同"归因到盐 —— 这才是实验设计的关键）**

单看"两次不同"**不是证据**，它可能来自随机盐，也可能来自算法自带的随机性（随机 IV / 时间戳）。
必须配一组对照来**排除替代解释**：

| 对照 | 命令 | 实测结果 | 排除了什么 |
|---|---|---|---|
| 对照一 · 无盐 SHA-256 | `%PY% -c "import hashlib;s1=hashlib.sha256(b'Admin123').hexdigest();s2=hashlib.sha256(b'Admin123').hexdigest();print(s1);print(s2);print('same?',s1==s2)"` | 两次都是 `3b612c75…`，`same? True` | 证明 SHA-256 是**确定性**的 ⇒ bcrypt 的"不同"不是"算两次必然不同"这种平凡原因 |
| 对照二 · bcrypt + **固定盐** ⭐ | `%PY% -c "import bcrypt;pw=b'Admin123';s=bcrypt.gensalt(rounds=11,prefix=b'2a');h1=bcrypt.hashpw(pw,s);h2=bcrypt.hashpw(pw,s);print(h1.decode());print(h2.decode());print('same?',h1==h2)"` | 两条**逐字相同**（连盐段都一样），`same? True` | **算法不变、只把盐钉死** ⇒ 差异只能归因于盐 |

⚠️ **对照二比对照一更紧**：对照一同时改了两件事（算法 bcrypt → SHA-256 **和** 去盐），严格说不是单变量。
对照二保持 bcrypt 不变、只固定盐 —— **唯一变量就是盐**。两个都讲最好；只讲一个就讲对照二。

⚠️ **对照组不是"验证命令"**：项目里**根本没有"无盐 SHA-256 存口令"这条代码路径**。
它只是实验设计里的**参照系** —— 用来证明"如果没加盐，库里会长什么样"。

**顺带的收获（可以讲）**：无盐时，**两个不同用户只要口令相同，库里的哈希就完全相同** ——
攻击者一眼看出"这两个人同密码"，且彩虹表查一次同时命中所有人。这才是"为什么必须加盐"的直观证据。

**⚠️ 这里有个陷阱，必须提前知道**：
"两次不同"**分辨不出 pepper 在不在**。pepper 是**定值**、不随机 —— 加了 pepper 也两次不同，不加也两次不同（两者实测都是 `不相同`）。
所以 **S2 只能证明"有随机盐"，证明不了"有 pepper"** —— pepper 要靠 S3 的证伪法。

**讲这句话**：
> 同一口令两次哈希不同，说明每条记录有独立随机盐 —— 彩虹表和批量比对因此失效。但要强调：**这一步只证明了盐，证明不了 pepper**，因为 pepper 是定值，不改变"两次是否相同"这个观察。

---

### S3 · pepper 真的参与了运算（**证伪法**，关键一举）

**为什么用证伪**：你没法从哈希串里"看出"有没有掺 pepper（`v2$` 前缀只是自报家门）。
真正的证明是反过来：**假设它没掺 pepper，那裸口令就该验得过 —— 实测验不过，假设被推翻。**

**先把这两条断言找出来看**：用编辑器打开 `tools\pepper_probe.py`、跳到 **258 与 260 行**；想在终端里直接看就用：

```cmd
%PY% -c "L=open(r'tools\pepper_probe.py',encoding='utf-8').read().splitlines();print(L[257]);print(L[259])"
```

⚠️ **别用 `findstr` 搜中文** —— 它是按系统代码页匹配的，而 `.py` 是 UTF-8，实测**一条都搜不到**（切 `chcp 65001` 也一样）。搜中文一律走 Python 读文件，别跟代码页较劲。

正式跑在 S4。这两条断言的原文是：

| 断言 | 位置 | 含义 |
|---|---|---|
| `独立复算：HMAC-SHA256(P1) → bcrypt 命中该哈希（不靠后端自证）` | `:258-259` | 用 Python 从零算，**不信后端自证** |
| `剥掉标记后用裸口令直接验证必须失败（证明 pepper 真的参与了运算）` | `:260-261` | ⭐ **这条才是钉死 pepper 的证据** |

实现分别在 `v2_check()`（`:113`，正确复算）与 `naked_check()`（`:124-125`，剥掉 `v2$` 后用裸口令验证）。

**讲这句话**：
> 我们没法从哈希串里"看出"有没有 pepper，所以我做的是证伪：把 `v2$` 标记剥掉、用原始口令直接验 —— **必须失败**。它要是成功了，才说明 pepper 没参与。实测失败，所以 pepper 确实掺进去了。

---

### S4 · 全套 45 项真机证据（起真后端 + 直连测试库）

```cmd
cd /d <仓库根目录>
set AUTHBASELINE_REQUIRE_HTTPS=false
%PY% tools\pepper_probe.py AuthServer\publish\AuthServer.exe 5232 PepperProbe
```

| 项 | 说明 |
|---|---|
| 参数 | `pepper_probe.py [exe路径] [端口] [测试库名] [--keep]`（`:66-73`） |
| 库 | 默认 `PepperProbe`（守卫保证不碰 `AuthBaselineDb`；会派生 `PepperProbeFresh` / `PepperProbeMig`） |
| 端口 | 默认 5232；和别的探针错开 |
| 断言数 | **45 项**（`tools/README.md:41`） |

**它覆盖的 12 条判据**（脚本 docstring `:1-30` 逐条列了，可当答辩提纲）：

1. 新写入的哈希带 `v2$`（**含启动播种的 admin，没有例外**）
2. `v2$` 构造能被 Python **独立复算**
3. **剥标记 + 裸口令 ⇒ 必须失败**（`H) 证伪`）
4. 旧格式 `$2a$` 账号仍能登录
5. 登录后库里的哈希**自动升级**为 `v2$`（`:284-291`），且升级值可独立复算
6. 该次升级**恰好留 1 条** `PASSWORD_HASH_UPGRADED` 审计，且**审计全文不含口令**（`:294-302`）
7. 再登录不再升级（**幂等**，`:305-306`）
8. 换**错误的 pepper**：正确口令也登不进，且**不把库里的哈希改坏**（`:321-326`）
9. 库里有 `v2$`、本机 pepper 丢失 ⇒ **拒绝启动**（非 0 退出 + 可读原因 + 恢复指引 + **绝不静默生成新 pepper**，`:349-353`）
10. 干净库无 pepper ⇒ 首次初始化成功，落盘是 **DPAPI 密文**不是 32 字节明文（`:371-372`）
11. `--pepper-export` / `--pepper-import` 往返 + 指纹一致（`:390+`）
12. pepper 落盘**一次性搬迁**（老位置在安装目录里，会被 NSIS 卸载扫掉）

⚠️ 这一份是**最完整**的，也是**耗时最长**的（会起停后端多次）。**别安排在演示现场跑**，提前跑好、截图留存。

---

### S5 · 会话票据也是哈希（27 项）

```cmd
%PY% tools\ticket_hash_probe.py AuthServer\publish\AuthServer.exe 5231 TicketHashProbe
```

**要证明的一句话**（脚本 docstring）：*库里再也拿不到"读走就能用"的东西。*

| 断言 | 期望 |
|---|---|
| 登录接口仍返回**明文票据** | 契约未变（客户端拿不到就登不了） |
| `Sessions` 文档里**不存在** ticket 明文字段 | 只有 `ticketHash` |
| `ticketHash` 独立复算一致 | 无盐 SHA-256，Python 自算 |
| **用库里那个哈希值当 Bearer 发回来** | **必须 401** ⭐ |
| 索引是 `uniq_ticket_hash`，老 `uniq_ticket` **必须已删** | 不删会让第二条会话插不进去（null 参与唯一约束） |
| 连续两次登录都成功 | 上一条的回归 |
| 登出后明文票据立刻 401 | 吊销按哈希工作 |

实现：`Services/TicketHasher.cs:33`（**无盐** SHA-256 + Base64Url）。
⚠️ **票据刻意不加盐** —— 它只需不可反推，不需要抗彩虹表（票据是高熵随机值）。被问到要主动解释。

---

### S6 · 存储层收尾（一句话）

> 存储层是**哈希 + 随机盐 + pepper**，三者分工不同：**bcrypt 盐**抗彩虹表与批量比对，**pepper** 抗"整库被拿走"（没有 pepper，库里那批 `v2$` 一个都验不过）。而**票据只哈希不加密** —— 票据不可反推就够了。

⚠️ **库被整体拿走真的没用，只在两处成立**：口令（无 pepper 验不了）与票据（不可反推）。
**用户名 / 邮箱 / 审计元数据在库里是明文的** —— MongoDB 是 `mongodb://localhost:27017` **无凭据**、Community 版**无落盘加密**。这条要**主动说**，别等老师发现。

---

## 三、传输层验收（T1 → T8）

### T1 · 「加密实现」只有一行（先把预期摆正）

```cmd
%PY% -c "print(open('AuthServer/Program.cs',encoding='utf-8').read().splitlines()[68:71])"
```

或直接打开 `AuthServer/Program.cs:69-71`：

```csharp
:69  var leaf = certManager.LeafCertificate;
:70  builder.WebHost.ConfigureKestrel(o =>
:71      o.ConfigureHttpsDefaults(h => h.ServerCertificate = leaf));
```

**这就是仓库里离"加密实现"最近的一行**。此后握手与加解密由 Kestrel → Windows SChannel 完成。

**讲这句话**：
> 加密我们**没有自己实现**，用的是标准 TLS。项目只做三件事：签发本机证书、把它交给 Kestrel、声明走 https。
> 自研报文加密我们**刻意拒绝**了 —— 密钥分发、IV 复用、填充预言这些坑自己写一定出错，而我们已经具备上标准 TLS 的全部条件。

⚠️ 被追问"那加密运算的代码在哪" ⇒ 答：在 .NET 运行时与 Windows 里，**不在项目仓库内** —— 这正是分层设计的意图。

**顺带排雷**：`Services/CertificateManager.cs:313-314,364-365` 里的 `RSA.Create(2048)` 带的是 `RSASignaturePadding.Pkcs1` —— 那是**签名**（给证书签名），**不是加密**。看到 RSA 别顺口答成"加密实现"。

---

### T2 · 拿不到证书就不启动（fail-closed）

打开 `AuthServer/Program.cs:78-84`：

```csharp
:78  catch (CertificateUnavailableException ex) {
:79      ...
:80      // 桌面端 Console 输出留不下来，所以额外写文件
:81      File.WriteAllText(errPath, ...);
:83      return 1;                       // ← 拒绝启动
:84  }
```

**讲这句话**：
> 这里不是"有证书就用、没有就算了" —— 拿不到证书直接**退出码 1 拒绝启动**。因为一条"看起来正常"的明文链路，比启动失败危险得多。

**加分细节（`Program.cs:86-95` 的 else 分支）**：`RequireHttps=false` 时刻意**不去加载证书**。
理由写在 `:90-93`：若此时仍挂证书、实际走 HTTPS，就会出现"状态栏说明文、链路其实加密"—— **比不加密更糟，它会让验收结论失真**。**开关必须名副其实。**

---

### T3 · 界面上那个「加密」徽记，判据是什么

| 字段 | 位置 | 说明 |
|---|---|---|
| **`Request.IsHttps`** | `AuthServer/Controllers/AuthController.cs:43` | **事实的唯一来源** —— 这一跳实际有没有 TLS |
| **`tls`** | `AuthController.cs:53` | `tls = https`，下发给前端 |
| `downgraded` | `AuthController.cs:60` | `RequireHttps && !https` —— 配置要求加密但实际明文 |
| `scheme` / `subject` / `notAfter` / `thumbprint` / `trustStore` | `AuthController.cs:52,55-58` | scheme 只是地址前缀；证书四要素是公钥信息，故接口**刻意不鉴权**（`:33-35`） |

前端消费：`AuthClient/src/components/StatusBar.vue:27-28` 注释写得很直白 ——
*"判据取后端返回的 `tls`，而不是'地址开头是不是 https' —— 后者只说明我们**打算**加密。"*
实际渲染在 `StatusBar.vue:38`（`label: tls ? '加密' : '明文'`）。

⚠️ **这段是"把事实说出来"，不是"加密实现"** —— 段内一行 TLS 调用都没有。
**别把它当论据**，它是收尾。而且它有个硬伤：`Request.IsHttps` 是**后端自己说的**，老师一句"我怎么知道它不是永远返回 true"就能把你绕进去。
⇒ 必须配 **T4/T5 的外部证据**。

**讲这句话**：
> 注意这个判据是 `Request.IsHttps` —— **实际请求**是不是 HTTPS，而不是我配置里写了什么。配置说"我要加密"和执行结果是两件事，所以我特意加了 `downgraded` 字段：只要配置要求加密、而实际是明文，界面就必须显眼地报出来，而不是静静显示"明文"糊弄过去。

---

### T4 · curl 实测（30 秒，含**端口怎么取**）

**端口是动态的** —— `src-tauri/src/lib.rs:75-79` 的 `TcpListener::bind("127.0.0.1:0")` 让操作系统每次挑一个空闲端口（Windows 动态区间，通常 49152–65535）。
⚠️ **界面不显示端口**（`StatusBar.vue:51` 只到 `https://127.0.0.1`），桌面端也没有地址栏 ⇒ 必须从外部问出来。
⚠️ **别填 `5173`** —— 那是 Vite **开发**端口，与装出来的桌面版无关。

**取端口的三种办法**：

| 办法 | 命令 | 适用 |
|---|---|---|
| ① 脚本直接打印 | `%PY% tools\launch_desktop.py` → 末行 `PORT=xxxxx` | **首选**，自带就绪等待 |
| ② 手查监听进程 | `netstat -ano \| findstr LISTENING \| findstr 127.0.0.1` + `tasklist /FI "IMAGENAME eq authserver.exe"` 对 PID | 软件已在跑 |
| ③ **自己起后端、端口自己定** ⭐ | `cd /d "%LOCALAPPDATA%\AuthBaseline"` 然后 `authserver.exe --urls https://127.0.0.1:5443` | 演示最省事，命令可提前写好 |

**办法 ③ 之后（推荐用于现场演示）：**

```cmd
curl --cacert "%LOCALAPPDATA%\AuthBaselineData\certs\server.crt" https://127.0.0.1:5443/api/auth/transport
```

**期望**：终端里直接出现 `"scheme":"https"` 与 `"tls":true`，以及 `"downgraded":false`。

⚠️ 三个坑：

1. **必须带 `--cacert`（不要用 `-k`）** —— 带信任锚才证明"证书链**真的在验**"；`-k` 等于把 TLS 变成装饰。
   `server.crt` 是 **CA 公钥**（信任锚），不是 leaf。
2. **协议必须是 `https://`** —— 用 `http` 打 https 端口只会得到"连接被重置"，看着像后端没起来（`tools/_probe_common.py:76-81` 专门记过这个误判）。
3. 办法 ③ 会读**真实库** `AuthBaselineDb`，但 `GET /api/auth/transport` 是**只读**接口（`AuthController.cs:37`）—— 安全。

---

### T5 · TLS 断言 A–E（证明加密**不是装饰**）

```cmd
%PY% tools\transport_tls_probe.py https://127.0.0.1:5443 "%LOCALAPPDATA%\AuthBaselineData\certs\server.crt"
```

| 段 | 断言 | 期望 | 证明了什么 |
|---|---|---|---|
| **A** | https + 固定信任锚(`server.crt`) | 200 且 `tls=true` | "能通" |
| **B** | https + **空信任锚** | **必须失败** ⭐ | **"真在验链"**，不是装饰 |
| **C** | **明文 http** 打同一端口 | **必须失败** ⭐ | **没有静默降级** |
| **D** | 打印实际协商的 TLS 版本与密码套件 | `TLSv1.3` / `TLS_AES_256_GCM_SHA384` | 不是"看起来像 TLS" |
| **E** | 系统信任存储判定 | 必须通过 | WebView2/Schannel 会接受（界面能渲染的前提） |

⚠️ **B 段为什么用"空信任锚"而不是"默认上下文"**（脚本头部有解释）：CA 一旦写进系统根存储（生产路径就是这么做的），`ssl.create_default_context()` 会把我们的 CA 也读进来 —— 那时"不带 cacert 必须失败"就不成立、B 会**假阳性**。所以 B 必须用一张 CA 都不加载的上下文。

**讲这句话**：
> 只有"必须失败"的测试才证明 TLS 不是装饰。所以我不只测"能连上"，还测两条**反的**：清空信任锚必须失败、明文 http 打同一端口必须失败。

---

### T6 · 加密之后业务是否仍然全通（9 项）

```cmd
%PY% tools\transport_func_check.py            :: 自动从运行中的 authserver.exe 反查端口
%PY% tools\transport_func_check.py 5443       :: 或手工指定
```

断言（脚本 docstring）：① 协议必须是 https（用**系统根存储**校验，即 Schannel/WebView2 同一判定路径）② `/api/auth/transport` 必须 `tls=true` ③ 登录 + 票据访问受保护接口正常 ④ 未授权访问被拒。退出码 0 = 全通过。

**这就是"加密没把功能搞坏"的那一页 PPT。**

---

### T7 · 界面级证据（10 项 + 截图）

```cmd
%PY% tools\ui_tls_check.py
```

它自己起桌面端（带 WebView2 CDP 调试端口 9333）→ 跑断言 → 收尾，**必须同进程**（沙箱里调用方退出会回收 GUI 子进程）。
默认凭据 `admin` / `Admin123`（README 公开的演示种子口令），可用 `E2E_USER` / `E2E_PASS` 覆盖。

**产出截图**（写入 `tools/evidence/`，可用 `E2E_SHOTDIR` 覆盖）：

| 文件 | 内容 |
|---|---|
| `tls_01_login_encrypted.png` | 登录页 + 状态栏「加密」徽记 |
| `tls_02_after_login.png` | 登录后 |

判断体 `tools/ui_tls_events.mjs` 里有关键两条：`check('后端自述 tls=true 且 scheme=https')`、`check('状态栏出现「加密」徽记')`。

**这两张图直接贴进答辩 PPT** —— 比现场截图稳（不会因为手抖或端口没起来翻车）。

---

### T8 · 「看 Network」这一步 —— ⚠️ F12 在桌面端**不可用**

**Tauri 生产版默认禁用开发者工具**：`tauri.conf.json` 无 devtools 配置、`lib.rs` 无 `open_devtools` 调用 ⇒ NSIS 装出来的 release 版里按 **F12 毫无反应**。**别把这个当演示步骤**，现场按下去没反应会很难堪。

**替代路径 A（最接近原意）：用 Edge 打开后端地址**。后端从 `wwwroot` 同源提供页面，所以浏览器打开后端地址看到的就是同一套界面，而 **Edge 的 F12 功能完整**：

```cmd
:: 方式一：桌面端已经在跑 —— 先把端口问出来
%PY% tools\launch_desktop.py     :: 末行 PORT=xxxx

:: 方式二：自己起后端、端口自己定（推荐 —— 命令可提前写进讲稿）
cd /d "%LOCALAPPDATA%\AuthBaseline"
authserver.exe --urls https://127.0.0.1:5443
:: 另开一个 cmd 窗口：
start msedge https://127.0.0.1:5443/
```

**本机实测确认（2026-10-13）**：

| 项 | 实测值 |
|---|---|
| `GET /` | HTTP 200、`text/html`、494 字节（只是壳，真界面由 `/assets/` 的 JS 渲染）⇒ **浏览器打开就是完整界面** |
| `GET /api/auth/transport` | `tls:true`、`scheme:https`、`subject:"CN=127.0.0.1"`、`trustStore:"CurrentUser"`、`downgraded:false` |
| **CA 位置** | `Cert:\CurrentUser\Root` —— `CN=AuthBaseline Local CA`，指纹 `D96339BC…`，有效期至 **2031-10-02** |
| 叶子证书 | `CurrentUser\My` —— `CN=127.0.0.1`，由上面那张 CA 签发，指纹 `CAE1356A…`，有效期至 **2027-10-02** |
| ⇒ **Edge 不会弹证书警告** | CA 已在**当前用户**根存储，而 Edge 走的正是这个信任存储（`LocalMachine\Root` 里**没有**，不影响） |

**Edge 的 Security 面板会显示**：颁发给 `CN=127.0.0.1` · 颁发者 `CN=AuthBaseline Local CA` · 有效期至 2027/10/2。
这三点正好与 `transport` 接口返回的 `subject` / `notAfter` / `thumbprint` **逐项对得上** —— 这本身就是一条交叉验证（接口说的和我浏览器看到的必须一致）。

**不用浏览器也能先自证这条路通**（会起后端、只发 GET、跑完自动收尾）：

```cmd
%PY% .workbuddy\tmp\t8_verify.py
```

到 Network 面板，**重点看三处**（别只停在 Network）：

| 看哪里 | 看什么 |
|---|---|
| Protocol 列 | `h2` / `h3`，且 URL 是 `https://` |
| `login` 请求 → Headers → General | `Request URL = https://127.0.0.1:xxxxx/api/auth/login` |
| **安全性（Security）工具** ⭐ | "此连接安全" + **完整证书链**（CA → leaf）+ **连接信息（协议/密钥交换/加密套件）** |

**第 3 处是全场最有说服力的一屏** —— 它直接给出证书链和实际协商到的 TLS 参数，比 Network 里那个小锁图标有分量得多。

⚠️ **但"安全性"不是 Network 里请求详情的标签页，路径和直觉不一样**（本机 Edge 155 实测）：

| 情况 | 怎么找 |
|---|---|
| 顶部标签只到"性能"、旁边有个 `»` | 点 **`»`（溢出菜单）** → 选 **"安全性"** |
| `»` 里也没有 | 点右上角 **`⋮` → 更多工具 → 安全性** |
| 更省事、任何版本都有 | **直接点地址栏左边的图标** → 弹窗里点"证书有效 / 连接已安全" → 打开**证书查看器** → 切到 **"证书路径"** 标签 ⇒ 看到两级链 |

**Security 工具里点"主源"后能看到**（`docs` 官方说明）：**连接** 区块（协议 = 协商到的 TLS 版本、密钥交换、服务器签名、加密套件）+ **证书** 区块，还有"打开完整证书详情"按钮。

⚠️ 如果现场找不到这个面板，就用终端兜底 —— `transport_tls_probe.py` 的 D 段直接打印 TLS 版本与加密套件，比翻界面稳。

**⚠️ 必答追问（不准备就会翻车）**：Network 里 `POST /api/auth/login` 的 **Payload 是明文 JSON**：

```
{"username":"admin","password":"..."}
```

老师一定会看到并问"你不是说加密了吗？"

> **标准答案**：F12 看的是**应用层** —— 浏览器展示的本来就是解密之后的内容。TLS 加密发生在更下面的传输层，数据离开浏览器之前就已经变成密文了，浏览器自己能看到明文是理所当然的。**要看密文必须抓包**，F12 永远看不到密文。

**这句话主动先说，效果远好于被问。** 说成"F12 里能看到加密后的口令"就是硬伤。

---

### T9 · 可选但杀伤力最大的一步：把开关拨到明文

```cmd
set AUTHBASELINE_REQUIRE_HTTPS=false
"%LOCALAPPDATA%\AuthBaseline\auth-baseline-desktop.exe"
```

`resolve_scheme()`（`src-tauri/src/lib.rs:45-71`）会读这个环境变量、退回 `http`。

**期望现象**：状态栏**红色常驻**报明文（`StatusBar.vue:43` 那句"口令与票据在链路上可被本机其他进程读取"），`downgraded` 为 `true`。
⇒ 证明这套机制是**活的**，不是摆设。

**这也是必答追问的答案之一**："把 `RequireHttps` 改成 false 呢？" ⇒ 会变明文，**而且界面会显眼地报出来**。这是**刻意留的对照实验开关**（`Program.cs:88-105`），不是漏洞。**主动说，别等问。**

---

## 四、追问与红线口径

### 4.1 三个"别说错"

| ❌ 别说 | ✅ 应该说 | 为什么 |
|---|---|---|
| "存储是加密的" | "口令以 **bcrypt 哈希 + 随机盐 + pepper** 存储" | 哈希**不可逆**，没有"解密"这一步 |
| "口令加密传输" | "口令**在 TLS 信道里**传输" | 表单里是明文，出网卡前才被加密，到后端又是明文 |
| "我实现了加密" | "我**接上了标准 TLS**" | 加密代码不在仓库里 —— 这是**加分项** |
| "审计链不可篡改" | "局部增删改会留下**无法局部修补的断点**，可独立复算验证" | 那是**无密钥 SHA-256 链**（非 HMAC） |

### 4.2 必答追问速查

| 追问 | 标准答案 |
|---|---|
| "哈希能还原成口令吗？" | **不能**。系统里只做 `checkpw` 比对，**不存在任何把哈希还原成口令的代码路径**。 |
| "那你为什么不用固定盐？" | 盐固化 ≈ 无盐，彩虹表照样用。bcrypt 的盐是**每条记录独立随机**，且内嵌在串里所以验证时能自动取到。 |
| "pepper 和盐有什么区别？" | 盐**随机且公开**（在串里），抗彩虹表；pepper**定值且保密**（DPAPI 落盘），抗"整库被拿走"。 |
| "pepper 丢了会怎样？" | 该机**全部口令不可验证**（是"锁死"不是"泄露"）。库里有 `v2$` 而本机读不到 pepper ⇒ **拒绝启动**，绝不静默生成新的。 |
| "挂上证书就等于加密了吗？" | **不等于**。`ServerCertificate` 只解决"出示哪张证书"；加密是握手后 Kestrel 用协商密钥做的。 |
| "怎么证明 `tls` 字段可信？" | 它取自 `Request.IsHttps`，由 Kestrel 的 TLS 终止决定，**不是应用层赋值**。要外部核实就抓包 / 跑 T5 探针。 |
| "加密防得住本机攻击者吗？" | **防不住**，也不打算防。口径见 `CertificateManager.cs:95-98`：防的是**链路上的窃听者** —— 能读 `CurrentUser` 存储或改本机根存储的进程本就有管理员级能力。所以是「**把最廉价的窃听路径堵死**」，不是「链路绝对安全」。 |
| "库里数据被拿走了怎么办？" | 口令与票据拿不走（无 pepper 验不过 / 不可反推）；但**用户名、邮箱、审计元数据是明文**，MongoDB 无凭据、无落盘加密 —— 这条是**已知局限**，写在设计文档 §1.2。 |

### 4.3 现场演示推荐顺序（五步，别跳步）

1. 打开软件 → 状态栏「加密」徽记 → **悬停**看到证书主题 / 到期日 / 信任存储
2. （可选）把开关拨成 `false` 重启 → 红色常驻报明文 → 证明机制是活的
3. 打开 `Program.cs:69-71` → "挂证书就这一行"；`Program.cs:78-84` → "拿不到就不启动"
4. 打开 `AuthController.cs:37-63` → "怎么把事实告诉用户"（**收尾**，不放前面）
5. Edge 打开 → F12 → 点地址栏锁图标看**证书路径**（或 DevTools `»` → 安全性）→ 主动解释 Payload 明文

---

## 五、命令速查卡

```cmd
:: ===== 环境（每条新开的 cmd 都要来一次）=====
cd /d <仓库根目录>
set AUTHBASELINE_REQUIRE_HTTPS=false
set PY=<系统 Python 的完整路径>

:: ===== 存储层 =====
%PY% tools\db_survey.py                                               :: S1 只读看库
%PY% tools\pepper_probe.py AuthServer\publish\AuthServer.exe 5232 PepperProbe   :: S4 45 项
%PY% tools\ticket_hash_probe.py AuthServer\publish\AuthServer.exe 5231 TicketHashProbe  :: S5 27 项

:: ===== 传输层 =====
%PY% tools\launch_desktop.py                                          :: 取端口（末行 PORT=xxxx）
%PY% tools\transport_tls_probe.py https://127.0.0.1:5443 "%LOCALAPPDATA%\AuthBaselineData\certs\server.crt"   :: T5 A–E
%PY% tools\transport_func_check.py                                    :: T6 业务回归
%PY% tools\ui_tls_check.py                                            :: T7 界面 + 截图
curl --cacert "%LOCALAPPDATA%\AuthBaselineData\certs\server.crt" https://127.0.0.1:5443/api/auth/transport   :: T4

:: ===== 用固定端口自己起后端（T4/T5 最省事）=====
set AUTHBASELINE_REQUIRE_HTTPS=true
cd /d "%LOCALAPPDATA%\AuthBaseline"
authserver.exe --urls https://127.0.0.1:5443
```

**证据留存**：截图统一进 `tools\evidence\`（**整个目录不入库**，含真实用户名与本机 UA；要随提交走就 `git add -f` 指定单个文件）。
