using System.Text.Json;

namespace AuthServer.Services.Face;

/**
 * 动作挑战的**录制 / 回放**子命令（`--face-record` / `--face-replay`）。
 *
 * 为什么这件事值得做成命令，而不是"测试时临时写一段代码"：
 *   动作挑战的判定跑在**真实画面**上 —— 基线怎么求、滑窗几帧算命中、什么算回正、
 *   跳变阈值多大，全都只有在真人的脸上才看得出对错。过去这意味着一件事：
 *   **每次动阈值都得把人叫到摄像头前重看一遍**，而且"刚才到底发生了什么"无法回看，
 *   只能靠一句 `Diagnostic` 字符串猜。
 *
 *   录一次帧、之后反复回放，这段逻辑才算进入回归范围。回放走的是
 *   `CvFaceEngine.RunChallenge` 的**同一段代码**（只把采集源从摄像头换成图片目录），
 *   所以它不是"假引擎放行"，而是真的把 YuNet 检测 + SFace 特征又跑了一遍。
 *
 * 两条必须守住的边界：
 *   ① **只换采集源，不改判定**。任何"回放时特判一下"的写法都会让 fixture 失去意义 ——
 *      测的就不再是产品路径了。
 *   ② **录下来的是真人的脸**。fixture 目录已列入 .gitignore（tools/fixtures/），
 *      绝不允许提交到公开仓库。
 *
 * 用法：
 *   AuthServer.exe --face-record <目录> <left|right>    # 坐在摄像头前按提示做一次动作
 *   AuthServer.exe --face-replay <目录>                 # 离线重放，输出 JSON 结论
 *   python tools/face_fixture_check.py <exe>            # 批量重放并与 manifest 期望值对账
 */

/// <summary>一次录制的元数据。回放时读它拿 action 与期望结论。</summary>
public sealed class FaceFixtureManifest
{
    public string Action { get; set; } = string.Empty;
    public string RecordedAt { get; set; } = string.Empty;
    public int Frames { get; set; }

    /// <summary>录制当时的判定结论 —— 也就是回放要复现的"黄金样本"。</summary>
    public FaceFixtureExpectation Expect { get; set; } = new();

    /// <summary>录制当时的诊断串，出问题时用来对照，不参与判定。</summary>
    public string Diagnostic { get; set; } = string.Empty;

    public string Engine { get; set; } = string.Empty;
    public string Note { get; set; } = string.Empty;
}

/// <summary>期望结论。<see cref="Samples"/> 等计数量在回放里必须一致，否则说明判定节奏变了。</summary>
public sealed class FaceFixtureExpectation
{
    public bool Passed { get; set; }
    public string BusinessCode { get; set; } = string.Empty;
    public int Samples { get; set; }
    public int Misses { get; set; }
    public int Jumps { get; set; }
}

public static class FaceFixtureCli
{
    /// <summary>回放结论在标准输出里的前缀。控制台还有引擎日志，必须给机器一个可定位的锚点。</summary>
    public const string ReplayMarker = "FACE_REPLAY_RESULT=";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        // 落盘用 camelCase（与仓库里其它 JSON —— 审计袋、python 工具 —— 的命名习惯一致），
        // 读回时允许大小写不敏感：manifest 是**人手也可能改**的文件，
        // 因为"多写了个大写 A"就报"缺少 action 字段"是最没必要的坑。
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// 机器读的那一行：**单行紧凑 JSON**。
    /// 用 WriteIndented 的同一份选项会输出多行，而"以标记开头的那一行"才是可解析的锚点 ——
    /// 多行会把自己截断（第一版就踩了这个坑：报"Expecting property name"）。
    /// </summary>
    private static readonly JsonSerializerOptions JsonLineOpts = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        // 刻意**不**用 UnsafeRelaxedJsonEscaping：诊断串里有中文，
        // 而 Windows 控制台把重定向的 stdout 按 GBK 输出，下游按 cp936 解码就成乱码。
        // 让非 ASCII 一律转成 \uXXXX，这一行在任何编码下都读得出同样的内容。
    };

    public static bool IsFixtureCommand(string[] args) =>
        args.Length > 0 && (args[0] == "--face-record" || args[0] == "--face-replay");

    public static int Run(string[] args)
    {
        var isRecord = args[0] == "--face-record";
        if (args.Length < 2)
        {
            Usage();
            return 2;
        }

        var dir = Path.GetFullPath(args[1]);

        return isRecord
            ? Record(dir, args.Length > 2 ? args[2] : string.Empty)
            : Replay(dir);
    }

    private static void Usage()
    {
        Console.Error.WriteLine("用法：");
        Console.Error.WriteLine("  AuthServer.exe --face-record <目录> <left|right>");
        Console.Error.WriteLine("  AuthServer.exe --face-replay <目录>");
    }

    /// <summary>造一份"只用于这次录制"的配置：显式清掉另一种模式的开关，避免环境变量把模式搅混。</summary>
    private static FaceOptions OptionsFor(string recordDir, string replayDir)
    {
        var opt = new FaceOptions();
        opt.ApplyEnvironmentOverrides();
        opt.Engine = "cv";          // 录制/回放只对真实引擎有意义
        opt.RecordDir = recordDir;
        opt.ReplayDir = replayDir;
        return opt;
    }

    private static int Record(string dir, string action)
    {
        if (string.IsNullOrWhiteSpace(action) || !FacePose.Actions.Contains(action))
        {
            Console.Error.WriteLine($"动作必须是 {string.Join(" / ", FacePose.Actions)} 之一，收到：'{action}'");
            return 2;
        }

        // 目录里已有帧就拒绝：接着往里写会把两次录制的帧按文件名混在一起排序，
        // 回放出来是"两段录像首尾相接"的怪东西，而症状只表现为"判定莫名其妙"。
        // 删除用户文件是危险动作，所以这里只拒绝、不清理。
        if (Directory.Exists(dir)
            && Directory.GetFiles(dir).Any(p => Path.GetFileName(p).StartsWith("frame_", StringComparison.Ordinal)))
        {
            Console.Error.WriteLine($"目录里已经有录制帧，请换一个目录或自行清空：{dir}");
            return 2;
        }

        var opt = OptionsFor(recordDir: dir, replayDir: string.Empty);
        using var engine = new CvFaceEngine(opt);
        if (!engine.Status.Ready)
        {
            Console.Error.WriteLine($"人脸引擎不可用：{engine.Status.Message}");
            return 1;
        }

        Console.WriteLine($"开始录制 · 动作 {action} · {FacePose.ActionText(action)}");
        Console.WriteLine($"提示：{FacePose.ActionHint}");

        var outcome = engine.RunChallenge(action);
        var frames = Directory.Exists(dir)
            ? Directory.GetFiles(dir, "frame_*.jpg").Length
            : 0;

        var manifest = new FaceFixtureManifest
        {
            Action = action,
            RecordedAt = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss zzz"),
            Frames = frames,
            Diagnostic = outcome.Diagnostic,
            Engine = $"CvFaceEngine / {EngineVersion()} / {opt.CaptureWidth}x{opt.CaptureHeight}",
            Note = outcome.Passed
                ? "录制成功：回放应复现 passed=true"
                : "录制到了一次失败样例：它同样是有效 fixture（判定的否定结论也要能回归），回放应复现同一 businessCode",
            Expect = new FaceFixtureExpectation
            {
                Passed = outcome.Passed,
                BusinessCode = outcome.BusinessCode,
                Samples = outcome.Samples,
                Misses = outcome.Misses,
                Jumps = outcome.Jumps
            }
        };

        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "manifest.json"), JsonSerializer.Serialize(manifest, JsonOpts));

        Console.WriteLine($"帧数 {frames} · 结论 passed={outcome.Passed} code={outcome.BusinessCode}");
        Console.WriteLine($"诊断：{outcome.Diagnostic}");
        Console.WriteLine($"已写出：{Path.Combine(dir, "manifest.json")}");
        if (frames == 0)
        {
            Console.Error.WriteLine("一帧都没录到 —— 摄像头没打开，或刚开始就失败了。这次录制无效。");
            return 1;
        }
        // 录制到失败样例不算"命令失败"：它照样是一份可回归的 fixture。
        return 0;
    }

    private static int Replay(string dir)
    {
        var manifestPath = Path.Combine(dir, "manifest.json");
        if (!File.Exists(manifestPath))
        {
            Console.Error.WriteLine($"没有 manifest.json，无法回放：{manifestPath}");
            return 2;
        }

        FaceFixtureManifest? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<FaceFixtureManifest>(File.ReadAllText(manifestPath), JsonOpts);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"manifest.json 读不出来：{ex.Message}");
            return 2;
        }
        if (manifest is null || string.IsNullOrWhiteSpace(manifest.Action))
        {
            Console.Error.WriteLine("manifest.json 缺少 action 字段");
            return 2;
        }

        var opt = OptionsFor(recordDir: string.Empty, replayDir: dir);
        using var engine = new CvFaceEngine(opt);
        if (!engine.Status.Ready)
        {
            Console.Error.WriteLine($"人脸引擎不可用：{engine.Status.Message}");
            return 1;
        }

        var outcome = engine.RunChallenge(manifest.Action);

        // 结果单独打一行带前缀的 JSON：上面那些引擎日志是给人看的，机器只认这一行。
        Console.WriteLine(ReplayMarker + JsonSerializer.Serialize(new
        {
            action = manifest.Action,
            passed = outcome.Passed,
            businessCode = outcome.BusinessCode,
            samples = outcome.Samples,
            misses = outcome.Misses,
            jumps = outcome.Jumps,
            diagnostic = outcome.Diagnostic
        }, JsonLineOpts));
        return 0;
    }

    private static string EngineVersion()
    {
        try { return $"OpenCV {OpenCvSharp.Cv2.GetVersionString()}"; }
        catch { return "OpenCV ?"; }
    }
}
