using AuthServer.Services.FaceId;
using Xunit;

namespace AuthServer.Tests;

/// <summary>
/// <see cref="FaceIdOptions"/> 的纯逻辑回归：默认值、环境变量覆盖、路径解析。
///
/// 为什么值得单测：
///   · 环境变量覆盖是**探针依赖**的机制（AUTHBASELINE_FACEID_*）—— 没有摄像头的
///     机器上把 Engine 切成 stub、把行为切成 no_face/low_quality/engine_down，
///     全靠这几行解析。解析错一个字符（大小写、空白、不变文化），探针就会
///     "看起来在测假引擎，其实跑的是真引擎"或者反过来，而且现场极难发现。
///   · 阈值解析刻意走 InvariantCulture：配置文件里写 0.65 与探针设的环境变量
///     必须解释出同一个数。某台机器如果是逗号小数区，这里不能跟着变。
/// </summary>
public class FaceIdOptionsTests
{
    /// <summary>
    /// 默认值即"可用"：缺配置时模块按可用启动，而不是像 pepper/证书那样拒绝启动
    /// （人脸是可选登录方式，拒绝启动等于让没有摄像头的机器把整个认证系统拖下线）。
    /// </summary>
    [Fact(DisplayName = "默认值：按可用启动，阈值 0.30（P3 定档）/ 灰区 0.05 / 模板上限 3")]
    public void Defaults_AreUsable()
    {
        var opt = new FaceIdOptions();

        Assert.True(opt.Enabled);
        Assert.Equal("cv", opt.Engine);
        Assert.Equal(0.30, opt.Threshold);
        Assert.Equal(0.05, opt.GrayBand);
        Assert.Equal(3, opt.MaxTemplates);
        Assert.Equal(0, opt.CameraIndex);
        Assert.Equal(640, opt.CaptureWidth);
        Assert.Equal(480, opt.CaptureHeight);
        Assert.Equal("ok", opt.StubBehavior);
        Assert.Equal(string.Empty, opt.StubIdentity);
        Assert.Equal("face-models/face_detection_yunet_2023mar.onnx", opt.DetectorModel);
        Assert.Equal("face-models/face_recognition_arcface_w600k_r50.onnx", opt.RecognizerModel);
        Assert.False(opt.UseStubEngine);
    }

    /// <summary>UseStubEngine 大小写不敏感；空值与 cv 都走真引擎。</summary>
    [Theory(DisplayName = "UseStubEngine 判定")]
    [InlineData("stub", true)]
    [InlineData("Stub", true)]
    [InlineData("STUB", true)]
    [InlineData("cv", false)]
    [InlineData("", false)]
    public void UseStubEngine_Detection(string engine, bool expected)
    {
        Assert.Equal(expected, new FaceIdOptions { Engine = engine }.UseStubEngine);
    }

    /// <summary>
    /// 绝对路径原样返回、相对路径按 exe 目录落地。
    /// （模型路径含中文时由 CvFaceIdEngine 再镜像一份到 ASCII 目录，不在这里。）
    /// </summary>
    [Fact(DisplayName = "路径解析：绝对原样 / 相对按 BaseDirectory")]
    public void Resolve_RootedPassthrough_RelativeGetsRooted()
    {
        var opt = new FaceIdOptions();
        var rooted = Path.Combine(Path.GetTempPath(), "somewhere", "model.onnx");

        opt.DetectorModel = rooted;
        Assert.Equal(rooted, opt.ResolveDetector());

        opt.DetectorModel = "face-models/face_detection_yunet_2023mar.onnx";
        var resolved = opt.ResolveDetector();
        Assert.StartsWith(AppContext.BaseDirectory, resolved);
        Assert.EndsWith("face_detection_yunet_2023mar.onnx", resolved);
    }

    // ────────────────────────────────────────── 环境变量覆盖

    /// <summary>
    /// 每个环境变量用例都自带 save/restore —— 环境变量是**进程全局**的，
    /// 泄漏出去会悄悄改变同进程里其他测试（以及将来同进程的探针）看到的世界。
    /// </summary>
    private static void WithEnv(string name, string? value, Action<FaceIdOptions> act)
    {
        var previous = Environment.GetEnvironmentVariable(name);
        Environment.SetEnvironmentVariable(name, value);
        try
        {
            var opt = new FaceIdOptions();
            opt.ApplyEnvironmentOverrides();
            act(opt);
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, previous);
        }
    }

    [Theory(DisplayName = "FACEID_ENABLED 覆盖")]
    [InlineData("false", false)]
    [InlineData("0", false)]
    [InlineData("FALSE", false)]
    [InlineData("true", true)]
    [InlineData("1", true)]
    public void Override_Enabled(string raw, bool expected)
    {
        WithEnv("AUTHBASELINE_FACEID_ENABLED", raw, opt => Assert.Equal(expected, opt.Enabled));
    }

    [Fact(DisplayName = "FACEID_ENGINE=stub 覆盖且 UseStubEngine 跟随")]
    public void Override_Engine()
    {
        WithEnv("AUTHBASELINE_FACEID_ENGINE", " stub ", opt =>
        {
            Assert.Equal("stub", opt.Engine);      // 前后空白要trim掉
            Assert.True(opt.UseStubEngine);
        });
    }

    [Fact(DisplayName = "FACEID_THRESHOLD 覆盖：不变文化解析，垃圾值保持默认")]
    public void Override_Threshold()
    {
        WithEnv("AUTHBASELINE_FACEID_THRESHOLD", "0.65", opt => Assert.Equal(0.65, opt.Threshold));
        WithEnv("AUTHBASELINE_FACEID_THRESHOLD", "abc", opt => Assert.Equal(0.30, opt.Threshold));
        WithEnv("AUTHBASELINE_FACEID_THRESHOLD", "   ", opt => Assert.Equal(0.30, opt.Threshold));
    }

    [Fact(DisplayName = "FACEID_GRAYBAND 覆盖")]
    public void Override_GrayBand()
    {
        WithEnv("AUTHBASELINE_FACEID_GRAYBAND", "0.02", opt => Assert.Equal(0.02, opt.GrayBand));
    }

    [Fact(DisplayName = "FACEID_STUB_IDENTITY / BEHAVIOR 覆盖（含 trim）")]
    public void Override_StubFields()
    {
        WithEnv("AUTHBASELINE_FACEID_STUB_IDENTITY", "  alice  ",
            opt => Assert.Equal("alice", opt.StubIdentity));
        WithEnv("AUTHBASELINE_FACEID_STUB_BEHAVIOR", "no_face",
            opt => Assert.Equal("no_face", opt.StubBehavior));
    }

    /// <summary>
    /// 没有任何环境变量时，覆盖是一次**恒等变换** —— 默认值不许被"覆盖逻辑本身"改动。
    /// </summary>
    [Fact(DisplayName = "无环境变量时覆盖为恒等变换")]
    public void NoEnv_OverridesAreIdentity()
    {
        var opt = new FaceIdOptions();
        var before = (opt.Enabled, opt.Engine, opt.Threshold, opt.GrayBand, opt.StubBehavior);
        opt.ApplyEnvironmentOverrides();
        Assert.Equal(before, (opt.Enabled, opt.Engine, opt.Threshold, opt.GrayBand, opt.StubBehavior));
    }
}
