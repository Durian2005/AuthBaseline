using AuthServer.Services.FaceId;
using Xunit;

namespace AuthServer.Tests;

/// <summary>
/// <see cref="StubFaceIdEngine"/> 的纯逻辑回归 —— 纯人脸登录模块里
/// **不碰摄像头、不碰模型文件**的那一半。
///
/// 为什么这一半值得钉住：
///   · 假引擎是 P2 探针的唯一入口：没有摄像头的机器上，"用户名 → 采集 → 特征 →
///     比对 → 签票 → 审计"整条链能不能走通，全靠它提供的确定性分支。
///     四个行为开关（ok / no_face / low_quality / engine_down）对应四条完全不同的
///     上层路径，这里逐个钉死，探针才能放心依赖它们。
///   · ★ <see cref="StubFaceIdEngine.Derive"/> 曾经直接用
///     `BitConverter.ToSingle` 解释哈希字节 —— 约 0.8% 的字节组会解出 NaN，
///     同身份余弦因此变成 NaN，本人被判 Mismatch。这个 bug 在写本文件时被抓到，
///     派生方案改为"无符号整数 → [-1,1) 均匀映射"。下面两组断言
///     （同身份 = 1.0、跨身份接近正交、全有限）就是防止它退回去的闸门：
///     谁要把派生改回"转 float"，先过来改断言并解释 NaN 怎么办。
///   · <see cref="IFaceIdEngine.Similarity"/> 的数学边界（长度不符、零向量、
///     尺度不变性）同时覆盖真引擎 —— 两个引擎的该方法是逐字相同的，
///     真引擎的单测跑不了（要模型文件），这里测的就是将要发布的那段逻辑。
///
/// 摄像头相关的部分（采集节奏、真实对齐质量、ArcFace 数值正确性）不在这里 ——
/// 那些由 P0 Stage 0 对照实验（tools/faceid_stage0_check.py）与 P1 的帧回放覆盖。
/// </summary>
public class StubFaceIdEngineTests
{
    private static StubFaceIdEngine New(string behavior = "ok", string identity = "dio") =>
        new(new FaceIdOptions
        {
            Engine = "stub",
            StubBehavior = behavior,
            StubIdentity = identity
        });

    /// <summary>
    /// 通过公开路径取一个身份的特征（Feature 内部就是 Derive(StubIdentity)）。
    /// 刻意不走 internal 的 Derive —— 探针将来用的就是这条公开路径，
    /// 测它就够了；也给生产代码少开一扇 InternalsVisibleTo 的门。
    /// </summary>
    private static double[] FeatureOf(string identity)
    {
        var engine = New("ok", identity);
        Assert.Null(engine.TryOpen());          // 不开摄像头就读不到帧（Close 语义见下）
        var frame = engine.ReadFrame();
        Assert.NotNull(frame);
        var box = engine.DetectLargest(frame);
        Assert.NotNull(box);
        var feature = engine.Feature(frame, box);
        Assert.NotNull(feature);
        return feature;
    }

    // ────────────────────────────────────────── 一、ok 主链路

    /// <summary>ok 行为下整条采集链的形状：能开、有帧、有脸、有特征、余弦 1.0。</summary>
    [Fact(DisplayName = "ok 行为：开→帧→脸→特征全链路形状")]
    public void Ok_FullChain_Shape()
    {
        var engine = New("ok");

        Assert.True(engine.Status.Ready);
        Assert.Null(engine.TryOpen());

        var frame = engine.ReadFrame();
        Assert.NotNull(frame);
        Assert.Equal(640, frame.Width);
        Assert.Equal(480, frame.Height);
        // 假引擎没有真实像素，Backing 必须留空 —— 上层谁碰谁犯规。
        Assert.Null(frame.Backing);

        var box = engine.DetectLargest(frame);
        Assert.NotNull(box);
        Assert.Equal(10, box.Points.Length);
        Assert.Equal(0.99, box.Score);
        // 假脸必须完整落在画面里：坐标越界的"脸"会让上层裁图直接抛。
        Assert.InRange(box.X, 0, frame.Width - box.W);
        Assert.InRange(box.Y, 0, frame.Height - box.H);

        var feature = engine.Feature(frame, box);
        Assert.NotNull(feature);
        Assert.Equal(512, feature.Length);
        Assert.All(feature, v => Assert.True(double.IsFinite(v)));

        Assert.Equal(1.0, engine.Similarity(feature, feature), 9);
    }

    /// <summary>Close 之后读不到帧 —— 桌面端"关页面即释放摄像头"依赖这个语义。</summary>
    [Fact(DisplayName = "Close 后读帧返回 null")]
    public void Close_Then_ReadFrame_Null()
    {
        var engine = New("ok");
        Assert.Null(engine.TryOpen());
        Assert.NotNull(engine.ReadFrame());

        engine.Close();
        Assert.Null(engine.ReadFrame());
    }

    // ────────────────────────────────────────── 二、行为开关（探针的四条确定性路径）

    /// <summary>no_face：链路走到"检测"就断 —— 上层应按质量分支处理，而不是认证失败。</summary>
    [Fact(DisplayName = "no_face 行为：检测返回 null，其余环节正常")]
    public void NoFace_DetectReturnsNull()
    {
        var engine = New("no_face");
        Assert.Null(engine.TryOpen());

        var frame = engine.ReadFrame();
        Assert.NotNull(frame);
        Assert.Null(engine.DetectLargest(frame));
    }

    /// <summary>low_quality：检测得到脸但特征提不出来 —— 同样不是"不像"。</summary>
    [Fact(DisplayName = "low_quality 行为：特征返回 null")]
    public void LowQuality_FeatureReturnsNull()
    {
        var engine = New("low_quality");
        Assert.Null(engine.TryOpen());

        var frame = engine.ReadFrame();
        Assert.NotNull(frame);
        var box = engine.DetectLargest(frame);
        Assert.NotNull(box);
        Assert.Null(engine.Feature(frame, box));
    }

    /// <summary>
    /// engine_down：状态不可用、打不开、读不到帧。
    /// ★ 三层都必须断 —— 只断一层会让上层拿着 null 帧继续跑，
    /// 把"引擎不可用"演绎成一次莫名的认证失败。
    /// </summary>
    [Fact(DisplayName = "★ engine_down 行为：状态/打开/读帧三层全断")]
    public void EngineDown_AllThreeLayersBreak()
    {
        var engine = New("engine_down");

        Assert.False(engine.Status.Ready);
        Assert.False(string.IsNullOrWhiteSpace(engine.Status.Message));
        Assert.NotNull(engine.TryOpen());     // 打开必须失败并给出原因
        Assert.Null(engine.ReadFrame());      // 打不开就必然读不到
    }

    // ────────────────────────────────────────── 三、Derive：确定性与"本人/非本人"语义

    /// <summary>
    /// ★ 同一身份两次派生**逐位相同** —— 这是"录入 → 验证余弦 1.0"的前提。
    /// </summary>
    [Fact(DisplayName = "★ Derive 确定性：同身份两次派生逐位相同")]
    public void Derive_SameIdentity_BitwiseStable()
    {
        Assert.True(FeatureOf("dio").SequenceEqual(FeatureOf("dio")));
    }

    /// <summary>
    /// ★ 派生向量必须**全有限**且落在 [-1,1]：这是 NaN 事故的回归闸门
    /// （见文件头 ②：曾经约 0.8% 的坐标是 NaN）。
    /// </summary>
    [Fact(DisplayName = "★ Derive 输出：512 维全有限且值域 [-1,1]")]
    public void Derive_Output_AllFiniteInRange()
    {
        var feature = FeatureOf("dio");
        Assert.Equal(512, feature.Length);
        Assert.All(feature, v =>
        {
            Assert.True(double.IsFinite(v));
            Assert.InRange(v, -1.0, 1.0);
        });
    }

    /// <summary>
    /// ★ 同身份余弦 = 1.0、跨身份接近正交。跨身份这里取 0.2 为上界：
    /// 实测 190 个用户名组合 |cos| 最大 0.12、均值 0.038，0.2 留有充分余量，
    /// 又远低于默认阈值 0.50 与灰区下沿 0.45 —— 假引擎的"非本人"路径
    /// 不会因为派生分布退化而假阳性。
    /// </summary>
    [Fact(DisplayName = "★ Derive 语义：同身份 1.0 / 跨身份接近正交")]
    public void Derive_Semantics_SelfOneCrossOrthogonal()
    {
        var engine = New("ok", "dio");
        var self = FeatureOf("dio");
        Assert.Equal(1.0, engine.Similarity(self, self), 9);

        // 一组固定身份：确定性派生 ⇒ 这些数字永远不变，断言因此不会flaky。
        var others = new[] { "admin", "auditadmin", "user1", "zhangsan", "lisi",
                             "wangwu", "zhaoliu", "aaa", "bbb", "ccc" };
        foreach (var other in others)
        {
            var cos = engine.Similarity(self, FeatureOf(other));
            Assert.True(Math.Abs(cos) < 0.2, $"{other} 与 dio 的余弦 {cos:F4} 超过 0.2");
        }
    }

    // ────────────────────────────────────────── 四、Similarity 数学边界
    // （与 CvFaceIdEngine.Similarity 逐字相同，这里测的是将要发布的那段逻辑）

    /// <summary>长度不符或空向量 ⇒ 0，绝不抛异常（模板 dim 记错时不能炸）。</summary>
    [Fact(DisplayName = "Similarity：长度不符/空向量 ⇒ 0")]
    public void Similarity_MismatchedOrEmpty_Zero()
    {
        var engine = New();
        Assert.Equal(0, engine.Similarity(new[] { 1.0, 2.0 }, new[] { 1.0, 2.0, 3.0 }));
        Assert.Equal(0, engine.Similarity(Array.Empty<double>(), Array.Empty<double>()));
    }

    /// <summary>零向量 ⇒ 0（分母为 0 的守护，返回 0 而不是 NaN/Inf）。</summary>
    [Fact(DisplayName = "Similarity：零向量 ⇒ 0")]
    public void Similarity_ZeroVector_Zero()
    {
        var engine = New();
        Assert.Equal(0, engine.Similarity(new[] { 0.0, 0.0 }, new[] { 1.0, 2.0 }));
        Assert.Equal(0, engine.Similarity(new[] { 0.0, 0.0 }, new[] { 0.0, 0.0 }));
    }

    /// <summary>
    /// 尺度不变：余弦只看方向。特征**不做 L2 归一化**存储，
    /// 所以"同一张脸的两次提取得出不同长度"必须是同一结论。
    /// </summary>
    [Fact(DisplayName = "Similarity：尺度不变")]
    public void Similarity_ScaleInvariant()
    {
        var engine = New();
        var a = new[] { 1.0, 2.0, 3.0 };
        Assert.Equal(1.0, engine.Similarity(a, a.Select(v => v * 7.5).ToArray()), 12);
    }

    /// <summary>正交 ⇒ 0；反向 ⇒ -1 —— 余弦的完整值域 [-1,1] 两端都要成立。</summary>
    [Fact(DisplayName = "Similarity：正交 0 / 反向 -1")]
    public void Similarity_OrthogonalAndOpposite()
    {
        var engine = New();
        Assert.Equal(0, engine.Similarity(new[] { 1.0, 0.0 }, new[] { 0.0, 1.0 }));
        Assert.Equal(-1.0, engine.Similarity(new[] { 1.0, 0.0 }, new[] { -2.0, 0.0 }), 12);
    }
}
