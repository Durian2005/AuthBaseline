using AuthServer.Services.FaceId;
using Xunit;

namespace AuthServer.Tests;

/// <summary>
/// <see cref="FaceIdDecision"/> 的纯逻辑回归 —— "相似度 → 三途结论"的边界。
///
/// 为什么这几行判断值得一个独立文件加一组单测：
///   · 阈值（P3 定档为 0.30，通过线本身）与灰区半宽（0.05）是两个旋钮，它们切在哪里
///     直接决定"谁被签票、谁被计失败、谁被引导去输口令"。把边界交给
///     "起一次服务打一次接口"来验证，等于永远不验证。
///   · 边上的样本归哪边有明确的代价不对称：误拒真人是计一次失败（离锁窗更近），
///     误留灰区只是多输一次口令。所以两个边界都取"含"，且只有**明确低于**
///     阈值一个灰区宽度才计 Mismatch。这个取向必须由断言固定，而不是口头约定。
///   · P3 把语义正名为"阈值 = 通过线"（旧写法要 thr+band 才放行）。下面所有
///     边界值都按新语义写：灰区是 [thr-band, thr)，不再跨过阈值本身。
///   · NaN 与负灰区是两个"配置/数据出错时的行为"：一个必须 fail closed，
///     一个必须**不能**因为边界交叉而变成 fail-open。
/// </summary>
public class FaceIdDecisionTests
{
    // ────────────────────────────────────────── 一、定档档位下的三途边界（0.30 / 灰区 0.05）

    /// <summary>
    /// ★ 三条边的精确位置。真实帧的相似度几乎不可能恰好压线，
    /// 所以只有单测能钉住"判定式是 &gt;= 还是 &gt;" —— 而那就是
    /// "恰好 0.30 的样本是直接登录还是被请去输口令"的区别。
    /// </summary>
    [Theory(DisplayName = "★ 三途边界（阈值 0.30 · 灰区 [0.25, 0.30)）")]
    [InlineData(1.00, FaceIdVerdict.Pass)]        // 明确上方
    [InlineData(0.31, FaceIdVerdict.Pass)]
    [InlineData(0.30, FaceIdVerdict.Pass)]        // ★ 阈值本身就算通过（阈值 = 通过线）
    [InlineData(0.2999, FaceIdVerdict.GrayZone)]  // 差一丝就落到灰区
    [InlineData(0.27, FaceIdVerdict.GrayZone)]
    [InlineData(0.25, FaceIdVerdict.GrayZone)]    // 下边含：恰好 thr-band 仍不算失败
    [InlineData(0.2499, FaceIdVerdict.Mismatch)]  // 只有明确低于才计失败
    [InlineData(0.00, FaceIdVerdict.Mismatch)]
    [InlineData(-1.00, FaceIdVerdict.Mismatch)]   // 余弦下界
    public void Classify_DefaultBand(double similarity, FaceIdVerdict expected)
    {
        Assert.Equal(expected, FaceIdDecision.Classify(similarity, 0.30, 0.05));
    }

    /// <summary>灰区半宽为 0 时退化成普通阈值判定：上边含、下边不含、不产生灰区。</summary>
    [Theory(DisplayName = "灰区为 0 ⇒ 纯阈值判定")]
    [InlineData(0.30, FaceIdVerdict.Pass)]
    [InlineData(0.2999, FaceIdVerdict.Mismatch)]
    [InlineData(0.90, FaceIdVerdict.Pass)]
    [InlineData(0.10, FaceIdVerdict.Mismatch)]
    public void Classify_ZeroBand(double similarity, FaceIdVerdict expected)
    {
        Assert.Equal(expected, FaceIdDecision.Classify(similarity, 0.30, 0.0));
    }

    // ────────────────────────────────────────── 二、异常输入的行为

    /// <summary>
    /// ★ 负灰区是配置错误。新语义（阈值 = 通过线）下 Pass 只看 `sim >= thr`，
    /// 负灰区本身已经不可能把低分样本放进 Pass；但仍要归一到 0，
    /// 让灰区下沿不会跑到阈值上方去 —— 否则"低于阈值反而进灰区"这种
    /// 自相矛盾的区间会出现，调档时又会算错一档。
    /// </summary>
    [Fact(DisplayName = "★ 负灰区不得变成 fail-open")]
    public void Classify_NegativeBand_NeverFailsOpen()
    {
        Assert.Equal(FaceIdVerdict.Mismatch, FaceIdDecision.Classify(0.20, 0.30, -0.20));
        Assert.Equal(FaceIdVerdict.Mismatch, FaceIdDecision.Classify(0.10, 0.30, -0.10));
        // 正常样本不受影响。
        Assert.Equal(FaceIdVerdict.Pass, FaceIdDecision.Classify(0.90, 0.30, -0.10));
        // 灰区下沿被钉在阈值上：0.29 不该因为负灰区而"低于阈值却进灰区"。
        Assert.Equal(FaceIdVerdict.Mismatch, FaceIdDecision.Classify(0.29, 0.30, -0.20));
    }

    /// <summary>NaN 相似度（特征提坏时的理论输入）⇒ Mismatch，fail closed。</summary>
    [Fact(DisplayName = "NaN 相似度 ⇒ Mismatch（fail closed）")]
    public void Classify_NaN_FailsClosed()
    {
        Assert.Equal(FaceIdVerdict.Mismatch, FaceIdDecision.Classify(double.NaN, 0.30, 0.05));
    }

    // ────────────────────────────────────────── 三、单调性（防"调一下旋钮就前后矛盾"）

    /// <summary>
    /// 相似度单调增大时，结论只能越来越好：一旦 Pass 水远不会回退，
    /// 一旦 Mismatch 迟早会离开。P3 扫阈值时如果扫出非单调曲线，
    /// 说明判定式本身被改坏了，而不是数据问题。
    /// </summary>
    [Fact(DisplayName = "结论随相似度单调不减")]
    public void Classify_MonotonicInSimilarity()
    {
        bool everPass = false;
        for (double sim = -1.0; sim <= 1.0001; sim += 0.001)
        {
            var verdict = FaceIdDecision.Classify(sim, 0.30, 0.05);
            if (verdict == FaceIdVerdict.Pass)
                everPass = true;
            else
                Assert.False(everPass, $"相似度 {sim:F3} 已见过 Pass，却又退回 {verdict}");
        }
    }

    /// <summary>灰区集合恰好是 [thr-band, thr)：扫一遍把灰区的范围量出来。</summary>
    [Fact(DisplayName = "灰区集合恰好是 [thr-band, thr)")]
    public void Classify_GrayBandIsExactlyTheInterval()
    {
        // 用 k*step 现算而不是累加：累加会漂，最后一批样本会偏离 0.55 一个 ulp 以上，
        // 把"上沿不含"这条断言变成浮点偶然事件。
        var gray = new List<double>();
        for (int k = 0; k <= 20000; k++)
        {
            double sim = -1.0 + k * 0.0001;
            if (FaceIdDecision.Classify(sim, 0.30, 0.05) == FaceIdVerdict.GrayZone)
                gray.Add(sim);
        }

        Assert.NotEmpty(gray);
        Assert.InRange(gray[0], 0.2499, 0.2501);   // 下沿含：第一档就落在 0.25 上
        Assert.True(gray[^1] < 0.30, "上沿（阈值本身）必须不含，0.30 是 Pass");
        Assert.True(gray[^1] > 0.2997, "最后一个灰区样本应贴近上沿");
    }

    // ══════════════════════════════ 四、双模型 AND（阶段 2：ArcFace 0.30 + SFace 0.46）

    // 定档依据：docs/reports/FACEID-SFACE-THRESHOLD-CALIBRATION.md
    //   主模型 0.30（P3 定档，灰区 0.05）· SFace 0.46（独立夹逼，区间 [0.451, 0.66]）
    private const double Arc = 0.30, Band = 0.05, Sf = 0.46;

    /// <summary>
    /// ★ 四格真值表。这是 AND 的**全部**语义，必须逐格钉住：
    ///   主过 + 次过 ⇒ Pass；主过 + 次否 ⇒ Mismatch；
    ///   主灰 + 任意 ⇒ GrayZone；主否 + 任意 ⇒ Mismatch。
    ///
    /// 其中"主灰 + 次否 ⇒ GrayZone"这一格最容易写错成 Mismatch ——
    /// 那样通过集合不变（都没过），却凭空多一条把本人推向锁号的路径。
    /// </summary>
    [Theory(DisplayName = "★ AND 真值表（arc 0.30 / sface 0.46）")]
    [InlineData(0.80, 0.90, FaceIdVerdict.Pass)]        // 双过
    [InlineData(0.30, 0.46, FaceIdVerdict.Pass)]        // 两条线本身都含
    [InlineData(0.80, 0.46, FaceIdVerdict.Pass)]
    [InlineData(0.80, 0.4599, FaceIdVerdict.Mismatch)]  // ★ 主过、次差一丝 ⇒ 否决（计次）
    [InlineData(0.95, 0.20, FaceIdVerdict.Mismatch)]    // ★ 主模型很确定也没用
    [InlineData(0.27, 0.90, FaceIdVerdict.GrayZone)]    // 主灰、次很确定 ⇒ 仍是灰区
    [InlineData(0.27, 0.10, FaceIdVerdict.GrayZone)]    // ★ 主灰、次否决 ⇒ 灰区（不计次）
    [InlineData(0.20, 0.90, FaceIdVerdict.Mismatch)]    // 主明确否，次再高也不算
    [InlineData(0.20, 0.10, FaceIdVerdict.Mismatch)]
    public void ClassifyPair_TruthTable(double arcSim, double sfaceSim, FaceIdVerdict expected)
    {
        Assert.Equal(expected, FaceIdDecision.ClassifyPair(arcSim, sfaceSim, Arc, Band, Sf));
    }

    /// <summary>
    /// ★ 第二模型的否决**只作用于 Pass**，不得把灰区降级成计次。
    ///
    /// 这是本组断言里最重要的一条：它把"灰区不计次"这条既有的用户保护
    /// 与"新增一票否决"这两件事的边界固定下来。反过来说，如果哪天有人为了
    /// "更安全"把否决作用到灰区，就会有一条断言在这里红掉，逼他先解释
    /// "为什么愿意让边界上的本人更容易被锁"。
    /// </summary>
    [Fact(DisplayName = "★ 第二模型否决不作用于灰区（灰区仍不计次）")]
    public void ClassifyPair_VetoDoesNotDowngradeGrayZone()
    {
        foreach (var arcSim in new[] { 0.25, 0.26, 0.27, 0.28, 0.29, 0.2999 })
        {
            Assert.Equal(FaceIdVerdict.GrayZone,
                FaceIdDecision.ClassifyPair(arcSim, 0.0, Arc, Band, Sf));
            Assert.Equal(FaceIdVerdict.GrayZone,
                FaceIdDecision.ClassifyPair(arcSim, 0.99, Arc, Band, Sf));
        }
    }

    /// <summary>
    /// AND 的通过集合**必须**是单模型通过集合的子集 —— 加一个模型只能更严，不能更松。
    /// 扫一遍两条轴：任何一对分数只要 AND 判 Pass，单独主模型判必须也是 Pass。
    /// （反向不成立：主模型 Pass 的地方 AND 可能否决，这正是新增的安全性。）
    /// </summary>
    [Fact(DisplayName = "★ AND 的 Pass 集合 ⊆ 主模型 Pass 集合（只严不松）")]
    public void ClassifyPair_NeverLooserThanSingleModel()
    {
        for (int i = 0; i <= 200; i++)
        {
            double arcSim = -1.0 + i * 0.01;
            var single = FaceIdDecision.Classify(arcSim, Arc, Band);
            for (int j = 0; j <= 200; j++)
            {
                double sfSim = -1.0 + j * 0.01;
                if (FaceIdDecision.ClassifyPair(arcSim, sfSim, Arc, Band, Sf) == FaceIdVerdict.Pass)
                    Assert.Equal(FaceIdVerdict.Pass, single);
            }
        }
    }

    /// <summary>
    /// SFace 这一票是**真的一票**：固定主模型为"远远通过"，SFace 只要差一点点就翻成 Mismatch。
    /// 它防的是"AND 让主模型两次参与、SFace 从没被比较"这种实现错误 ——
    /// 那样所有断言都可能照过，而线上等于没加第二个模型。
    /// </summary>
    [Fact(DisplayName = "★ SFace 反对票确实能推翻主模型的通过")]
    public void ClassifyPair_SFaceVetoOverridesStrongArcface()
    {
        Assert.Equal(FaceIdVerdict.Pass, FaceIdDecision.ClassifyPair(0.99, 0.46, Arc, Band, Sf));
        Assert.Equal(FaceIdVerdict.Mismatch, FaceIdDecision.ClassifyPair(0.99, 0.45, Arc, Band, Sf));
    }

    /// <summary>NaN 从任何一侧进来都不能变成 Pass（fail closed）。</summary>
    [Fact(DisplayName = "AND：任一侧 NaN ⇒ 不通过")]
    public void ClassifyPair_NaN_NeverPasses()
    {
        Assert.NotEqual(FaceIdVerdict.Pass,
            FaceIdDecision.ClassifyPair(double.NaN, 0.99, Arc, Band, Sf));
        Assert.NotEqual(FaceIdVerdict.Pass,
            FaceIdDecision.ClassifyPair(0.99, double.NaN, Arc, Band, Sf));
    }
}
