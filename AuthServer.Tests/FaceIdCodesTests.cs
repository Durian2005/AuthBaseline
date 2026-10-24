using AuthServer.Models;
using AuthServer.Services.FaceId;
using Xunit;

namespace AuthServer.Tests;

/// <summary>
/// <see cref="FaceIdCodes"/> 与 <see cref="FaceIdModelIdentity"/> 的纯逻辑回归。
///
/// 这两块看起来"只是常量映射"，但它们是两处**会被静默写错**的地方：
///   · 码映射错了，审计里一件事会被归到另一类（例如把"口令错"记成"质量不合格"），
///     事后按码检索就查不出人；
///   · 计次规则错了，要么给攻击者留了一条不计次的在线口令猜测通道，
///     要么让正常用户被自己的镜头误伤到锁号。
/// 两者都没有运行时症状，只能靠断言钉住。
/// </summary>
public class FaceIdCodesTests
{
    [Theory(DisplayName = "业务码 → 审计码：逐条映射")]
    [InlineData(BusinessCode.FaceIdEngineUnavailable, AuditReason.FaceIdEngineUnavailable)]
    [InlineData(BusinessCode.FaceIdDisabled, AuditReason.FaceIdEngineUnavailable)]
    [InlineData(BusinessCode.FaceIdNoFace, AuditReason.FaceIdEnrollRejected)]
    [InlineData(BusinessCode.FaceIdMultipleFaces, AuditReason.FaceIdEnrollRejected)]
    [InlineData(BusinessCode.FaceIdTooSmall, AuditReason.FaceIdEnrollRejected)]
    [InlineData(BusinessCode.FaceIdNotFrontal, AuditReason.FaceIdEnrollRejected)]
    [InlineData(BusinessCode.FaceIdLowQuality, AuditReason.FaceIdEnrollRejected)]
    [InlineData(BusinessCode.FaceIdEnrollFailed, AuditReason.FaceIdEnrollRejected)]
    [InlineData(BusinessCode.FaceIdModelMismatch, AuditReason.FaceIdModelMismatch)]
    [InlineData(BusinessCode.FaceIdNotEnrolled, AuditReason.FaceIdNoTemplate)]
    [InlineData(BusinessCode.FaceIdLivenessFailed, AuditReason.FaceIdLivenessFailed)]
    [InlineData(BusinessCode.FaceIdMismatch, AuditReason.FaceIdMismatch)]
    [InlineData(BusinessCode.FaceIdGrayZone, AuditReason.FaceIdGrayZone)]
    public void ToAuditReason_MapsEachCode(string businessCode, string expected)
    {
        Assert.Equal(expected, FaceIdCodes.ToAuditReason(businessCode));
    }

    /// <summary>
    /// ★ 未知业务码的兜底方向：落 **B 组（不计次）**。
    ///
    /// 与 2FA 的兜底（落 A 组）刻意相反，因为默认处境不同：
    ///   2FA 的未知码出现在登录路径上，宁可多计；本模块出现在**已登录后的录入**路径上，
    ///   多计只会误伤本人。真正需要计次的口令猜测有自己的码，不依赖兜底。
    /// </summary>
    [Fact(DisplayName = "★ 未知业务码兜底 ⇒ 录入被拒（B 组·不计次）")]
    public void UnknownCode_FallsBackToNotCounted()
    {
        var reason = FaceIdCodes.ToAuditReason("SOME_FUTURE_CODE");
        Assert.Equal(AuditReason.FaceIdEnrollRejected, reason);
        Assert.False(FaceIdCodes.IsCounted(reason));
    }

    /// <summary>
    /// 计次的只有三类：二次口令错（在线口令猜测）、活体失败（拿照片在试）、
    /// 登录时人脸判错（等价于口令错）。
    ///
    /// **灰区刻意不计**：灰区是"证据不足"而不是"证明不是"，
    /// 计次会让"灯太暗"这种环境问题逐步把本人锁在门外。
    /// </summary>
    [Theory(DisplayName = "计次规则：口令错 + 活体失败 + 登录判错；灰区不计")]
    [InlineData(AuditReason.FaceIdWrongPassword, true)]
    [InlineData(AuditReason.FaceIdLivenessFailed, true)]
    [InlineData(AuditReason.FaceIdMismatch, true)]
    [InlineData(AuditReason.FaceIdGrayZone, false)]
    [InlineData(AuditReason.FaceIdEnrollRejected, false)]
    [InlineData(AuditReason.FaceIdNoTemplate, false)]
    [InlineData(AuditReason.FaceIdEngineUnavailable, false)]
    [InlineData(AuditReason.FaceIdModelMismatch, false)]
    [InlineData(AuditReason.AccountLocked, false)]
    [InlineData(AuditReason.EmptyFields, false)]
    public void IsCounted_OnlyWrongPassword(string reason, bool expected)
    {
        Assert.Equal(expected, FaceIdCodes.IsCounted(reason));
    }

    [Theory(DisplayName = "质量结论 → 业务码")]
    [InlineData(FaceIdQualityVerdict.NoFace, BusinessCode.FaceIdNoFace)]
    [InlineData(FaceIdQualityVerdict.MultipleFaces, BusinessCode.FaceIdMultipleFaces)]
    [InlineData(FaceIdQualityVerdict.TooSmall, BusinessCode.FaceIdTooSmall)]
    [InlineData(FaceIdQualityVerdict.NotFrontal, BusinessCode.FaceIdNotFrontal)]
    [InlineData(FaceIdQualityVerdict.Blurry, BusinessCode.FaceIdLowQuality)]
    [InlineData(FaceIdQualityVerdict.Pass, BusinessCode.FaceIdEnrollFailed)]
    public void BusinessCodeFor_MapsVerdicts(FaceIdQualityVerdict verdict, string expected)
    {
        Assert.Equal(expected, FaceIdCodes.BusinessCodeFor(verdict));
    }

    /// <summary>每种业务码都必须有一句给人看的话术，不能落到空字符串（界面会显示空白）。</summary>
    [Theory(DisplayName = "话术表覆盖所有业务码")]
    [InlineData(BusinessCode.FaceIdDisabled)]
    [InlineData(BusinessCode.FaceIdEngineUnavailable)]
    [InlineData(BusinessCode.FaceIdNoFace)]
    [InlineData(BusinessCode.FaceIdMultipleFaces)]
    [InlineData(BusinessCode.FaceIdTooSmall)]
    [InlineData(BusinessCode.FaceIdNotFrontal)]
    [InlineData(BusinessCode.FaceIdLowQuality)]
    [InlineData(BusinessCode.FaceIdEnrollFailed)]
    [InlineData(BusinessCode.FaceIdNotEnrolled)]
    [InlineData(BusinessCode.FaceIdModelMismatch)]
    [InlineData(BusinessCode.FaceIdLivenessFailed)]
    [InlineData(BusinessCode.FaceIdMismatch)]
    [InlineData(BusinessCode.FaceIdGrayZone)]
    public void MessageFor_IsNeverEmpty(string code)
    {
        Assert.False(string.IsNullOrWhiteSpace(FaceIdCodes.MessageFor(code)));
    }

    /// <summary>
    /// 多脸的提示不许暗示"系统在拍别人"—— 它只说明"画面里只能有一个人"。
    /// 这条断言保护的是措辞，而不是功能：一句容易被误解的话，
    /// 在隐私敏感的功能里本身就是缺陷。
    /// </summary>
    [Fact(DisplayName = "多脸话术强调「只能有一个人」而非「检测到他人」")]
    public void MultipleFacesMessage_IsNeutral()
    {
        var message = FaceIdCodes.MessageFor(BusinessCode.FaceIdMultipleFaces);
        Assert.Contains("只能有一个人", message);
        Assert.DoesNotContain("检测到他人", message);
    }
}

/// <summary>
/// 模型身份：模板与它绑定，换模型必须作废。这几条断言防的是"静默换模型"
/// —— 换权重后老模板还能算出相似度（一个合法但无意义的数字），
/// 表现为"这个人有时能进有时进不去"，是最难归因的故障。
/// </summary>
public class FaceIdModelIdentityTests
{
    private static FaceIdOptions StubOptions() => new() { Engine = "stub", EmbeddingDim = 512 };

    [Fact(DisplayName = "假引擎 ⇒ 身份带 stub 前缀且含两条维度")]
    public void StubIdentity_IsPrefixed()
    {
        var id = new FaceIdModelIdentity(StubOptions());
        Assert.Equal("stub:512+128", id.ModelId);
        Assert.Equal(512, id.Dim);
        Assert.Equal(128, id.SFaceDim);
    }

    /// <summary>
    /// ★ 假引擎录的模板不能被真引擎认成"可用"。
    /// 两条链路的特征空间完全不同，而它们的维度都是 512 ——
    /// 只靠维度区分必然失败，所以身份里必须带引擎种类。
    /// </summary>
    [Fact(DisplayName = "★ stub 身份与 cv 身份不可能相等")]
    public void StubIdentity_DiffersFromCv()
    {
        var stub = new FaceIdModelIdentity(StubOptions());
        var cv = new FaceIdModelIdentity(new FaceIdOptions
        {
            Engine = "cv",
            // 指向一个不存在的模型文件：函数必须返回一个确定身份，而不是抛异常。
            RecognizerModel = "face-models/__not_there__.onnx"
        });

        Assert.StartsWith("cv:", cv.ModelId);
        Assert.Contains("missing", cv.ModelId);
        Assert.NotEqual(stub.ModelId, cv.ModelId);
        Assert.False(stub.Matches(cv.ModelId));
        Assert.False(cv.Matches(stub.ModelId));
    }

    [Theory(DisplayName = "Matches：空 / null / 旧格式 / 不同值一律不匹配")]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("stub:128", false)]
    // ★ 旧格式（单模型）不再匹配：它代表的是一张"只有一半"的模板 ——
    // 允许它匹配，AND 就会拿一条不存在的第二向量去比。
    [InlineData("stub:512", false)]
    [InlineData("stub:512+128", true)]
    public void Matches_IsStrict(string? stored, bool expected)
    {
        Assert.Equal(expected, new FaceIdModelIdentity(StubOptions()).Matches(stored));
    }

    /// <summary>维度配置非法（0 或负数）时回落到默认值，而不是让模板校验静默失效。</summary>
    [Theory(DisplayName = "非法维度 ⇒ 回落到 512+128")]
    [InlineData(0)]
    [InlineData(-1)]
    public void InvalidDim_FallsBackTo512(int dim)
    {
        var id = new FaceIdModelIdentity(new FaceIdOptions { Engine = "stub", EmbeddingDim = dim });
        Assert.Equal(512, id.Dim);
        Assert.Equal("stub:512+128", id.ModelId);
    }

    /// <summary>
    /// ★ 真引擎的身份必须**同时**纳入两个模型。
    ///
    /// 只记主模型的话，"换了 SFace 权重"不会让老模板作废 ⇒ AND 的一半来自旧特征空间、
    /// 一半来自新空间，得分合法但毫无意义（表现仍是"有人有时能进有时进不去"）。
    /// 这里用不存在的文件名构造"missing"身份，正好可以在没有模型文件的机器上验证
    /// 这条组合规则：只改第二模型的名字，身份就必须变。
    /// </summary>
    [Fact(DisplayName = "★ cv 身份同时纳入两个模型（只换第二模型也必须作废）")]
    public void CvIdentity_CoversBothModels()
    {
        var both = new FaceIdModelIdentity(new FaceIdOptions
        {
            Engine = "cv",
            RecognizerModel = "face-models/__arc_a__.onnx",
            SFaceModel = "face-models/__sface_a__.onnx"
        });

        Assert.StartsWith("cv:", both.ModelId);
        Assert.Contains("__arc_a__.onnx:missing:512", both.ModelId);
        Assert.Contains("__sface_a__.onnx:missing:128", both.ModelId);

        var other = new FaceIdModelIdentity(new FaceIdOptions
        {
            Engine = "cv",
            RecognizerModel = "face-models/__arc_a__.onnx",   // 主模型不变
            SFaceModel = "face-models/__sface_b__.onnx"       // 只换第二模型
        });

        Assert.NotEqual(both.ModelId, other.ModelId);
        Assert.False(both.Matches(other.ModelId));
        Assert.False(other.Matches(both.ModelId));
    }
}
