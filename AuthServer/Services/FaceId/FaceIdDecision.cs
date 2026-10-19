namespace AuthServer.Services.FaceId;

/**
 * 纯人脸登录的相似度判定：一个**纯函数**，输入 (相似度, 阈值, 灰区半宽)，
 * 输出三途结论。P2 的 FaceIdLoginService 会调用它；本文件不碰任何 IO。
 *
 * 为什么要把这三行判断从服务里抠出来单独立一个文件：
 *   阈值与灰区是 P3 唯一要调的两个旋钮，而"调旋钮"必须有一份**钉住边界语义**的
 *   回归 —— 0.50 是怎么切的、灰区朝哪边偏，这些决定过用户是被锁在门外还是
 *   被放进一个冒充者。服务层代码（签票、审计、计次）没法为这几行判断做单测，
 *   因为起一次服务才能碰到它；抠成纯函数后，`dotnet test` 在没有任何摄像头、
 *   没有任何模型文件的机器上就能把边界全部钉住。
 *
 * 边界语义（以及为什么这样定）：
 *   · sim >= threshold + grayBand            → Pass   （明确是本人）
 *   · threshold - grayBand <= sim < threshold + grayBand → GrayZone（灰区）
 *   · sim < threshold - grayBand             → Mismatch（明确不是本人）
 *   灰区**不计失败、不签票**，引导用户转用口令登录。两条边都取"含"（>=）：
 *   相似度是连续量，"恰好压在边上"时没有任何信息量能区分该归哪边，
 *   而不对称的代价决定了偏向 —— 误把本人推进 Mismatch 会计一次失败、
 *   离锁窗更近一步；误把本人留在灰区只是让他改输口令。所以边上的样本归灰区，
 *   只有**明确低于**阈值一个灰区宽度，才计 Mismatch。
 *
 * 这个函数**看不到**质量类失败（没检测到脸 / 特征提不出来 / 模板读不了）——
 * 那些分支在相似度算出来之前就已经分岔，由 P2 的服务层自己判定，
 * 绝不包装成"余弦不够高"混进这里（理由同 2FA：环境事故不能伪装成认证失败）。
 */
public enum FaceIdVerdict
{
    /// <summary>明确是本人：签票。</summary>
    Pass,

    /// <summary>灰区：不签票、不计失败，转口令登录。</summary>
    GrayZone,

    /// <summary>明确不是本人：计一次失败。</summary>
    Mismatch
}

/// <summary>
/// 阈值/灰区判定。实例化无意义，全部静态。
/// </summary>
public static class FaceIdDecision
{
    /// <summary>
    /// 按阈值与灰区把相似度分成三途。
    /// </summary>
    /// <param name="similarity">余弦相似度（由 <see cref="IFaceIdEngine.Similarity"/> 得出）。</param>
    /// <param name="threshold">判定阈值（FaceIdOptions.Threshold，P3 定档）。</param>
    /// <param name="grayBand">灰区半宽（FaceIdOptions.GrayBand，P3 定档）。</param>
    /// <remarks>
    /// ⚠️ <paramref name="grayBand"/> 传负数是配置错误：负半宽会让两个边界交叉，
    ///     退化成"什么都通过"的 fail-open。这里把它按 0 处理 —— 错误的配置
    ///     应该表现为"退化成普通阈值判定"这种可预测的行为，而不是悄悄放行。
    /// ⚠️ NaN 输入走不到任何一条 >= ，结论为 Mismatch（fail closed）。
    /// </remarks>
    public static FaceIdVerdict Classify(double similarity, double threshold, double grayBand)
    {
        var band = grayBand < 0 ? 0 : grayBand;
        if (similarity >= threshold + band) return FaceIdVerdict.Pass;
        if (similarity >= threshold - band) return FaceIdVerdict.GrayZone;
        return FaceIdVerdict.Mismatch;
    }
}
