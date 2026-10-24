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
 * 边界语义（P3 定档时正名：**阈值就是通过线**）：
 *   · sim >= threshold                       → Pass   （明确是本人，签票）
 *   · threshold - grayBand <= sim < threshold → GrayZone（灰区，不签票、不计失败）
 *   · sim < threshold - grayBand             → Mismatch（明确不是本人，计一次失败）
 *
 *   为什么 P3 把语义改成"阈值即通过线"：
 *     P2 的写法是 `sim >= threshold + grayBand` 才通过，于是界面上写着"判定阈值 0.50"、
 *     实际要 0.55 才放行 —— 同一个数字在代码与界面里指两件事。定档正是要拿实测曲线
 *     反推一个数，这种歧义必然算错一档，所以先改正再定档。
 *
 *   两条边都取"含"（>=）：相似度是连续量，"恰好压在边上"时没有信息量能区分归哪边，
 *   而不对称的代价决定了偏向 —— 误把本人推进 Mismatch 会计一次失败、离锁窗更近一步；
 *   误把本人留在灰区只是让他改输口令。所以边界样本归灰区，
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
        if (similarity >= threshold) return FaceIdVerdict.Pass;
        if (similarity >= threshold - band) return FaceIdVerdict.GrayZone;
        return FaceIdVerdict.Mismatch;
    }

    /// <summary>
    /// 双模型（ArcFace + SFace）的 **AND** 判定。
    ///
    /// 规则（阶段 2 落地口径，见 docs/reports/FACEID-SFACE-THRESHOLD-CALIBRATION.md）：
    ///   通过 ⇔ `arcSim >= arcThreshold` **且** `sfaceSim >= sfaceThreshold`
    ///
    /// 四格真值表（按主模型的结论分岔，第二模型**只否决"通过"**）：
    ///   主模型 Pass   + SFace Pass ⇒ **Pass**
    ///   主模型 Pass   + SFace 否决 ⇒ **Mismatch**（计次；这是 AND 的唯一新增拒识来源）
    ///   主模型 Gray   + 任意       ⇒ **GrayZone**（不计次）
    ///   主模型 Mismatch + 任意     ⇒ **Mismatch**
    ///
    /// 为什么第二模型**只能否决通过、不能把灰区降级成计次**（这一条最容易写错）：
    ///   灰区的唯一作用是"把边界上的本人挪出计次窗口"。若让 SFace 的否决也作用于灰区，
    ///   那么一个主模型 0.28（原本 GrayZone、不计次）的本人会因 SFace 低分变成计次失败 ——
    ///   通过集合没变（都没过），**却凭空多了一条把本人推向锁号的路径**。
    ///   攻击者一个字节都没多拿到，本人却更容易被锁。所以否决只作用于 Pass。
    ///
    /// 为什么第二模型**没有**灰区（本函数唯一"不对称"的地方）：
    ///   灰区宽度必须由**该模型的本人分布**标出来。主模型的 0.05 是从 LFW 本人分布上
    ///   量出来的；SFace 侧**没有做过这项标定**，照搬 0.05 会凭空造出一条"试了不锁"的
    ///   地带 —— 而撞脸样本在 SFace 上能摸到 0.40 附近（标定报告 §四：0.40 以下就有
    ///   探针能过），那正是最不该给免费试错机会的区间。
    ///   ⇒ 已知代价：AND 的 TAR 95.87%，约 4% 的本人会在主模型通过后被 SFace 否决
    ///     并计一次失败。多张模板取 max 已把它摊薄，但这条成本是**真实的**，
    ///     不许在文档里抹掉；要消掉它必须先补 SFace 本人分布的标定。
    ///
    /// ⚠️ AND 的**作用单元**是"两模型各自取模板 max 之后相与"，不是"任一副本两模型都过"。
    ///    线上没有逐副本比对这一步，调用方必须先把 max 取完再进来。
    /// ⚠️ NaN ⇒ 所有 `>=` 都不成立 ⇒ 走不到 Pass（fail closed）。
    /// </summary>
    /// <param name="arcSimilarity">主模型（ArcFace）对全部模板取的最大余弦。</param>
    /// <param name="sfaceSimilarity">第二模型（SFace）对全部模板取的最大余弦。</param>
    public static FaceIdVerdict ClassifyPair(
        double arcSimilarity, double sfaceSimilarity,
        double arcThreshold, double grayBand, double sfaceThreshold)
    {
        // 主模型没过 ⇒ 结论与单模型完全一致（灰区/明确不是本人），第二模型不参与。
        // 这一句就是"否决只作用于 Pass"的实现，不要把它改写成先判 SFace。
        if (!(arcSimilarity >= arcThreshold))
            return Classify(arcSimilarity, arcThreshold, grayBand);

        // 主模型过了：这时才轮到第二模型行使否决权。
        return sfaceSimilarity >= sfaceThreshold ? FaceIdVerdict.Pass : FaceIdVerdict.Mismatch;
    }
}
