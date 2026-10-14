namespace AuthServer.Services.Face;

/**
 * 头部姿态的**代理值**，以及动作挑战的判定规则。
 *
 * 全部是从参考项目 FaceLogin 的 `liveness.py` / `face.py` 移植的（含那几个经验阈值）。
 * 移植而不是重新推导，是因为那些数字是在真实摄像头上逐点核对出来的，
 * 重新"设计"一遍只会得到一组没人验证过的魔数。
 *
 * 为什么是"代理值"而不是真实角度：YuNet 只给 5 个关键点（双眼、鼻尖、双嘴角），
 * 没有相机标定就别谈真实角度。用比值近似足够做动作判定，而且**比值天然抗缩放** ——
 * 这一点很关键：C# 侧采集分辨率与参考项目不同，比值仍然可比。
 *
 * 为什么一律用"相对基线的变化量"而不是绝对阈值：
 *   yaw 的正视取值因人、因坐姿而异（实测同一个人在 +0.01 ~ +0.07 之间波动），
 *   pitch 的直接还取决于鼻长与嘴位。用绝对阈值必然误判一批人。
 */
public static class FacePose
{
    // ── 动作定义 ──────────────────────────────────────────────
    public const string Left = "left";
    public const string Right = "right";
    public const string Up = "up";
    public const string Down = "down";

    public static readonly string[] Actions = { Left, Right, Up, Down };

    public static string ActionText(string action) => action switch
    {
        Left => "把头转向你的左侧",
        Right => "把头转向你的右侧",
        Up => "把头略微抬起（向上看）",
        Down => "把头略微低下（向下看）",
        _ => "请正对摄像头"
    };

    public const string ActionHint = "幅度大一点，保持约 1 秒，然后转回正对摄像头";

    // ── 判定参数（与参考项目一致，改这里前先想清楚为什么要改） ──
    public const double SampleIntervalSeconds = 0.07;   // 采样间隔，约 14 Hz
    public const int BaselineFrames = 4;                // 求基线所需帧数
    public const int HitWindow = 5;                     // 判定动作的滑窗长度
    public const int HitNeeded = 3;                     // 滑窗内至少命中几帧才算动作成立
    public const int NeutralFrames = 2;                 // 回正需要连续几帧
    public const int MaxMiss = 10;                      // 连续读帧失败 / 检测不到人脸的上限
    public const int MaxJumps = 3;                      // 允许的人脸位置跳变次数
    public const double JumpRatio = 0.6;                // 相邻帧人脸中心位移 / 人脸宽度 上限
    public const int MinSamples = 6;                    // 判定所需的最少有效帧

    public const double YawTurn = 0.13;                 // "明显转头"的 yaw 偏移阈值
    public const double PitchTilt = 0.10;               // "明显抬头/低头"的 pitch 偏移阈值
    public const double NeutralYaw = 0.07;              // 视为已回正的 yaw 容差
    public const double NeutralPitch = 0.05;            // 视为已回正的 pitch 容差

    /// <summary>由 5 个关键点算 (yaw, pitch, iod)。iod 是瞳距像素值，可用于判断离镜头过远。</summary>
    public static (double Yaw, double Pitch, double Iod) Metrics(FaceBox box)
    {
        var p = box.Points;
        // 顺序：眼A(0,1) 眼B(2,3) 鼻(4,5) 嘴A(6,7) 嘴B(8,9)
        double eyeMidX = (p[0] + p[2]) / 2.0;
        double eyeMidY = (p[1] + p[3]) / 2.0;
        double mouthMidY = (p[7] + p[9]) / 2.0;
        double noseX = p[4], noseY = p[5];

        double iod = Math.Sqrt((p[0] - p[2]) * (p[0] - p[2]) + (p[1] - p[3]) * (p[1] - p[3]));
        double span = mouthMidY - eyeMidY;

        double yaw = (noseX - eyeMidX) / Math.Max(iod, 1e-6);
        double pitch = (noseY - eyeMidY) / Math.Max(span, 1e-6);
        return (yaw, pitch, iod);
    }

    /// <summary>给定相对基线的偏移，判断本帧是否满足指定动作。</summary>
    public static bool Satisfied(string action, double dy, double dp) => action switch
    {
        Left => dy >= YawTurn,
        Right => dy <= -YawTurn,
        Up => dp <= -PitchTilt,
        _ => dp >= PitchTilt      // down
    };

    /// <summary>是否已回到"正对镜头"。</summary>
    public static bool IsNeutral(double dy, double dp) =>
        Math.Abs(dy) <= NeutralYaw && Math.Abs(dp) <= NeutralPitch;

    public static double Median(List<double> xs)
    {
        if (xs.Count == 0) return 0;
        var s = xs.ToList();
        s.Sort();
        int n = s.Count;
        return n % 2 == 1 ? s[n / 2] : (s[n / 2 - 1] + s[n / 2]) / 2.0;
    }
}
