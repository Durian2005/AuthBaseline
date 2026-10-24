using OpenCvSharp;

namespace AuthServer.Services.FaceId;

/**
 * 嵌入导出 CLI：`AuthServer --faceid-embed [--sface] <图片路径> [更多图片...]`
 *
 * 用途只有一个：**P0 Stage 0 对照实验** —— 让 Python 参考管线（cv2 + onnxruntime）
 * 与本引擎对同一张图各算一次嵌入，比对余弦。没有它，"C# 管线与参考实现等价"
 * 这件事只能靠嘴说。阶段 2 起两条管线各有一套预处理，`--sface` 用来单独复核
 * 第二模型（SFace）那条，避免"只验了主模型就宣布双双等价"。
 *
 * 与人脸 2FA 的 FaceFixtureCli 同思路：子命令必须在 CreateBuilder **之前**截住
 * （WebApplication.CreateBuilder 会消费命令行参数；且这条命令只跑引擎，
 * 不需要 pepper / 数据库 / 证书）。
 *
 * 输出（每张图一行，TSV）：
 *   <输入序号> \t <维度> \t f0,f1,...,fN    （R 格式， round-trip 精度， InvariantCulture）
 *
 * ⚠️ 第一列是**序号**而不是路径：中文 Windows 下 C# 控制台按 GBK 输出，
 *    含中文的路径回显到管道后会被调用方打成 U+FFFD，按路径精确配对所有图都失败。
 *    序号由调用方自己映射回路径 —— 输入顺序即输出顺序，缺行代表该图失败。
 *    失败原因（读图失败 / 没检测到脸 / 提不出特征）走 stderr，退出码非 0。
 */
public static class FaceIdEmbedCli
{
    public static bool IsCommand(string[] args) =>
        args.Length > 0 && string.Equals(args[0], "--faceid-embed", StringComparison.OrdinalIgnoreCase);

    public static int Run(string[] args)
    {
        var paths = args.Skip(1).Where(a => !a.StartsWith('-')).ToArray();
        if (paths.Length == 0)
        {
            Console.Error.WriteLine("usage: AuthServer --faceid-embed [--sface] <image...>");
            return 2;
        }

        // `--sface` 导出**第二模型**的向量，否则导出主模型。
        // 为什么用开关而不是"一次输出两行"：调用方（Python 参考管线）按
        // "输入顺序 = 输出顺序、一行一张图"来配对，多一行会让序号映射整体错位。
        var wantSecond = args.Any(a => string.Equals(a, "--sface", StringComparison.OrdinalIgnoreCase));

        var opt = new FaceIdOptions();
        opt.ApplyEnvironmentOverrides();

        using var engine = new CvFaceIdEngine(opt);
        if (!engine.Status.Ready)
        {
            Console.Error.WriteLine($"engine down: {engine.Status.Message}");
            return 3;
        }

        int failed = 0;
        for (int i = 0; i < paths.Length; i++)
        {
            var path = paths[i];

            using var mat = Cv2.ImRead(path, ImreadModes.Color);
            if (mat.Empty())
            {
                Console.Error.WriteLine($"read failed: {path}");
                failed++;
                continue;
            }

            var frame = new FaceIdFrame { Width = mat.Width, Height = mat.Height, Backing = mat };
            var box = engine.DetectLargest(frame);
            if (box is null)
            {
                Console.Error.WriteLine($"no face: {path}");
                failed++;
                continue;
            }

            var pair = engine.Feature(frame, box);
            if (pair is null)
            {
                Console.Error.WriteLine($"feature failed: {path}");
                failed++;
                continue;
            }

            var feature = wantSecond ? pair.Second : pair.Primary;
            var line = string.Join(",", feature.Select(f =>
                f.ToString("R", System.Globalization.CultureInfo.InvariantCulture)));
            Console.WriteLine($"{i}\t{feature.Length}\t{line}");
        }

        return failed == 0 ? 0 : 4;
    }
}
