using OpenCvSharp;

namespace AuthServer.Services.FaceId;

/**
 * 嵌入导出 CLI：`AuthServer --faceid-embed <图片路径> [更多图片...]`
 *
 * 用途只有一个：**P0 Stage 0 对照实验** —— 让 Python 参考管线（cv2 + onnxruntime）
 * 与本引擎对同一张图各算一次嵌入，比对余弦。没有它，"C# 管线与参考实现等价"
 * 这件事只能靠嘴说。
 *
 * 与人脸 2FA 的 FaceFixtureCli 同思路：子命令必须在 CreateBuilder **之前**截住
 * （WebApplication.CreateBuilder 会消费命令行参数；且这条命令只跑引擎，
 * 不需要 pepper / 数据库 / 证书）。
 *
 * 输出（每张图一行，TSV）：
 *   <路径> \t <维度> \t f0,f1,...,fN      （R 格式， round-trip 精度， InvariantCulture）
 * 读不到图 / 检测不到脸 / 提不出特征 ⇒ 该行进 stderr，退出码非 0。
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
            Console.Error.WriteLine("usage: AuthServer --faceid-embed <image...>");
            return 2;
        }

        var opt = new FaceIdOptions();
        opt.ApplyEnvironmentOverrides();

        using var engine = new CvFaceIdEngine(opt);
        if (!engine.Status.Ready)
        {
            Console.Error.WriteLine($"engine down: {engine.Status.Message}");
            return 3;
        }

        int failed = 0;
        foreach (var path in paths)
        {
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

            var feature = engine.Feature(frame, box);
            if (feature is null)
            {
                Console.Error.WriteLine($"feature failed: {path}");
                failed++;
                continue;
            }

            var line = string.Join(",", feature.Select(f =>
                f.ToString("R", System.Globalization.CultureInfo.InvariantCulture)));
            Console.WriteLine($"{path}\t{feature.Length}\t{line}");
        }

        return failed == 0 ? 0 : 4;
    }
}
