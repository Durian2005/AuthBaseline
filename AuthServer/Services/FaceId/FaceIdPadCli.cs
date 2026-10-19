using OpenCvSharp;

namespace AuthServer.Services.FaceId;

/**
 * 活体分数导出 CLI：`AuthServer --faceid-pad <图片...>`
 *
 * 用途与 --faceid-embed 相同 —— **让"我们的预处理与参考实现等价"变成可复算的**，
 * 而不是一句写在文档里的断言。PAD 尤其需要这一层：
 * 它的分数对"除不除 255 / 通不通道交换 / 裁多大"极其敏感（实测：除 255 会把真人
 * 一片判成 replay），而这种错误不会抛异常，只会安静地给出一个错误的数。
 *
 * 输出（每张图一行，TSV）：
 *   <路径> \t <live>          （R 格式，round-trip 精度，InvariantCulture）
 * 读不到图 / 检测不到脸 / 模型不可用 ⇒ 该行进 stderr，退出码非 0。
 */
public static class FaceIdPadCli
{
    public static bool IsCommand(string[] args) =>
        args.Length > 0 && string.Equals(args[0], "--faceid-pad", StringComparison.OrdinalIgnoreCase);

    public static int Run(string[] args)
    {
        var paths = args.Skip(1).Where(a => !a.StartsWith('-')).ToArray();
        if (paths.Length == 0)
        {
            Console.Error.WriteLine("usage: AuthServer --faceid-pad <image...>");
            return 2;
        }

        var opt = new FaceIdOptions();
        opt.ApplyEnvironmentOverrides();
        // 检出分数与"线上用不用活体"无关：CLI 只负责回答"这张图的分数是多少"。
        opt.PadEnabled = true;

        using var engine = new CvFaceIdEngine(opt);
        if (!engine.Status.Ready)
        {
            Console.Error.WriteLine($"engine down: {engine.Status.Message}");
            return 3;
        }

        var liveness = new CvFaceIdLiveness(opt);
        if (!liveness.Status.Ready)
        {
            Console.Error.WriteLine($"liveness down: {liveness.Status.Message}");
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

            var live = liveness.Score(frame, box);
            if (live is null)
            {
                Console.Error.WriteLine($"pad failed: {path}");
                failed++;
                continue;
            }

            Console.WriteLine($"{path}\t{live.Value.ToString("R", System.Globalization.CultureInfo.InvariantCulture)}");
        }

        return failed == 0 ? 0 : 4;
    }
}
