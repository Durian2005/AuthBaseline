using OpenCvSharp;

namespace AuthServer.Services.FaceId;

/**
 * 纯采集 CLI：`AuthServer --faceid-capture <目录> [帧数] [间隔毫秒]`
 *
 * 与 2FA 的 --face-record 的区别：**它不提示任何动作**。
 * 存在的唯一理由是 P1b 的活体标定需要"看起来一样的画面、只差一个真假"：
 *   活人侧   = 本人坐在镜头前（可以有微小的自然动作）
 *   攻击侧   = 举着手机 / 打印照片 / 播放视频对着镜头
 * 后者没法按"转头"的提示配合，所以必须有一个"只管录、不管像什么"的命令。
 *
 * 采集的是**原始彩色帧**（640×480，与线上同一分辨率）——
 * 标定必须在线上同一输入尺度上做，否则标出来的阈值不适用。
 *
 * ⚠️ 落盘的帧里有真人的脸，**绝不入库**：目录必须落在 tools/fixtures/ 或本机私有目录。
 */
public static class FaceIdCaptureCli
{
    public static bool IsCommand(string[] args) =>
        args.Length > 0 && string.Equals(args[0], "--faceid-capture", StringComparison.OrdinalIgnoreCase);

    public static int Run(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: AuthServer --faceid-capture <dir> [frames=60] [intervalMs=120]");
            return 2;
        }

        var dir = Path.GetFullPath(args[1]);
        int frames = args.Length > 2 && int.TryParse(args[2], out var f) ? Math.Max(1, f) : 60;
        int interval = args.Length > 3 && int.TryParse(args[3], out var i) ? Math.Max(0, i) : 120;

        Directory.CreateDirectory(dir);

        var opt = new FaceIdOptions();
        opt.ApplyEnvironmentOverrides();

        using var engine = new CvFaceIdEngine(opt);
        if (!engine.Status.Ready)
        {
            Console.Error.WriteLine($"engine down: {engine.Status.Message}");
            return 3;
        }

        var openError = engine.TryOpen();
        if (openError is not null)
        {
            Console.Error.WriteLine($"camera open failed: {openError}");
            return 3;
        }

        int saved = 0;
        try
        {
            Console.WriteLine($"采集中：{frames} 帧，间隔 {interval} ms ⇒ {dir}");
            Console.WriteLine("（按提示摆好姿势后让它跑完即可；Ctrl+C 中止）");

            var deadline = DateTime.UtcNow.AddSeconds(frames * (interval + 200) / 1000.0 + 15);
            while (saved < frames)
            {
                if (DateTime.UtcNow > deadline)
                {
                    Console.Error.WriteLine("超时：摄像头没有给出足够的帧");
                    break;
                }

                var frame = engine.ReadFrame();
                if (frame is null)
                {
                    Thread.Sleep(30);
                    continue;
                }

                if (frame.Backing is not Mat mat || mat.Empty()) continue;

                var name = Path.Combine(dir, $"frame_{saved:0000}.jpg");
                // 用 ImEncode + WriteAllBytes 而不是 ImWrite：中文目录下 ImWrite 会失败
                // （与 onnx 路径同一类问题：OpenCV 按 ANSI 编组路径）。
                Cv2.ImEncode(".jpg", mat, out var bytes, new ImageEncodingParam(ImwriteFlags.JpegQuality, 92));
                File.WriteAllBytes(name, bytes);

                saved++;
                if (saved % 10 == 0) Console.WriteLine($"  已保存 {saved}/{frames}");
                if (interval > 0) Thread.Sleep(interval);
            }
        }
        finally
        {
            engine.Close();
        }

        Console.WriteLine($"完成：{saved} 帧 ⇒ {dir}");
        return saved == frames ? 0 : 4;
    }
}
