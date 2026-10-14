using OpenCvSharp;

namespace AuthServer.Services.Face;

/**
 * 把一帧画成**预览 JPEG**：人脸框 + 置信度，按状态换颜色。
 *
 * 为什么标注放在服务端画，而不是把框的坐标下发给前端让前端画：
 *   ① 前端拿到的就是"服务端看到的那一帧"，所见即所判 —— 不存在
 *      "界面上的框来自 A 帧、判定用的是 B 帧"这种对不上的情况；
 *   ② 前端因此**不需要**任何坐标数据，接口上依旧只有一张图，
 *      连"疑似特征/关键点外泄"的顾虑都不存在（5 个关键点属于生物特征，
 *      画成框之后再下发，出去的只是可视化结果）。
 *
 * ⚠️ 只画 ASCII：OpenCV 内置的 Hershey 字体不含汉字，
 *    `Cv2.PutText` 写中文会变成一串问号。中文措辞（"已检测到人脸"这类）
 *    一律由前端用 HTML 叠加，服务端只负责数字与框。
 */
internal static class FacePreviewEncoder
{
    /// <summary>JPEG 画质。75 在 640x480 上约 30~40KB/帧，本地环回完全够用。</summary>
    private const int JpegQuality = 75;

    /// <summary>
    /// 在**副本**上画框并编码。
    /// ⚠️ 必须传副本：采集循环里那张 Mat 同时是提特征用的原图，
    ///    在上面画框会把框的像素喂进对齐与特征提取，污染判定结果。
    /// </summary>
    public static byte[] Annotate(Mat frame, FaceBox? box, string state)
    {
        using var canvas = frame.Clone();

        if (box is not null && box.W > 1 && box.H > 1)
        {
            var color = state switch
            {
                FacePreviewFrame.StateAction => new Scalar(0, 190, 255),    // BGR：琥珀色，等动作
                FacePreviewFrame.StateReturned => new Scalar(0, 230, 255),  // 亮黄，等回正
                _ => new Scalar(96, 220, 96)                                // 绿，已检测到
            };

            // 框可能有一部分在画面外（贴边时），先裁到画面内再画，
            // 否则 OpenCV 会抛而不是自动裁剪。
            int x = Math.Clamp((int)box.X, 0, Math.Max(0, canvas.Width - 1));
            int y = Math.Clamp((int)box.Y, 0, Math.Max(0, canvas.Height - 1));
            int w = Math.Clamp((int)box.W, 1, canvas.Width - x);
            int h = Math.Clamp((int)box.H, 1, canvas.Height - y);

            Cv2.Rectangle(canvas, new Rect(x, y, w, h), color, 2, LineTypes.AntiAlias);

            // 置信度画在框的上方；先描一层深色再压亮色，保证在任何背景上都读得清
            var label = box.Score.ToString("F2");
            var org = new Point(x, Math.Max(18, y - 8));
            Cv2.PutText(canvas, label, org, HersheyFonts.HersheyDuplex, 0.7, new Scalar(0, 0, 0),
                4, LineTypes.AntiAlias);
            Cv2.PutText(canvas, label, org, HersheyFonts.HersheyDuplex, 0.7, color, 1, LineTypes.AntiAlias);
        }

        Cv2.ImEncode(".jpg", canvas, out var buffer,
            new[] { new ImageEncodingParam(ImwriteFlags.JpegQuality, JpegQuality) });
        return buffer;
    }

    /// <summary>
    /// 占位帧：拿不到真实画面时给一张带说明的深色图。
    ///
    /// 为什么要有它，而不是直接返回 null 让界面显示空白：
    ///   假引擎（`FaceOptions.Engine=stub`）与"本机没有摄像头"这两种情况下，
    ///   流程仍然应该能被完整走到与验证 —— 界面显示"STUB / CAMERA UNAVAILABLE"
    ///   远比一片空白更容易判断"到底卡在哪一步"。
    /// </summary>
    public static byte[] Placeholder(int width, int height, string text)
    {
        using var canvas = new Mat(new Size(Math.Max(64, width), Math.Max(64, height)),
            MatType.CV_8UC3, new Scalar(34, 28, 34));
        Cv2.Rectangle(canvas, new Rect(1, 1, canvas.Width - 2, canvas.Height - 2),
            new Scalar(96, 96, 96), 2);

        var size = Cv2.GetTextSize(text, HersheyFonts.HersheyDuplex, 0.8, 2, out _);
        Cv2.PutText(canvas, text,
            new Point(Math.Max(4, (canvas.Width - size.Width) / 2), canvas.Height / 2),
            HersheyFonts.HersheyDuplex, 0.8, new Scalar(200, 200, 200), 2, LineTypes.AntiAlias);

        Cv2.ImEncode(".jpg", canvas, out var buffer, new[] { new ImageEncodingParam(ImwriteFlags.JpegQuality, 80) });
        return buffer;
    }
}
