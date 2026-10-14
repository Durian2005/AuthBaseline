using System.Collections.Concurrent;

namespace AuthServer.Services.Face;

/**
 * 预览的一帧：**已经编码好的 JPEG** + 这一帧的检测状态。
 *
 * 为什么要连 JPEG 一起存，而不是存下来让渲染层自己编：
 *   编码器只有 OpenCV 一份（`FacePreviewEncoder`），把这件活摊到两个地方
 *   迟早会出现"预览的框和判定的框不是同一个框"。这里存的就是最终要显示的那张图。
 *
 * `State` 是**给界面看的粗粒度状态**，不是认证判定结果 ——
 * 判定结果只走 `FaceLoginService`，两者绝不能互相代替（否则界面显示"已检测到人脸"
 * 就会被误读成"验证通过"）。
 */
public sealed record FacePreviewFrame(byte[] Jpeg, string State, double? Score, DateTime AtUtc)
{
    /// <summary>引擎/摄像头不可用，这一帧是占位图。</summary>
    public const string StateDown = "down";

    /// <summary>画面里没有人脸。</summary>
    public const string StateNoFace = "no-face";

    /// <summary>检测到人脸（尚未进入动作挑战）。</summary>
    public const string StateDetected = "detected";

    /// <summary>正在等用户完成动作。</summary>
    public const string StateAction = "action";

    /// <summary>动作已完成，正在等用户转回正对镜头。</summary>
    public const string StateReturned = "returned";
}

/**
 * 人脸"识别画面"的**门禁 + 帧槽**。
 *
 * ── 它解决的矛盾 ─────────────────────────────────────────────────
 * 设计文档 §九 原本刻意**去掉了摄像头预览接口**，三条理由里有一条是
 * "后端若无鉴权地推画面，本机任何页面都能来拉摄像头流"。
 * 要显示识别画面，就必须把这条理由正面解决掉，而不是绕过去：
 *
 *   ① **门禁绑在挑战上**：只有持有一张**尚未过期的一次性挑战 token** 才拿得到画面。
 *      而挑战只可能来自"口令刚刚验证通过"那一步（登录）或"本人重新输了口令"（录入）。
 *      ⇒ 预览不是一条常开的摄像头流，而是一段**有主的、会自己结束的**窗口。
 *   ② **采集端仍然只在服务端**：帧由引擎在服务端进程内取，画框也在服务端画，
 *      前端拿到的是**已经渲染好的图**。接口形状上没有"接收画面/特征"这一项，
 *      "前端伪造一个向量直接提交"这条路依然不存在。
 *   ③ **摄像头不会自己一直开着**：后台循环在"没有有效 token"时立刻 `Close()`，
 *      把设备还回去。用户关掉页面 / token 过期之后，摄像头在 1 个循环周期内被释放。
 *
 * ── 与引擎的关系是双向的，所以分两步接线 ──────────────────────────
 * 引擎要在正式采集（RunChallenge）期间**推帧**（那几秒里只有它持有摄像头），
 * 而本服务要读帧、并在空闲时关摄像头。两边都要对方的引用 ⇒ 构造函数会成环。
 * 因此 `Program.cs` 里先生成本服务、把它交给引擎，再回调 `Bind(engine)`；
 * 这是**启动期一次性的接线**，运行期不再改变。
 */
public sealed class FacePreviewService : IDisposable
{
    /// <summary>后台取帧周期。约 9 帧/秒 —— 高于这个数本地环回上只是多消耗 CPU</summary>
    private const int PumpIntervalMs = 110;

    /// <summary>token → 过期时刻（UTC）。key 与挑战 token 同物，但不参与挑战的消费语义</summary>
    private readonly ConcurrentDictionary<string, DateTime> _open = new();

    private IFaceEngine? _engine;
    private volatile FacePreviewFrame? _latest;

    /// <summary>采集进行中的计数器（同一时刻只可能有一个采集，用计数是为了配 using 更稳）</summary>
    private int _capturing;

    private readonly Timer _pump;
    private int _pumping;
    private bool _active;
    private bool _disposed;

    public FacePreviewService()
    {
        _pump = new Timer(_ => Pump(), null, PumpIntervalMs, PumpIntervalMs);
    }

    /// <summary>启动期接线：把引擎交给本服务（用于取帧与释放摄像头）。</summary>
    public void Bind(IFaceEngine engine) => _engine = engine;

    // ────────────────────────────────────────────── 门禁

    /// <summary>
    /// 放行一张挑战 token。只登记 token 与过期时刻 —— **不保存任何画面、不保存账号**。
    /// 挑战自身的消费语义（一次性、用途绑定）仍只由 `FaceChallengeStore` 负责，
    /// 这里只是"这张票现在还允许看一眼画面吗"。
    /// </summary>
    public void Open(string token, int ttlSeconds)
    {
        if (string.IsNullOrWhiteSpace(token)) return;
        _open[token] = DateTime.UtcNow.AddSeconds(Math.Max(1, ttlSeconds));
        Volatile.Write(ref _active, true);
    }

    /// <summary>收回一张 token 的预览权（采集结束 / 用户放弃时调用）。</summary>
    public void Close(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return;
        _open.TryRemove(token, out _);
        if (_open.IsEmpty) _latest = null;
    }

    /// <summary>这张 token 现在是否允许拉取画面。</summary>
    public bool IsOpen(string? token)
    {
        if (string.IsNullOrWhiteSpace(token)) return false;
        if (!_open.TryGetValue(token, out var until)) return false;
        if (until > DateTime.UtcNow) return true;
        _open.TryRemove(token, out _);
        return false;
    }

    /// <summary>当前放行的 token 数（探针用）。</summary>
    public int OpenCount => _open.Count;

    /// <summary>最新的一帧；没有则为 null。</summary>
    public FacePreviewFrame? Latest => _latest;

    // ────────────────────────────────────────────── 采集期

    /**
     * 标记"正式采集已经开始"。在它的作用域内：
     *   · 后台取帧循环**停手** —— 那几秒里摄像头归采集循环独占，
     *     两边各读一半帧会把判定用的采样率砍半（14Hz → 7Hz），是能直接把挑战判失败的；
     *   · 画面改由采集循环自己推（它读到的就是判定用的那一帧，所见即所判）。
     */
    public IDisposable BeginCapture()
    {
        Interlocked.Increment(ref _capturing);
        return new CaptureScope(this);
    }

    /// <summary>采集期间由引擎调用：推一帧画面出去。</summary>
    public void Publish(FacePreviewFrame frame) => _latest = frame;

    private sealed class CaptureScope : IDisposable
    {
        private readonly FacePreviewService _owner;
        private bool _done;

        public CaptureScope(FacePreviewService owner) => _owner = owner;

        public void Dispose()
        {
            if (_done) return;
            _done = true;
            Interlocked.Decrement(ref _owner._capturing);
        }
    }

    // ────────────────────────────────────────────── 后台取帧

    private void Pump()
    {
        if (_disposed) return;
        // 上一轮还没跑完就跳过这一拍：宁可掉帧，也不要两个线程同时去抢摄像头
        if (Interlocked.Exchange(ref _pumping, 1) == 1) return;
        try
        {
            Prune();

            // 没人在看 / 正在正式采集 ⇒ 一次帧都不取，并且把摄像头还回去
            if (_open.IsEmpty || Volatile.Read(ref _capturing) > 0)
            {
                ReleaseIfIdle();
                return;
            }

            var engine = _engine;
            if (engine is null) return;

            var frame = engine.SnapshotPreview();
            if (frame is not null) _latest = frame;
        }
        catch (Exception ex)
        {
            // 预览是锦上添花：任何异常都不许把进程带下去，也不许写审计
            // （审计只记录认证行为，预览失败不是认证行为）。
            Console.WriteLine($"[Face] 预览取帧失败：{ex.Message}");
        }
        finally
        {
            Interlocked.Exchange(ref _pumping, 0);
        }
    }

    private void Prune()
    {
        if (_open.IsEmpty) return;
        var now = DateTime.UtcNow;
        foreach (var kv in _open)
        {
            if (kv.Value <= now) _open.TryRemove(kv.Key, out _);
        }
    }

    /**
     * 没有有效 token 时把摄像头关掉。
     * 只在"从活跃转为空闲"的那一次真正调用 `Close()` ——
     * 每 110ms 无脑关一次虽然幂等，但会把日志刷满，也让"摄像头什么时候被释放"
     * 这件事变得没法从日志上看出来。
     */
    private void ReleaseIfIdle()
    {
        if (!_active) return;
        _active = false;
        _latest = null;
        try
        {
            _engine?.Close();
            Console.WriteLine("[Face] 预览已结束，摄像头已释放");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Face] 释放摄像头失败：{ex.Message}");
        }
    }

    public void Dispose()
    {
        _disposed = true;
        _pump.Dispose();
        ReleaseIfIdle();
    }
}
