namespace AuthServer.Models;

public class ApiResponse<T>
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public T? Data { get; set; }

    /// <summary>
    /// 抹掉泛型参数、只留"成功 / 码 / 话术"的视图。
    ///
    /// 给"只关心做没做成"的调用方用（批量处置汇总每条结果时就是这种）。
    /// 刻意**不做继承**：两个类并存是为了让 Data 的静态类型在编译期就分开，
    /// 改成继承会让既有接口的响应契约跟着变 —— 而那是不该为了少写三行而付的代价。
    /// </summary>
    public ApiResponse ToBase() => new()
    {
        Success = Success,
        Message = Message,
        Code = Code,
        Data = Data
    };
}

public class ApiResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public object? Data { get; set; }
}
