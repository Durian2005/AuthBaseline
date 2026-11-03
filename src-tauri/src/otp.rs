//! 一次性口令（哈希链）的**客户端计算**。
//!
//! 放在 Rust 侧而不是 JS 侧，理由只有三条，但都不是风格问题：
//!
//!   ① **口令的暴露面**：口令本来就要经过 DOM（用户敲进去的），这一点无法改变；
//!      但「用完即擦」这件事 JS 做不到 —— `String` 不可变，擦不掉，只能等 GC。
//!      这里用 `Zeroizing` 包住口令与链根，函数返回时立刻覆写。
//!   ② **计算本身**：PBKDF2-HMACSHA256 100k 次 + 1000 次 SHA-256 是纯 CPU 活。
//!      放在 IPC 另一侧，Vue 的渲染线程完全不受影响（否则登录时界面会卡一下）。
//!   ③ **实现只有一份**：链的派生方向、盐编码、迭代顺序只要有一处不一致，
//!      症状是「口令明明对却登不上」，而且**永远不会报错**。集中到一处才好钉住。
//!
//! ⚠️ 与 C# 侧（`AuthServer/Services/Otp/OtpVerifier.cs`）必须**逐字节一致**：
//!      · 盐 = `Encoding.UTF8.GetBytes(r)`（r 是 ASCII 的 Base32，所以等价于 `r.as_bytes()`）；
//!      · PBKDF2-HMACSHA256，输出 32 字节；
//!      · `x_i = SHA256(x_{i-1})`，对**原始 32 字节**做，不做十六进制编码；
//!      · 输出用标准 Base64（带 `=` 填充）。
//!   这四条任何一个不同，服务端就只会回「口令错」。所以下面有跨实现的固定向量单测。

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use pbkdf2::pbkdf2_hmac;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::Instant;
use zeroize::Zeroizing;

/// 链格字节数。SHA-256 输出 32 字节，PBKDF2 也取 32 字节，全链同宽。
const ROOT_LEN: usize = 32;

/// 新链种子的字节数（与服务端 `OtpChainStore.NewSeed` 一致：20 字节 → 32 位 Base32）。
const SEED_BYTES: usize = 20;

/// RFC 4648 Base32 字母表（大写、无填充）。与服务端 `Base32Alphabet` 逐字一致。
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 迭代次数的上界。**不是安全阈值，是防呆**：这个值来自服务端响应，
/// 若某天它被配成 2^31，客户端会当场卡死几十秒而用户只看到「没反应」。
const MAX_ITERATIONS: u32 = 10_000_000;

/// 链长上界，同上。
const MAX_LENGTH: i32 = 1_000_000;

/// 计算结果。字段名用 camelCase 直接下发，前端不需要再改名。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtpComputed {
    /// 本次应提交的格 `x_k`（标准 Base64）。
    pub code: String,

    /// 续期用的新种子（Base32）。`renew=false` 时为 `None`。
    pub next_r: Option<String>,

    /// 续期用的新链头 `x_N`（标准 Base64，用**新种子**派生）。`renew=false` 时为 `None`。
    pub next_head: Option<String>,

    /// 本次计算耗时（毫秒）。给「登录耗时增量」这条判据留证，不参与任何判定。
    pub elapsed_ms: f64,
}

/// 算一格链值（可选地顺带算一条新链）。
///
/// `k` 与 `n` 都由服务端在挑战里给出，**客户端不得自行推断**：
/// 本地猜的 `k` 只会得到一个必然被拒的值，而失败会计入登录失败次数。
#[tauri::command]
pub fn otp_compute(
    password: String,
    r: String,
    k: i32,
    n: i32,
    iterations: u32,
    renew: bool,
) -> Result<OtpComputed, String> {
    let started = Instant::now();

    // ── 入参校验：全部在**开始算之前**做完 ──
    // 这些错误的共同点是「算下去也能算出一个值」，只是那个值一定是错的；
    // 与其让它走到服务端变成一个被计次的失败，不如在这里就拒掉。
    if password.is_empty() {
        return Err("口令不能为空".into());
    }
    if r.len() != 32 || !r.bytes().all(|b| BASE32_ALPHABET.contains(&b)) {
        return Err("链种子必须是 32 位 Base32 字符".into());
    }
    if n < 2 || n > MAX_LENGTH {
        return Err(format!("链长超出范围：{n}"));
    }
    if k < 0 || k >= n {
        return Err(format!("链下标 {k} 不在 [0, {}) 内", n));
    }
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err(format!("PBKDF2 迭代次数超出范围：{iterations}"));
    }

    // 口令从这一刻起被 `Zeroizing` 接管，函数返回（含提前 return 与 panic）时会被覆写。
    let password = Zeroizing::new(password);

    // ── ① x_0 = PBKDF2(password, salt = UTF8(r)) ──
    let mut root = Zeroizing::new([0u8; ROOT_LEN]);
    pbkdf2_hmac::<Sha256>(password.as_bytes(), r.as_bytes(), iterations, &mut *root);

    // ── ② 走到 x_k ──
    let code = B64.encode(iter_once(&root, k as u32).as_ref());

    // ── ③ 续期：新种子 + 用新种子重算整条链头 ──
    // 只有在服务端判定「该续期」时才算。这一段是一次**额外的**完整派生（约与 ① 同价），
    // 所以绝不能无条件执行 —— 那会让每次登录都多付一次 PBKDF2。
    let mut next_r = None;
    let mut next_head = None;
    if renew {
        let seed = new_seed()?;

        let mut next_root = Zeroizing::new([0u8; ROOT_LEN]);
        pbkdf2_hmac::<Sha256>(password.as_bytes(), seed.as_bytes(), iterations, &mut *next_root);

        next_head = Some(B64.encode(iter_once(&next_root, n as u32).as_ref()));
        next_r = Some(seed);
    }

    Ok(OtpComputed {
        code,
        next_r,
        next_head,
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
    })
}

/// 从链根往下走 `times` 步，返回 `x_times`。`times = 0` 时就是链根本身。
///
/// 全过程在同一个 `Zeroizing` 缓冲里就地覆写：不额外分配，也不会在堆上留下
/// 一串「中间格」（那些中间值同样是可用凭据 —— 拿到 `x_j`（`j > k`）就等于拿到了未来的配额）。
fn iter_once(root: &[u8; ROOT_LEN], times: u32) -> Zeroizing<[u8; ROOT_LEN]> {
    let mut cur = Zeroizing::new(*root);
    for _ in 0..times {
        let digest = Sha256::digest(&cur[..]);
        cur.copy_from_slice(&digest);
    }
    cur
}

/// 生成一条新链的种子：20 字节 CSPRNG → 32 位 Base32。
///
/// 与服务端 `NewSeed()` 的形状逐字一致（同字节数、同字母表、同无填充），
/// 这样服务端那条「32 位 Base32」的形状校验对两边是同一个标准。
fn new_seed() -> Result<String, String> {
    let mut bytes = Zeroizing::new([0u8; SEED_BYTES]);
    getrandom::getrandom(&mut *bytes).map_err(|e| format!("系统随机源不可用：{e}"))?;
    Ok(to_base32(&bytes[..]))
}

/// RFC 4648 Base32（大写、无填充）。
///
/// 手写而不是引第三方 crate：只有 20 字节定长输入这一种用法，
/// 引一个通用实现反而要额外核对它的填充与大小写策略是否与 C# 侧一致。
fn to_base32(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for &b in data {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_ALPHABET[((buffer >> bits) & 0x1F) as usize] as char);
        }
    }
    // 20 字节是 5 的整数倍（160 bit / 5 = 32 字符），实际走不到这里；
    // 保留是为了这个函数对任意长度都成立，而不是只对当前这一个输入成立。
    if bits > 0 {
        out.push(BASE32_ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与 C# / Python 三方对齐的固定向量。
    ///
    /// 期望值由 Python 的 `hashlib.pbkdf2_hmac('sha256', ...)` + `hashlib.sha256` 独立算出，
    /// 而 C# 侧早已由 `tools/otp_p2_probe.py` 证明与之逐字节一致。
    /// 于是这一条断言同时钉住了三件事：盐的编码、迭代方向、Base64 形式。
    #[test]
    fn crosses_with_python_and_csharp() {
        let pw = "Abc12345";
        let r = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

        let cases: [(i32, &str); 4] = [
            (0, "jNHDM5aTfPGskb3mPUVcXVWsz5OeY0COtUPriasmLfg="),
            (1, "vUlbOAupl37jxvhaHm4VQByeYeBFYkeCurUezlPjOnc="),
            (7, "vV07fN0wIGOhaIScqvOTfm4ZsKBoXH8tXs6rOqy3YuA="),
            (999, "Rh4BQIshXpb/YkHZcAkWN7bGlx5moENNJbeFpC/7Td8="),
        ];

        for (k, expected) in cases {
            let got = otp_compute(pw.into(), r.into(), k, 1000, 1000, false).unwrap();
            assert_eq!(got.code, expected, "k={k} 与 Python 复算不一致");
            assert!(got.next_r.is_none() && got.next_head.is_none());
        }
    }

    /// 续期路径：新种子形状正确，且新链头确实等于「用新种子重算的 x_N」。
    #[test]
    fn renew_produces_usable_pair() {
        let pw = "Abc12345";
        let r = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

        let out = otp_compute(pw.into(), r.into(), 40, 1000, 1000, true).unwrap();
        let next_r = out.next_r.expect("该续期时必须给新种子");
        let next_head = out.next_head.expect("该续期时必须给新链头");

        assert_eq!(next_r.len(), 32);
        assert!(next_r.bytes().all(|b| BASE32_ALPHABET.contains(&b)));
        assert_ne!(next_r, r, "新种子必须换一个（否则等于没换盐）");

        // 用返回的新种子重新算「第 N 格」，应当与返回的链头逐字节相等。
        //
        // 为什么这里传 n=1001：`k` 必须严格小于 `n`（下标越界会被拒），而我们要的是 x_1000。
        // 把 `n` 说大一点不影响计算（`n` 只参与校验、不参与派生），
        // 于是这一行同时验证了「链头确实由新种子派生」与「n 不参与派生」两件事。
        let again = otp_compute(pw.into(), next_r, 1000, 1001, 1000, false).unwrap();
        assert_eq!(again.code, next_head, "新链头与用新种子重算的 x_N 不连续");
    }

    /// 两次调用给出的新种子必须不同（CSPRNG 而不是常量或时间派生）。
    #[test]
    fn renew_seed_is_random() {
        let r = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        let a = otp_compute("p".into(), r.into(), 1, 10, 10, true).unwrap();
        let b = otp_compute("p".into(), r.into(), 1, 10, 10, true).unwrap();
        assert_ne!(a.next_r, b.next_r);
    }

    /// 入参校验：这些值「算下去也不报错，只是结果必然被服务端拒」，所以必须提前挡。
    #[test]
    fn rejects_out_of_range_inputs() {
        let r = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        assert!(otp_compute("".into(), r.into(), 0, 10, 10, false).is_err(), "空口令");
        assert!(otp_compute("p".into(), "SHORT".into(), 0, 10, 10, false).is_err(), "种子长度");
        assert!(otp_compute("p".into(), r.into(), -1, 10, 10, false).is_err(), "负下标");
        assert!(otp_compute("p".into(), r.into(), 10, 10, 10, false).is_err(), "下标越界");
        assert!(otp_compute("p".into(), r.into(), 0, 10, 0, false).is_err(), "零迭代");
    }

    /// Base32：20 字节必须正好 32 字符，且只用字母表内的字符。
    #[test]
    fn base32_shape() {
        let encoded = to_base32(&[0xFFu8; 20]);
        assert_eq!(encoded.len(), 32);
        assert!(encoded.bytes().all(|b| BASE32_ALPHABET.contains(&b)));
        assert_eq!(&encoded[..4], "7777", "全 1 的每 5 bit 都是 31");
    }

    /// 耗时判据（§7 验收）的取证：**单跑一次**，用 `--release --nocapture` 看数值。
    ///
    /// 不加断言阈值：CI 机器负载不可控，把耗时写成断言只会得到一条随机失败的用例。
    /// 真正的判据是端到端登录耗时（见 `tools/otp_p7_probe.py`），这里只给出算法自身的成本。
    #[test]
    fn timing_report() {
        let r = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        let out = otp_compute("Abc12345".into(), r.into(), 999, 1000, 100_000, true).unwrap();
        println!(
            "[timing] PBKDF2 100k + H^999 + 续期一条新链 = {:.1} ms",
            out.elapsed_ms
        );
    }
}
