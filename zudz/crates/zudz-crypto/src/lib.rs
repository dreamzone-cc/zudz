//! ZUDZ crypto — فك تشفير ملفات إعدادات ZTE (config.bin / db_user_cfg.xml)
//!
//! منقول بايت-لمبايت من المرجع البايثوني `zte-toolkit/ztk/crypto.py` (المبني على
//! zte-config-utility v0.5.3 MIT). كل الثوابت والترتيب مطابقان للأصل لضمان
//! التطابق التفاضلي مع الـoracle.

pub mod known;
pub mod xcrypt;
pub mod format;
pub mod auto;
pub mod encrypasswd;

pub use auto::{decrypt_auto, DecryptParams};
pub use encrypasswd::decrypt_encrypasswd;
pub use format::{inspect, inspect_bytes};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZudzCryptoError {
    #[error("ملف بترميز base64 — فك الترميز أولاً")]
    Base64File,
    #[error("قيمة ترويسة غير متوقعة: 0x{0:X}")]
    BadHeader(u32),
    #[error("الملف صغير جداً أو تالف")]
    TooShort,
    #[error("تعذّر فك التشفير بكل المفاتيح المعروفة — جرّب --mac/--serial/--password")]
    NoKeyFound,
    #[error("خطو فك ضغط zlib: {0}")]
    Zlib(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
