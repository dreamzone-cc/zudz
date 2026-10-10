//! فك encrypasswd الخاص بـpppd (passpppoe.so)
//!
//! الخوارزمية (مجرّبة على الجهاز الحي): AES-256-ECB بالمفتاح
//! SHA256("608158c36497b00221db14afb845c9e3") — السلسلة مضمّنة في /lib/passpppoe.so.
//! مثال مؤكد: 6575d558d478c6af58c17815250fdaee → "12345678"

use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
use sha2::{Digest, Sha256};

pub const PASSPPPOE_KEY_STRING: &str = "608158c36497b00221db14afb845c9e3";

/// يفك كلمة مرور pppd من encrypasswd (hex). يعيد النص الصريح بدون حشو الأصفار.
pub fn decrypt_encrypasswd(hex_passwd: &str) -> Result<String, String> {
    let ct = hex::decode(hex_passwd.trim()).map_err(|e| format!("hex غير صالح: {e}"))?;
    decrypt_encrypasswd_bytes(&ct)
}

pub fn decrypt_encrypasswd_bytes(ct: &[u8]) -> Result<String, String> {
    if ct.is_empty() || ct.len() % 16 != 0 {
        return Err("طول encrypasswd يجب أن يكون مضاعفاً لـ16".into());
    }
    let key: [u8; 32] = Sha256::digest(PASSPPPOE_KEY_STRING.as_bytes()).into();
    let cipher = Aes256::new(&key.into());
    let mut out = Vec::with_capacity(ct.len());
    for block in ct.chunks_exact(16) {
        let mut g = aes::cipher::generic_array::GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut g);
        out.extend_from_slice(&g);
    }
    while out.last() == Some(&0) {
        out.pop();
    }
    String::from_utf8(out).map_err(|e| format!("الناتج ليس UTF-8: {e}"))
}
