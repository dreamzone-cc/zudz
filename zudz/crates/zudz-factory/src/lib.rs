//! ZUDZ factory — بروتوكول وضع المصنع لفتح telnet على ZTE F6600P/F6201B+
//!
//! منقول بايت-لمبايت من `zte-toolkit/ztk/onufactory.py` (المسترد أصلاً من تفكيك
//! zteonu3.06). الاكتشافان الحاسمان مضمّنان:
//! 1) CheckLoginAuth ببيانات واجهة الويب (لا حساب factorymode).
//! 2) ماك الحمولة = ماك الإطار الفعلي (get_local_mac) — لا حاجة لتغيير MAC.

pub mod http;
pub mod unlock;

pub use unlock::{get_local_mac, unlock_telnet, FactoryError, UnlockResult};

pub const FACTORY_USER: &str = "factorymode";
pub const FACTORY_PASS: &str = "nE%jA@5b";
/// الماك التشخيصي السحري (مسار احتياطي فقط — يتطلب تغيير ماك الكرت إليه)
pub const LOCAL_MAC: [u8; 6] = [0x00, 0x07, 0x29, 0x55, 0x35, 0x57];

/// KEY_POOL — 96 بايت (مستردة من تفكيك محرك بايثون في zteonu3.06_all_en.exe)
pub const KEY_POOL: [u8; 96] = [
    156, 51, 117, 209, 28, 66, 69, 55, 24, 72, 145, 115, 23, 69, 121, 68,
    67, 215, 213, 115, 51, 84, 118, 210, 197, 241, 44, 79, 122, 186, 97, 217,
    92, 105, 223, 140, 210, 28, 222, 59, 53, 45, 47, 225, 222, 76, 119, 245,
    26, 101, 209, 254, 24, 67, 142, 167, 66, 8, 4, 120, 213, 228, 243, 52,
    164, 211, 242, 54, 71, 109, 134, 157, 66, 101, 19, 66, 220, 66, 153, 72,
    220, 103, 159, 158, 220, 70, 55, 95, 132, 159, 111, 118, 206, 121, 79, 73,
];

pub const FNV_MULT: u64 = 16_777_619;
pub const MASK: u64 = 2_147_483_711; // 0x8000003F
pub const MODULUS: u64 = 30_049;
pub const EXPONENT: u64 = 5_767;

/// اشتقاق مفتاح AES-192 من server_rand (client_rand=0 دائماً)
pub fn derive_aes_key(server_rand: u64) -> ([u8; 24], u64) {
    let index = ((0u64 & MASK) ^ server_rand) % 60;
    let mut key = [0u8; 24];
    for i in 0..24 {
        key[i] = KEY_POOL[index as usize + i] ^ 0xA5;
    }
    (key, index)
}

fn modpow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result: u64 = 1;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exp >>= 1;
    }
    result
}

/// مصفوفة الحمولة: [0, 1, 0, pow(5767,5767,30049)] + srv_mac + client_mac×2
pub fn payload_words(server_mac: &[u8], client_mac: &[u8]) -> Vec<u32> {
    let mut words = vec![0u32, 1, 0, modpow(EXPONENT, EXPONENT, MODULUS) as u32];
    words.extend(server_mac.iter().map(|b| *b as u32));
    words.extend(client_mac.iter().map(|b| *b as u32));
    words.extend(client_mac.iter().map(|b| *b as u32));
    words
}

/// نص الحمولة: "SendInfo.gch?info={n}|" + كل قيمة 4 بايت little-endian (latin-1)
pub fn build_payload_str(words: &[u32]) -> String {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    format!("SendInfo.gch?info={}|{}", words.len(), String::from_latin1(&bytes))
}

/// حشو أصفار إلى مضاعف 16 (يضيف كتلة كاملة عند التساوي — كما في الأصل)
pub fn pad(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let pad_len = 16 - data.len() % 16;
    out.extend(std::iter::repeat_n(0u8, pad_len));
    out
}

pub fn unpad(data: &[u8]) -> Vec<u8> {
    if data.len() < 16 {
        return data.to_vec();
    }
    let (head, tail) = data.split_at(data.len() - 16);
    let mut result = head.to_vec();
    result.extend_from_slice(trim_trailing_zeros(tail));
    result
}

fn trim_trailing_zeros(mut s: &[u8]) -> &[u8] {
    while let Some((&last, rest)) = s.split_last() {
        if last == 0 {
            s = rest;
        } else {
            break;
        }
    }
    s
}

trait Latin1Ext {
    fn from_latin1(bytes: &[u8]) -> String;
}
impl Latin1Ext for String {
    fn from_latin1(bytes: &[u8]) -> String {
        bytes.iter().map(|b| *b as char).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_derivation_live_vector() {
        // متجه من جلسة حية: server_rand=28
        let (key, idx) = derive_aes_key(28);
        assert_eq!(idx, 28);
        assert_eq!(hex::encode(key), "df1fc47cf9cc7a2977b97b9e90888a447be9d250bfc0745b");
        let (key2, _) = derive_aes_key(32);
        assert_eq!(hex::encode(key2), "f9cc7a2977b97b9e90888a447be9d250bfc0745bbde62b02");
    }

    #[test]
    fn payload_words_shape() {
        let w = payload_words(&[1; 6], &[2; 6]);
        assert_eq!(w.len(), 4 + 18);
        assert_eq!(w[0], 0);
        assert_eq!(w[1], 1);
        assert_eq!(w[3], modpow(5767, 5767, 30049) as u32);
    }

    #[test]
    fn pad_unpad_roundtrip() {
        // FactoryMode.gch = 15 محرفاً + \0 = 16 بايت
        let data = b"FactoryMode.gch\0";
        assert_eq!(data.len(), 16);
        let padded = pad(data); // pad يضيف كتلة كاملة عند التساوي (سلوك الأصل)
        assert_eq!(padded.len(), 32);
        // unpad: head(16) + last_block.rstrip(zeros) = البيانات الأصلية
        assert_eq!(unpad(&padded), data.to_vec());
        // حالة STEP4 الفعلية من الجهاز: النتيجة تُقارن بـ rstrip إضافي في التدفق
        assert_eq!(unpad(&padded), b"FactoryMode.gch\0".to_vec());
    }
}
