//! ZUDZ factory — بروتوكول وضع المصنع لفتح telnet على ZTE F6600P/F6201B+
//!
//! منقول بايت-لمبايت من `zte-toolkit/ztk/onufactory.py` (المسترد أصلاً من تفكيك
//! zteonu3.06). الحقائق المثبتة (v0.2.1):
//! 1) CheckLoginAuth ببيانات واجهة الويب (لا حساب factorymode) — الجهاز يقبلهما.
//! 2) الجهاز يقفل telnet على الماك التشخيصي `00:07:29:55:35:57` — الحمولة تحمله
//!    ويجب أن يحمله كرت الشبكة الفعلي أيضاً (تغييره مؤقت وتلقائي عبر macctl).

pub mod http;
pub mod macctl;
pub mod unlock;
pub mod diagmac;
pub mod session;

pub use unlock::{
    check_diagnostic_mac, get_local_mac, mac_str, nic_mac_towards, unlock_telnet,
    unlock_telnet_quiet, unlock_telnet_with_mac, FactoryError, UnlockResult, DIAGNOSTIC_MAC,
    DIAGNOSTIC_MAC_STR,
};
pub use diagmac::{
    ensure_diag_route, setup_diag_route, remove_diag_route, diag_route_active,
    nic_is_diagnostic, DiagError, DiagMode, DiagRoute, DIAG_MAC, DIAG_IFACE,
};
pub use session::{
    port_open, wait_port_open, save_session, load_session, clear_session, session_path,
};

pub const FACTORY_USER: &str = "factorymode";
pub const FACTORY_PASS: &str = "nE%jA@5b";
/// اسم قديم لـ DIAGNOSTIC_MAC (محفوظ للتوافق)
pub const LOCAL_MAC: [u8; 6] = DIAGNOSTIC_MAC;

/// KEY_POOL — 96 بايت (مستردة من تفكيك محرك بايثون في zteonu3.06_all_en.exe)
pub const KEY_POOL: [u8; 96] = [
    156, 51, 117, 209, 28, 66, 69, 55, 24, 72, 145, 115, 23, 69, 121, 68,
    67, 215, 213, 115, 51, 84, 118, 210, 197, 241, 44, 79, 122, 186, 97, 217,
    92, 105, 223, 140, 210, 28, 222, 59, 53, 45, 47, 225, 222, 76, 119, 245,
    26, 101, 209, 254, 24, 67, 142, 167, 66, 8, 4, 120, 213, 228, 243, 52,
    164, 211, 242, 54, 71, 109, 134, 157, 66, 101, 19, 66, 220, 66, 153, 72,
    220, 103, 159, 158, 220, 70, 55, 95, 132, 159, 111, 118, 206, 121, 79, 73,
];

/// مجمّع محرك Go بدون --new (zteonu06.exe @ 0xb946c0) — احتياطي عند قطع SendInfo
pub const KEY_POOL_GO_OLD: [u8; 96] = [
    123, 86, 176, 247, 218, 14, 104, 82, 200, 25, 243, 43, 132, 144, 121, 229,
    98, 248, 234, 210, 100, 147, 135, 223, 115, 215, 251, 204, 170, 254, 117, 67,
    28, 41, 223, 76, 82, 44, 110, 123, 69, 61, 31, 241, 222, 188, 39, 133,
    138, 69, 145, 190, 56, 19, 222, 103, 50, 8, 84, 17, 117, 244, 211, 180,
    164, 179, 18, 134, 103, 35, 153, 76, 97, 127, 177, 210, 48, 223, 71, 241,
    118, 147, 163, 140, 149, 211, 89, 191, 135, 142, 243, 179, 228, 118, 73, 136,
];

/// مجمّع محرك Go مع --new (zteonu06.exe @ 0xb94720) — احتياطي عند قطع SendInfo
pub const KEY_POOL_GO_NEW: [u8; 96] = [
    140, 35, 101, 209, 252, 50, 69, 55, 17, 40, 113, 99, 7, 32, 105, 20,
    115, 231, 212, 83, 19, 36, 54, 194, 181, 225, 252, 207, 138, 154, 65, 137,
    60, 73, 207, 92, 114, 140, 158, 235, 117, 13, 63, 209, 254, 204, 87, 101,
    122, 53, 33, 62, 104, 83, 126, 151, 2, 72, 116, 113, 149, 52, 83, 132,
    180, 195, 226, 214, 39, 61, 230, 93, 114, 156, 188, 61, 3, 253, 118, 193,
    156, 37, 168, 146, 71, 228, 24, 15, 36, 63, 79, 103, 236, 151, 244, 153,
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
    fn diagnostic_mac_parsers_and_gate() {
        use crate::unlock::{mac_str, parse_link_mac, parse_route_dev, DIAGNOSTIC_MAC, DIAGNOSTIC_MAC_STR};

        // الثابت يطابق أداة zteonu الأصلية (نفس القيمة في ثنائية zteonu ووثائقها)
        assert_eq!(mac_str(&DIAGNOSTIC_MAC), DIAGNOSTIC_MAC_STR);
        assert_eq!(DIAGNOSTIC_MAC_STR, "00:07:29:55:35:57");

        // محلل مسار التوجيه
        assert_eq!(
            parse_route_dev("192.168.1.1 dev enp3s0 src 192.168.1.10 uid 1000"),
            Some("enp3s0".into())
        );
        assert_eq!(parse_route_dev("192.168.1.1 via 192.168.1.254 dev eth0 src 192.168.1.5"), Some("eth0".into()));
        assert_eq!(parse_route_dev("garbage without dev"), None);

        // محلل MAC من ip link
        assert_eq!(
            parse_link_mac("2: enp3s0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 link/ether 14:ca:56:dd:73:9f permaddr aa:bb:cc:dd:ee:ff"),
            Some([0x14, 0xca, 0x56, 0xdd, 0x73, 0x9f])
        );
        // يلتقط أول link/ether (permaddr يُتجاهل)
        assert_eq!(parse_link_mac("link/ether 00:07:29:55:35:57"), Some(DIAGNOSTIC_MAC));
        assert_eq!(parse_link_mac("no mac here"), None);
        assert_eq!(parse_link_mac("link/ether 00:07"), None);
    }

    #[test]
    fn key_pools_three_distinct_fallbacks() {
        // المجمّعات الاحتياطية من محرك Go (مستردة من ثنائية zteonu06.exe)
        assert_eq!(KEY_POOL.len(), 96);
        assert_eq!(KEY_POOL_GO_OLD.len(), 96);
        assert_eq!(KEY_POOL_GO_NEW.len(), 96);
        assert_ne!(KEY_POOL, KEY_POOL_GO_OLD);
        assert_ne!(KEY_POOL, KEY_POOL_GO_NEW);
        assert_ne!(KEY_POOL_GO_OLD, KEY_POOL_GO_NEW);
        // الاشتقاق من كل مجمّع يعطي مفاتيح مختلفة لنفس التحدّي
        let (k1, i) = crate::unlock::derive_key_from_pool_pub(&KEY_POOL, 28);
        let (k2, _) = crate::unlock::derive_key_from_pool_pub(&KEY_POOL_GO_NEW, 28);
        let (k3, _) = crate::unlock::derive_key_from_pool_pub(&KEY_POOL_GO_OLD, 28);
        assert_eq!(i, 28);
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        // والمجمّع الأساسي يطابق متجه الجلسة الحية الموثّق
        assert_eq!(hex::encode(k1), "df1fc47cf9cc7a2977b97b9e90888a447be9d250bfc0745b");
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
