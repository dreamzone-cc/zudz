//! جداول المفاتيح والمولدات المعروفة — منقولة حرفياً من ztk/crypto.py

/// مفاتيح ثابتة مرتبطة ببدايات التواقيع
pub const KNOWN_KEYS: &[(&str, &[&str])] = &[
    ("MIK@0STzKpB%qJZe", &["zxhn h118n e"]),
    ("MIK@0STzKpB%qJZf", &["zxhn h118n v"]),
    ("402c38de39bed665", &["zxhn h267a"]),
    ("Q#Zxn*x3kVLc", &["zxhn h168n v2"]),
    ("Wj", &["zxhn h298n"]),
    ("m8@96&ZG3Nm7N&Iz", &["zxhn h298a"]),
    ("GrWM2Hz&LTvz&f^5", &["zxhn h108n"]),
    ("GrWM3Hz&LTvz&f^9", &["zxhn h168n v3", "zxhn h168n h"]),
    ("Renjx%2$CjM", &["zxhn h208n", "zxv10 h201l"]),
    ("tHG@Ti&GVh@ql3XN", &["zxhn h267n"]),
];

pub const KNOWN_SIGNATURES: &[&str] = &["H188A", "H196Q", "H268Q", "H288A", "H298Q", "F6600P"];

pub const KNOWN_KEYPAIR_SUFFIXES: &[(&str, &str)] = &[
    ("", ""),
    ("key", "IV"),
    ("Key02660004", "Iv02660004"),
    ("Key02710001", "Iv02710001"),
    ("Key02710010", "Iv02710010"),
    ("Key02721401", "Iv02721401"),
    ("8cc72b05705d5c46f412af8cbed55aa", "667b02a85c61c786def4521b060265e"),
];

pub const KNOWN_KEYPAIR_PREFIXES: &[(&str, &str)] = &[
    ("", ""),
    ("8cc72b05705d5c46", "667b02a85c61c786"),
    ("8dc79b15726d5c46", "678b02a85c63c786"),
];

/// أزواج ثابتة — F6600P (نوع 5) أولاً كما في الأصل
pub const KNOWN_KEYPAIRS: &[(&str, &str)] = &[
    ("H267AV1_CZkey", "H267AV1_CZIV"),
    ("8cc72b05705d5c46f412af8cbed55aad", "667b02a85c61c786def4521b060265e8"),
    ("8dc79b15726d5c46d412af8cbed65aad", "678b02a85c63c786def4523b061265e8"),
    ("L04&Product@5A238dc79b15726d5c06", "ZTE%FN$GponNJ025678b02a85c63c706"),
    ("f680v9.0", "ZTE%FN$GponNJ025"),
];

pub const KNOWN_PASSWORD_KEYPAIR_SUFFIXES: &[(&str, &str)] = &[("", ""), ("Mcd5c46e", "G21b667b")];

pub const KNOWN_MAC_SERIAL_IVS: &[&str] = &["ZTE%FN$GponNJ025"];

/// أجهزة النوع 3: اسم الطراز يُستخدم مفتاحاً وIV معاً
pub const KNOWN_MODELS: &[&str] = &["H268Q", "H298Q", "H188A", "H288A", "H267AV1_CZ"];

pub const TYPE_3_KNOWN_KEY_IVS: &[(&str, &str)] = &[("H267AV1_CZkey", "H267AV1_CZIV")];

pub const KNOWN_MAC_KEY_SUFFIXES: &[&str] = &["Wj%2$CjM"];

/// يعيد المفتاح الثابت المرتبط بتوقيع (find_key)
pub fn find_key(signature: &str) -> Option<&'static str> {
    let sig = signature.to_ascii_lowercase();
    for (key, sigs) in KNOWN_KEYS {
        for s in *sigs {
            if sig.starts_with(s) {
                return Some(key);
            }
        }
    }
    None
}

/// mac_to_str — تطبيع MAC (بدون فواصل، 12 خانة hex، عكس اختياري)
pub fn mac_to_str(mac: &str, reverse: bool, separator: &str) -> Result<String, String> {
    let m: String = mac.trim().replace([':', '-'], "");
    if m.len() != 12 || !m.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("طول/صيغة MAC غير صحيحة: {mac}"));
    }
    let mut bytes = Vec::with_capacity(6);
    for i in (0..12).step_by(2) {
        bytes.push(u8::from_str_radix(&m[i..i + 2], 16).map_err(|e| e.to_string())?);
    }
    if reverse {
        bytes.reverse();
    }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(separator))
}

/// md5_to_hex — مطابق للأصل: hex(md5(x)) ثم أول 16 محرفاً
pub fn md5_to_hex(x: &str) -> String {
    use md5::{Digest, Md5};
    let d = Md5::digest(x.as_bytes());
    hex::encode(d)[..16].to_string()
}
