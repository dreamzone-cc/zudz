//! تسلسل وضع المصنع الكامل (STEP 0-5) — منقول من onufactory.py

use crate::http::{HttpError, RawHttp};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes192;
use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum FactoryError {
    #[error("STEP{step}: توقّع {expected}، حصلنا {got}")]
    Step { step: u8, expected: &'static str, got: String },
    #[error("STEP2: رد تحدٍّ غير متوقع: {0}")]
    Challenge(String),
    #[error("STEP4: رد غير متوقع بعد الدخول: {0}")]
    AuthResult(String),
    #[error("لم تُستخرج بيانات telnet من الرد: {0}")]
    NoTelnetCreds(String),
    #[error("تعذّر تحديد ماك بطاقة الشبكة الموصلة بالجهاز")]
    LocalMacNotFound,
    #[error(transparent)]
    Http(#[from] HttpError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct UnlockResult {
    pub telnet_user: String,
    pub telnet_pass: String,
    pub aes_key: String,
    pub server_mac: String,
    pub raw: String,
}

fn aes192_ecb_encrypt(key: &[u8; 24], data: &[u8]) -> Vec<u8> {
    let cipher = Aes192::new(key.into());
    let mut out = data.to_vec();
    let pad_len = 16 - out.len() % 16;
    out.extend(std::iter::repeat_n(0u8, pad_len));
    for chunk in out.chunks_exact_mut(16) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    out
}

fn aes192_ecb_decrypt(key: &[u8; 24], data: &[u8]) -> Vec<u8> {
    let cipher = Aes192::new(key.into());
    let mut out = vec![0u8; data.len() + (16 - data.len() % 16) % 16];
    out[..data.len()].copy_from_slice(data);
    for chunk in out.chunks_exact_mut(16) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
    out.truncate(data.len());
    out
}

/// ماك الكرت الموصل بالجهاز (الاكتشاف الحاسم: يُضمَّن في الحمولة بدل السحري)
pub fn get_local_mac() -> Result<[u8; 6], FactoryError> {
    // جرّب الأجهزة السلكية أولاً ثم أي جهاز فيه مسار للشبكة
    let out = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .map_err(|_| FactoryError::LocalMacNotFound)?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut best: Option<[u8; 6]> = None;
    for line in text.lines() {
        let Some(pos) = line.find("ether ") else { continue };
        let mac_str = line[pos + 6..].split_whitespace().next().unwrap_or("").trim();
        let clean: String = mac_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if clean.len() == 12 {
            let mut mac = [0u8; 6];
            let mut ok = true;
            for i in 0..6 {
                mac[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
                    ok = false;
                    0
                });
            }
            if ok && mac != [0; 6] {
                // فضّل غير loopback والماكات الحقيقية (أول 3 بايتات OUI غير صفرية)
                let is_virtual = mac[0] == 0x02 && mac[1] == 0x00; // بعض الوهمية
                if best.is_none() || !is_virtual {
                    best = Some(mac);
                    if !is_virtual && mac[0] != 0 {
                        break;
                    }
                }
            }
        }
    }
    best.ok_or(FactoryError::LocalMacNotFound)
}

/// التنفيذ الكامل: يفتح telnet ويعيد البيانات المؤقتة.
/// user/password = بيانات واجهة الويب (admin/admin افتراضياً على هذه العائلة).
pub fn unlock_telnet(host: &str, user: &str, password: &str) -> Result<UnlockResult, FactoryError> {
    unlock_telnet_with_mac(host, user, password, &get_local_mac()?)
}

pub fn unlock_telnet_with_mac(
    host: &str,
    user: &str,
    password: &str,
    client_mac: &[u8; 6],
) -> Result<UnlockResult, FactoryError> {
    let mut s = RawHttp::new(host, 8);

    // STEP 0 — reset (متوقع 400)
    let r = s.post_text("/webFac", "SendSq.gch")?;
    if r.status != 400 {
        return Err(FactoryError::Step { step: 0, expected: "400", got: r.status.to_string() });
    }

    // STEP 1 — طلب وضع المصنع (متوقع قطع اتصال)
    match s.post_text("/webFac", "RequestFactoryMode.gch") {
        Ok(_) => { /* بعض البرمجيات ترد 200 — نتابع */ }
        Err(HttpError::Disconnected) | Err(HttpError::Io(_)) => {}
    }

    // STEP 2 — التحدّي
    let r = s.post_text("/webFac", "SendSq.gch?rand=0\r\n")?;
    let text = latin1(&r.body);
    let Some(rest) = text.strip_prefix("re_rand=") else {
        return Err(FactoryError::Challenge(text.chars().take(120).collect()));
    };
    let mut it = rest.split('&');
    let server_rand: u64 = it
        .next()
        .unwrap_or("")
        .trim()
        .parse()
        .map_err(|_| FactoryError::Challenge(text.clone()))?;
    let _seed = it.next().unwrap_or("");
    let server_mac_str = it.next().unwrap_or("");
    let server_mac: Vec<u8> = server_mac_str.chars().map(|c| c as u8).collect();

    // STEP 3 — المفتاح والحمولة
    let (key, _index) = crate::derive_aes_key(server_rand);
    let words = crate::payload_words(&server_mac, client_mac);
    let payload = crate::build_payload_str(&words);
    let enc = aes192_ecb_encrypt(&key, &latin1_bytes(&payload));
    let r = s.post_raw("/webFacEntry", &enc)?;
    if r.status != 200 {
        return Err(FactoryError::Step { step: 3, expected: "200", got: r.status.to_string() });
    }

    // STEP 4 — دخول ببيانات الواجهة
    let auth = format!("CheckLoginAuth.gch?version50&user={user}&pass={password}");
    let enc = aes192_ecb_encrypt(&key, &latin1_bytes(&auth));
    let r = s.post_raw("/webFacEntry", &enc)?;
    if r.status != 200 {
        return Err(FactoryError::Step { step: 4, expected: "200", got: r.status.to_string() });
    }
    let res_url = crate::unpad(&aes192_ecb_decrypt(&key, &r.body));
    let expected = b"FactoryMode.gch";
    if res_url != expected.to_vec() && res_url[..res_url.len().min(expected.len())] != expected[..] {
        return Err(FactoryError::AuthResult(hex::encode(&res_url[..res_url.len().min(60)])));
    }

    // STEP 5 — تفعيل ← بيانات telnet
    let fm = "FactoryMode.gch?mode=2&user=notused";
    let enc = aes192_ecb_encrypt(&key, fm.as_bytes());
    let r = s.post_raw("/webFacEntry", &enc)?;
    if r.status != 200 {
        return Err(FactoryError::Step { step: 5, expected: "200", got: r.status.to_string() });
    }
    let dec = aes192_ecb_decrypt(&key, &r.body);
    let dec = trim_zeros(&dec);
    let raw = latin1(&dec);
    let (telnet_user, telnet_pass) = extract_creds(&raw).ok_or_else(|| {
        FactoryError::NoTelnetCreds(raw.chars().take(150).collect())
    })?;

    Ok(UnlockResult {
        telnet_user,
        telnet_pass,
        aes_key: hex::encode(key),
        server_mac: hex::encode(&server_mac),
        raw,
    })
}

fn extract_creds(raw: &str) -> Option<(String, String)> {
    // raw مثل: FactoryModeAuth.gch?user=XXXX&pass=YYYY
    let q = raw.split('?').nth(1)?;
    let mut user = None;
    let mut pass = None;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=')?;
        match k {
            "user" => user = Some(v.to_string()),
            "pass" => pass = Some(v.to_string()),
            _ => {}
        }
    }
    Some((user?, pass?))
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|c| *c as char).collect()
}
fn latin1_bytes(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u32 as u8).collect()
}
fn trim_zeros(mut v: &[u8]) -> &[u8] {
    while let Some((&l, rest)) = v.split_last() {
        if l == 0 {
            v = rest;
        } else {
            break;
        }
    }
    v
}
