//! الفك التلقائي: توليد المرشحات وترتيبها كما في ztk/crypto.py ثم التجربة بالترتيب.

use crate::format::{self, PAYLOAD_MAGIC};
use crate::known::*;
use crate::xcrypt;

#[derive(Debug, Default, Clone)]
pub struct DecryptParams {
    pub signature: Option<String>,
    pub serial: Option<String>,
    pub mac: Option<String>,
    pub password: Option<String>,
    pub key: Option<String>,
    pub iv: Option<String>,
    pub key_prefix: Option<String>,
    pub iv_prefix: Option<String>,
    pub key_suffix: Option<String>,
    pub iv_suffix: Option<String>,
    pub model: Option<String>,
}

fn looks_like_payload(d: &[u8]) -> bool {
    d.len() >= 4 && u32::from_be_bytes(d[0..4].try_into().unwrap()) == PAYLOAD_MAGIC
}

fn looks_like_db(d: &[u8]) -> bool {
    d.starts_with(b"<DB>")
}

/// يولّد المرشحين (key, iv, وصف) بنفس ترتيب الأصل
pub fn candidate_keypairs(p: &DecryptParams, payload_type: u32) -> Vec<(String, Option<String>, &'static str)> {
    let mut pairs: Vec<(String, Option<String>, &'static str)> = Vec::new();

    if let Some(k) = &p.key {
        pairs.push((k.clone(), p.iv.clone(), "explicit key"));
    }

    if payload_type == 3 {
        if let Some(m) = &p.model {
            pairs.push((m.clone(), Some(m.clone()), "model"));
        }
        if let Some(sig) = &p.signature {
            let s = sig.replace(' ', "");
            pairs.push((s.clone(), Some(s), "signature-as-model"));
        }
        for m in KNOWN_MODELS {
            pairs.push(((*m).to_string(), Some((*m).to_string()), "known model"));
        }
        for (k, iv) in TYPE_3_KNOWN_KEY_IVS {
            pairs.push((k.to_string(), Some(iv.to_string()), "type3 static"));
        }
    }

    if let Some(sig) = &p.signature {
        let s = sig.replace(' ', "");
        for (k, iv) in KNOWN_KEYPAIRS {
            pairs.push((k.to_string(), Some(iv.to_string()), "static keypair"));
        }
        for (ks, is) in KNOWN_KEYPAIR_SUFFIXES {
            pairs.push((format!("{s}{ks}"), Some(format!("{s}{is}")), "sig+suffix"));
        }
        if let Some(k) = find_key(sig) {
            pairs.push((k.to_string(), None, "key-for-signature"));
        }
    }

    if let Some(serial) = &p.serial {
        let mut prefixes: Vec<(String, String)> = Vec::new();
        if let (Some(kp), Some(ip)) = (&p.key_prefix, &p.iv_prefix) {
            prefixes.push((kp.clone(), ip.clone()));
        }
        for (kp, ip) in KNOWN_KEYPAIR_PREFIXES {
            prefixes.push((kp.to_string(), ip.to_string()));
        }
        for (kp, ip) in prefixes {
            pairs.push((format!("{kp}{serial}"), Some(format!("{ip}{serial}")), "serial+prefix"));
        }
    }

    if let Some(mac) = &p.mac {
        if let Ok(flat) = mac_to_str(mac, false, "") {
            for suffix in KNOWN_MAC_KEY_SUFFIXES {
                let tail = &flat[6.min(flat.len())..];
                pairs.push((md5_to_hex(&format!("{tail}{suffix}")), None, "mac+suffix"));
            }
        }
    }

    if let (Some(mac), Some(serial)) = (&p.mac, &p.serial) {
        for iv in KNOWN_MAC_SERIAL_IVS {
            for sep in ["", ":"] {
                for rev in [false, true] {
                    if let Ok(m) = mac_to_str(mac, rev, sep) {
                        let mut serials: Vec<String> = vec![serial.clone()];
                        if serial.len() > 4 {
                            serials.push(serial[4..].to_string());
                        }
                        serials.push(serial[serial.len().saturating_sub(8)..].to_string());
                        serials.push(serial[..serial.len().min(8)].to_string());
                        for s in serials {
                            if !s.is_empty() {
                                pairs.push((format!("{s}{m}"), Some(iv.to_string()), "serial+mac"));
                            }
                        }
                    }
                }
            }
        }
        if let Ok(rev_flat) = mac_to_str(mac, true, "") {
            pairs.push((md5_to_hex(&format!("{serial}{rev_flat}")), None, "md5(serial+mac)"));
        }
    }

    if let (Some(mac), Some(serial), Some(password)) = (&p.mac, &p.serial, &p.password) {
        if let Ok(mac_colon) = mac_to_str(mac, false, ":") {
            for (ks, ip) in KNOWN_PASSWORD_KEYPAIR_SUFFIXES {
                pairs.push((
                    format!("{password}{serial}{ks}"),
                    Some(format!("{ip}{mac_colon}{password}")),
                    "password+serial+mac",
                ));
            }
            if let (Some(ks), Some(is)) = (&p.key_suffix, &p.iv_suffix) {
                pairs.push((
                    format!("{password}{serial}{ks}"),
                    Some(format!("{is}{mac_colon}{password}")),
                    "password+serial+mac custom",
                ));
            }
        }
    }

    pairs
}

/// الفك التلقائي الكامل — يعيد (XML، وصف الطريقة).
/// مطابق تفاضلياً لـ crypto.decrypt_file في المرجع البايثوني.
pub fn decrypt_auto(raw: &[u8], params: &DecryptParams) -> Result<(Vec<u8>, String), crate::ZudzCryptoError> {
    let (info, body_offset, payload_type_opt) = format::parse(raw)?;

    // نوع 0 = zlib فقط (بايثون: payload_type == 0 فقط عندما يوجد الماجيك فعلاً)
    if payload_type_opt == Some(0) {
        let xml = xcrypt::decompress_all(&raw[body_offset..]).map_err(crate::ZudzCryptoError::Zlib)?;
        return Ok((xml, "zlib only (type 0)".into()));
    }

    let payload_type = payload_type_opt.unwrap_or(0);
    let mut p = params.clone();
    if p.signature.is_none() {
        p.signature = info.signature.clone();
    }

    // body = payload[60:] عندما توجد ترويسة الحمولة (parse ضبط body_offset بذلك)
    let body = &raw[body_offset.min(raw.len())..];

    for (key, iv, desc) in candidate_keypairs(&p, payload_type) {
        let is_ecb = iv.is_none() && !key.is_empty() && key.len() <= 16 && payload_type == 2;
        let inner = if is_ecb {
            xcrypt::xcryptor_decrypt(body, &key)
        } else {
            let iv_str = iv.clone().unwrap_or_else(|| key.clone());
            xcrypt::cbc_xcryptor_decrypt(body, &key, &iv_str)
        };
        let Some(inner) = inner else { continue };

        if looks_like_payload(&inner) || looks_like_db(&inner) {
            if let Ok(xml) = xcrypt::decompress_all(&inner) {
                let head = &xml[..xml.len().min(100)];
                if xml.first() == Some(&b'<') || head.windows(4).any(|w| w == b"<DB>") {
                    let iv_note = iv.map(|v| format!(" / IV={v}")).unwrap_or_default();
                    return Ok((xml, format!("{desc} → key='{key}'{iv_note} (payload type {payload_type})")));
                }
            }
        }
        if inner.first() == Some(&0x78) {
            if let Ok(xml) = xcrypt::decompress_all(&inner) {
                if xml.first() == Some(&b'<') {
                    let iv_note = iv.map(|v| format!(" / IV={v}")).unwrap_or_default();
                    return Ok((xml, format!("{desc} → key='{key}'{iv_note} (payload type {payload_type})")));
                }
            }
        }
    }

    Err(crate::ZudzCryptoError::NoKeyFound)
}
