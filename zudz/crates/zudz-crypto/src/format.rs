//! تحليل بنية ملفات إعدادات ZTE (ترويسة/توقيع/نوع حمولة)

pub const PAYLOAD_MAGIC: u32 = 0x0102_0304;
pub const SIGNATURE_MAGIC: u32 = 0x0403_0201;
pub const ZTE_MAGIC: [u32; 4] = [0x9999_9999, 0x4444_4444, 0x5555_5555, 0xAAAA_AAAA];

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub signature: Option<String>,
    pub payload_type: Option<u32>,
    pub has_zte_header: bool,
}

/// يفكك بنية الملف: ترويسة ZTE الكاملة (اختيارية) + التوقيع + نوع الحمولة.
/// يعيد (معلومات، إزاحة الجسم، نوع الحمولة كـOption — None عند غياب الماجيك).
pub fn parse(raw: &[u8]) -> Result<(FileInfo, usize, Option<u32>), crate::ZudzCryptoError> {
    if raw.starts_with(b"BAMC") {
        return Err(crate::ZudzCryptoError::Base64File);
    }
    let mut info = FileInfo { signature: None, payload_type: None, has_zte_header: false };
    let mut pos = 0usize;

    if raw.len() >= 16 {
        let mut m = [0u32; 4];
        for i in 0..4 {
            m[i] = u32::from_be_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap());
        }
        if m == ZTE_MAGIC {
            info.has_zte_header = true;
            if raw.len() < 128 {
                return Err(crate::ZudzCryptoError::TooShort);
            }
            let h2 = u32::from_be_bytes(raw[16 + 8..16 + 12].try_into().unwrap());
            if h2 != 4 {
                return Err(crate::ZudzCryptoError::BadHeader(h2));
            }
            pos = 128;
        }
    }

    // توقيع الجهاز
    if raw.len() >= pos + 12 {
        let magic = u32::from_be_bytes(raw[pos..pos + 4].try_into().unwrap());
        if magic == SIGNATURE_MAGIC {
            let sig_len = u32::from_be_bytes(raw[pos + 8..pos + 12].try_into().unwrap()) as usize;
            if pos + 12 + sig_len <= raw.len() {
                info.signature =
                    Some(String::from_utf8_lossy(&raw[pos + 12..pos + 12 + sig_len]).into_owned());
                pos += 12 + sig_len;
            }
        }
    }

    if raw.len() < pos + 8 {
        return Err(crate::ZudzCryptoError::TooShort);
    }
    let pm = u32::from_be_bytes(raw[pos..pos + 4].try_into().unwrap());
    let mut body_offset = pos;
    if pm == PAYLOAD_MAGIC {
        info.payload_type =
            Some(u32::from_be_bytes(raw[pos + 4..pos + 8].try_into().unwrap()));
        body_offset = pos + 60; // ترويسة الحمولة 60 بايت
    }
    let payload_type = info.payload_type;
    Ok((info, body_offset, payload_type))
}

/// inspect_file المكافئ للبايثون
pub fn inspect(path: &str) -> Result<FileInfo, crate::ZudzCryptoError> {
    let raw = std::fs::read(path)?;
    let (info, _, _) = parse(&raw)?;
    Ok(info)
}

/// فحص من محتوى البايتات مباشرة (للملفات القادمة من المتصفح)
pub fn inspect_bytes(raw: &[u8]) -> Result<FileInfo, crate::ZudzCryptoError> {
    let (info, _, _) = parse(raw)?;
    Ok(info)
}
