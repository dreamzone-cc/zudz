//! TagParams — تحليل مخرجات setmac show2 وتحويل السيريالات
//! منقول من ztk/tagparams.py

use regex::Regex;
use std::collections::BTreeMap;

/// خريطة أسماء المعرفات المعروفة
pub fn tag_name(id: u32) -> &'static str {
    match id {
        1 => "device base MAC",
        256..=263 => "additional MAC",
        512 => "device serial (label)",
        768 => "OUI",
        1024..=1031 => "default SSID",
        1296..=1331 => "default PSK/WEP key",
        1537 => "web username (user)",
        1538 => "web username (admin)",
        1793 => "web password (user)",
        1794 => "web password (admin)",
        2176 => "GPON SN VID (first 4 chars)",
        2177 => "GPON SN last 8 hex",
        2178 => "GPON PLOAM password",
        2181 => "GPON PLOAM password (copy)",
        2182 => "EPON SN",
        2186 => "GPONPWD flag",
        2187 => "GPON hex password",
        32768 => "PON MAC",
        32769 => "PON MAC (2)",
        32770 => "Equipment ID",
        36864 => "software version",
        40960 => "WAN type",
        _ => "unknown",
    }
}

/// يحلل مخرجات setmac show2 → {id: value}
/// منقول بمنطق المرجع (نمطا الأسطر + الاستثناءات).
pub fn parse_show2(text: &str) -> BTreeMap<u32, String> {
    let mut out = BTreeMap::new();
    let re_kv = Regex::new(
        r"^\s*(?:No\.?\s*)?(\d{1,6})\s*[:=]\s*(?:0x)?([0-9A-Za-z@#\$\*\.:\- ]+?)\s*$",
    )
    .unwrap();
    let re_gap = Regex::new(r"^\s*(\d{1,6})\s{2,}(\S.*)$").unwrap();

    // نمط ZTE الفعلي: "   NAME[ID:  2177] is set to VALUE"
    let re_set = Regex::new(
        r"^\s*\w[\w ]*\[ID:\s*(\d{1,6})\]\s+is set to\s+(.+?)\s*$",
    )
    .unwrap();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("login") || lower.starts_with("password") || lower.starts_with("f6") {
            continue;
        }
        if let Some(c) = re_set.captures(line) {
            let id: u32 = c[1].parse().unwrap_or(0);
            let val = c[2].trim().trim_matches('"').to_string();
            if id > 0 && !val.is_empty() {
                out.insert(id, val);
                continue;
            }
        }
        if let Some(c) = re_kv.captures(line) {
            let id: u32 = c[1].parse().unwrap_or(0);
            let val = c[2].trim().trim_end_matches(',').to_string();
            let bad = val.eq_ignore_ascii_case("show2") || val.eq_ignore_ascii_case("setmac")
                || (val.contains(' ') && val.len() > 40);
            if id > 0 && !bad && !val.is_empty() {
                out.insert(id, val);
            }
            continue;
        }
        if let Some(c) = re_gap.captures(line) {
            let id: u32 = c[1].parse().unwrap_or(0);
            let val = c[2].trim().to_string();
            if id > 0 && !val.is_empty() {
                out.insert(id, val);
            }
        }
    }
    out
}

/// يشتق مكونات GPON SN من السيريال المطبوع (مع تحذير إن لم يكن hex صافياً)
pub fn gpon_sn_from_label(serial: &str) -> (String, String, Option<String>) {
    let s = serial.trim().to_ascii_uppercase();
    let s = s.split('-').next_back().unwrap_or(&s).to_string();
    if s.len() < 8 {
        return (s.clone(), String::new(), Some("serial too short".into()));
    }
    let vid = s[..4].to_string();
    let rest = &s[4..];
    // ابحث من اليمين عن نافذة 8 خانات hex صافية
    let mut sn8 = String::new();
    let mut note = None;
    for i in (1..=rest.len()).rev() {
        let start = i.saturating_sub(8);
        let chunk = &rest[start..i];
        if chunk.len() == 8 && chunk.chars().all(|c| c.is_ascii_hexdigit()) {
            sn8 = chunk.to_string();
            break;
        }
    }
    if sn8.is_empty() {
        sn8 = rest[rest.len().saturating_sub(8)..].to_string();
        note = Some("آخر 8 محارف ليست hex صافياً — تحقق عبر setmac 2 2177".into());
    }
    (vid, sn8, note)
}
