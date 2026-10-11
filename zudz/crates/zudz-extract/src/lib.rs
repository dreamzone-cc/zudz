//! extract_all — الاستخراج الموحد بالمسارات الأربعة (A/C/D) وتوليد التقرير.
//! المسار A: عمليات حية (خيارات pppd + ذاكرة cspd المشتركة)
//! المسار C: واجهة LUA (غير دخولي — إثراء)
//! المسار D: TagParams (setmac show2)

use regex::Regex;
use serde::{Deserialize, Serialize};
use zudz_gpon::parse_show2;
use zudz_telnet::ZteTelnet;

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("فشل فتح المصنع: {0}")]
    Unlock(String),
    #[error("telnet: {0}")]
    Telnet(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ZudzReport {
    pub host: String,
    pub generated_at: String,
    pub device: Device,
    pub gpon: Gpon,
    pub pppoe: Pppoe,
    pub voip: Voip,
    pub wifi_defaults: WifiDefaults,
    pub sources: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Device {
    pub model: String,
    pub serial_label: String,
    pub hardware: String,
    pub software: String,
    pub boot: String,
    pub base_mac: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Gpon {
    pub vid: String,
    pub sn8: String,
    pub full_sn: String,
    pub ploam_password: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Pppoe {
    pub username: String,
    pub password: String,
    pub vlan: String,
    pub mtu: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Voip {
    pub sip_uri: String,
    pub phone_number: String,
    pub password: String,
    pub registrar: String,
    pub p_cscf: String,
    pub proxy1: String,
    pub proxy2: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WifiDefaults {
    pub ssid_24g: String,
    pub ssid_5g: String,
    pub psk: String,
}

pub struct ExtractOptions {
    pub host: String,
    pub web_user: String,
    pub web_password: String,
    /// سحب ويب LUA (إثرائي — يتجاهل الفشل)
    pub with_web: bool,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            host: "192.168.1.1".into(),
            web_user: "admin".into(),
            web_password: "admin".into(),
            with_web: true,
        }
    }
}

/// سلسلة محاولات دخول telnet: المؤقتة من الفتح أولاً، ثم root الدائم
/// (ZTE + PLOAM من آخر تقرير محفوظ) — بعض البرمجيات تُبقي خادم telnet
/// عالقاً على بيانات أول جلسة فتُرفض المؤقتة الجديدة.
pub fn telnet_attempts(r: &zudz_factory::UnlockResult) -> Vec<(String, String)> {
    let mut v = vec![(r.telnet_user.clone(), r.telnet_pass.clone())];
    if let Ok(pw) = std::env::var("ZUDZ_TELNET_ROOT_PWD") {
        if !pw.is_empty() {
            v.push(("root".into(), pw));
        }
    } else {
        for p in ["zudz_region_backup/report.json", "zudz_gpon_backup/report.json"] {
            if let Ok(d) = std::fs::read_to_string(p) {
                if let Ok(j) = serde_json::from_str::<serde_json::Value>(&d) {
                    if let Some(ploam) = j.pointer("/gpon/ploam_password").and_then(|x| x.as_str()) {
                        if !ploam.is_empty() {
                            v.push(("root".into(), format!("ZTE{ploam}")));
                        }
                        break;
                    }
                }
            }
        }
    }
    v
}

/// الاستخراج الكامل عبر telnet (بعد فتح المصنع تلقائياً)
pub fn extract_all(opts: &ExtractOptions) -> Result<ZudzReport, ExtractError> {
    let r = zudz_factory::unlock_telnet(&opts.host, &opts.web_user, &opts.web_password)
        .map_err(|e| ExtractError::Unlock(e.to_string()))?;
    let mut tn = ZteTelnet::connect(&opts.host, 23, 12)
        .map_err(|e| ExtractError::Telnet(e.to_string()))?;
    tn.login_fallback(&telnet_attempts(&r))
        .map_err(|e| ExtractError::Telnet(e.to_string()))?;
    let report = extract_with_telnet(&mut tn, opts)?;
    tn.sendline("exit");
    Ok(report)
}

/// الاستخراج عبر جلسة telnet قائمة (يفصلها extract_all للأغراض الاختبارية)
pub fn extract_with_telnet(tn: &mut ZteTelnet, opts: &ExtractOptions) -> Result<ZudzReport, ExtractError> {
    let _ = tn.run_capture("", 2);
    let mut rep = ZudzReport {
        host: opts.host.clone(),
        generated_at: now_iso(),
        ..Default::default()
    };

    // ── D: TagParams ──────────────────────────────────────────────
    let _ = tn.run_capture("setmac show2 > /tmp/zudz_s2.txt 2>&1", 3);
    let show2 = tn.run_capture("cat /tmp/zudz_s2.txt", 4);
    let _ = tn.run_capture("rm -f /tmp/zudz_s2.txt", 2);
    let tp = parse_show2(&show2);
    rep.gpon.vid = tp.get(&2176).cloned().unwrap_or_default();
    rep.gpon.sn8 = tp.get(&2177).cloned().unwrap_or_default();
    rep.gpon.full_sn = format!("{}{}", rep.gpon.vid, rep.gpon.sn8);
    rep.gpon.ploam_password = tp
        .get(&2178)
        .or_else(|| tp.get(&2181))
        .cloned()
        .unwrap_or_default();
    rep.device.base_mac = tp.get(&256).cloned().unwrap_or_default();
    rep.device.serial_label = tp.get(&512).cloned().unwrap_or_default();
    rep.device.software = tp.get(&36864).cloned().unwrap_or_default();
    rep.wifi_defaults.ssid_24g = tp.get(&1024).cloned().unwrap_or_default();
    rep.wifi_defaults.ssid_5g = tp.get(&1028).cloned().unwrap_or_default();
    rep.wifi_defaults.psk = tp.get(&1296).cloned().unwrap_or_default();
    if !tp.is_empty() {
        rep.sources.push("tagparams".into());
    }

    // ── A1: خيارات pppd ──────────────────────────────────────────
    let opts_txt = tn.run_capture("cat /var/tmp/ppp/options.* 2>/dev/null", 4);
    for line in opts_txt.lines() {
        if let Some(v) = line.trim().strip_prefix("user ") {
            rep.pppoe.username = v.trim().to_string();
        } else if let Some(v) = line.trim().strip_prefix("encrypasswd ") {
            if let Ok(p) = zudz_crypto::decrypt_encrypasswd(v.trim()) {
                rep.pppoe.password = p;
            }
        } else if let Some(v) = line.trim().strip_prefix("vlan ") {
            rep.pppoe.vlan = v.trim().to_string();
        } else if let Some(v) = line.trim().strip_prefix("mtu ") {
            rep.pppoe.mtu = v.trim().to_string();
        }
    }
    if !rep.pppoe.username.is_empty() {
        rep.sources.push("pppd-options".into());
    }

    // ── A2: ذاكرة cspd المشتركة (SIP URI + كلمة السر) ────────────
    if let Ok(sip) = scrape_shm_sip(tn) {
        rep.voip = sip;
        rep.sources.push("cspd-shm".into());
    }

    // ── C: ويب LUA (إثرائي) ────────────────────────────────────────
    if opts.with_web {
        if let Ok(mut s) = zudz_web::LuaSession::login(&opts.host, &opts.web_user, &opts.web_password) {
            if let Ok(w) = s.scrape() {
                if rep.device.model.is_empty() {
                    rep.device.model = w.model;
                }
                if rep.device.serial_label.is_empty() {
                    rep.device.serial_label = w.serial_label;
                }
                if rep.device.hardware.is_empty() {
                    rep.device.hardware = w.hardware;
                }
                if rep.device.boot.is_empty() {
                    rep.device.boot = w.boot;
                }
                if rep.device.software.is_empty() {
                    rep.device.software = w.software;
                }
                if rep.voip.registrar.is_empty() {
                    rep.voip.registrar = w.sip_registrar;
                }
                if rep.voip.proxy1.is_empty() {
                    rep.voip.proxy1 = w.sip_proxy1;
                }
                if rep.voip.proxy2.is_empty() {
                    rep.voip.proxy2 = w.sip_proxy2;
                }
                rep.sources.push("web-lua".into());
            }
        }
    }

    Ok(rep)
}

/// يبث ذاكرة cspd المشتركة عبر hexdump ويفك عنقدة قيم SIP
fn scrape_shm_sip(tn: &mut ZteTelnet) -> Result<Voip, ExtractError> {
    // ابحث عن PID عامل cspd
    let ps = tn.run_capture("ps", 3);
    let cspd_pid = ps
        .lines()
        .find(|l| l.trim_end().ends_with("cspd"))
        .and_then(|l| l.trim().split_whitespace().next())
        .ok_or_else(|| ExtractError::Telnet("cspd غير موجود".into()))?
        .to_string();

    // خريطة الذاكرة: مقطع /SYSV
    let maps = tn.run_capture(&format!("cat /proc/{cspd_pid}/maps"), 3);
    let sysv = maps
        .lines()
        .find(|l| l.contains("/SYSV"))
        .and_then(|l| l.split('-').next())
        .ok_or_else(|| ExtractError::Telnet("لا مقطع SYSV".into()))?
        .to_string();
    let base = u64::from_str_radix(&sysv, 16)
        .map_err(|_| ExtractError::Telnet(format!("عنوان غير صالح: {sysv}")))?;
    let skip = base / 4096;

    // dump 2MB ثم بث
    let _ = tn.run_capture(
        &format!("dd if=/proc/{cspd_pid}/mem of=/tmp/zudz_shm.bin bs=4096 skip={skip} count=512 2>&1"),
        4,
    );
    let blob = tn
        .hex_stream_file("/tmp/zudz_shm.bin")
        .map_err(|e| ExtractError::Telnet(e.to_string()))?;
    let _ = tn.run_capture("rm -f /tmp/zudz_shm.bin", 2);

    Ok(parse_shm_sip(&blob))
}

/// يفك عنقدة قيم SIP من ذاكرة CMAPI:
/// URI بنمط <أرقام>@<نطاق يحوي voip أو ims> + كلمة السر = أقرب رقم خالص قبلها
pub fn parse_shm_sip(blob: &[u8]) -> Voip {
    let mut v = Voip::default();
    let text = String::from_utf8_lossy(blob).into_owned();
    // كل السلاسل القابلة للطباعة
    let mut strings: Vec<(usize, String)> = Vec::new();
    let mut start: Option<usize> = None;
    for (i, b) in text.bytes().enumerate() {
        if (0x20..0x7f).contains(&b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            if i - s >= 4 {
                strings.push((s, text[s..i].to_string()));
            }
            start = None;
        }
    }
    let uri_re = Regex::new(r"^\d{6,}@[A-Za-z0-9.\-]+$").unwrap();
    let domain_re = Regex::new(r"@((?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,})").unwrap();
    let p_cscf_re = Regex::new(r"^p-cscf\.").unwrap();
    for (idx, (pos, s)) in strings.iter().enumerate() {
        if uri_re.is_match(s) {
            v.sip_uri = s.clone();
            v.phone_number = s.split('@').next().unwrap_or("").to_string();
            if let Some(c) = domain_re.captures(s) {
                v.registrar = c[1].to_string();
            }
            // كلمة السر: أقرب سلسلة أرقام خالصة (4-16) قبلها
            for j in (0..idx).rev() {
                let cand = &strings[j].1;
                if cand.len() >= 4 && cand.len() <= 16 && cand.chars().all(|c| c.is_ascii_digit()) {
                    v.password = cand.clone();
                    break;
                }
            }
            let _ = pos;
        } else if p_cscf_re.is_match(s) {
            v.p_cscf = s.clone();
        }
    }
    v
}

pub fn report_json(rep: &ZudzReport) -> String {
    serde_json::to_string_pretty(rep).unwrap_or_default()
}

/// تقرير نصي — كل الأرقام غربية 0-9 (القيم تقنية لاتينية أصلاً)
pub fn report_markdown(rep: &ZudzReport) -> String {
    use std::fmt::Write;
    let mut m = String::new();
    let _ = writeln!(m, "# ZUDZ — تقرير بيانات الجهاز والمزود");
    let _ = writeln!(m);
    let _ = writeln!(m, "- الجهاز: {} ({})", rep.device.model, rep.host);
    let _ = writeln!(m, "- السيريال: {}", rep.device.serial_label);
    let _ = writeln!(m, "- البرمجية: {} / العتاد: {} / الإقلاع: {}", rep.device.software, rep.device.hardware, rep.device.boot);
    let _ = writeln!(m);
    let _ = writeln!(m, "## هوية GPON (للترحيل)");
    let _ = writeln!(m, "- GPON SN: `{}`", rep.gpon.full_sn);
    let _ = writeln!(m, "- PLOAM: `{}`", rep.gpon.ploam_password);
    let _ = writeln!(m, "- MAC: `{}`", rep.device.base_mac);
    let _ = writeln!(m);
    let _ = writeln!(m, "## اتصال الإنترنت (PPPoE)");
    let _ = writeln!(m, "- المستخدم: `{}`", rep.pppoe.username);
    let _ = writeln!(m, "- كلمة المرور: `{}`", rep.pppoe.password);
    let _ = writeln!(m, "- VLAN: {}", rep.pppoe.vlan);
    let _ = writeln!(m);
    let _ = writeln!(m, "## الهاتف (VoIP/SIP)");
    let _ = writeln!(m, "- الرقم/URI: `{}`", rep.voip.sip_uri);
    let _ = writeln!(m, "- كلمة السر: `{}`", rep.voip.password);
    let _ = writeln!(m, "- Registrar: `{}`", rep.voip.registrar);
    if !rep.voip.p_cscf.is_empty() {
        let _ = writeln!(m, "- P-CSCF: `{}`", rep.voip.p_cscf);
    }
    let _ = writeln!(m);
    let _ = writeln!(m, "## WiFi الافتراضية (من المصنع)");
    let _ = writeln!(m, "- SSID 2.4G: `{}` | SSID 5G: `{}` | PSK: `{}`",
        rep.wifi_defaults.ssid_24g, rep.wifi_defaults.ssid_5g, rep.wifi_defaults.psk);
    let _ = writeln!(m);
    let _ = writeln!(m, "---");
    let _ = writeln!(m, "المصادر: {}", rep.sources.join(" + "));
    let _ = writeln!(m, "> ملف حساس — احتفظ به بصلاحية 600.");
    m
}

fn now_iso() -> String {
    // بدون اعتماديات: زمن يونكس ×  ثانية — كافٍ للتقرير (أرقام غربية)
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_shm_sip_from_live_capture() {
        // مقتطف من عنقدة القيم الحقيقية (الجلسة الحية)
        let mut blob = vec![0u8; 64];
        blob.extend_from_slice(b"DEV.WIFI.RD1\0");
        blob.extend_from_slice(b"46327985\0");
        blob.extend_from_slice(b"21339182080@voip.ims.algerietelecom.dz\0");
        blob.extend_from_slice(b"p-cscf.ims.algerietelecom.dz\0");
        let v = parse_shm_sip(&blob);
        assert_eq!(v.sip_uri, "21339182080@voip.ims.algerietelecom.dz");
        assert_eq!(v.phone_number, "21339182080");
        assert_eq!(v.password, "46327985");
        assert_eq!(v.registrar, "voip.ims.algerietelecom.dz");
        assert_eq!(v.p_cscf, "p-cscf.ims.algerietelecom.dz");
    }
}
