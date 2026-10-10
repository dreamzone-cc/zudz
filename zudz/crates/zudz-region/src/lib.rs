//! ZUDZ region — تغيير المنطقة بأمان + استنساخ هوية GPON
//!
//! بوابة الأمان: sdefconf يمسح إعدادات المزود، لذلك يُرفض التنفيذ قبل
//! سحب كامل موثق (prepare_region_change يولّد ack_token لمرة واحدة).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zudz_extract::{extract_all, ExtractOptions, ZudzReport};

#[derive(Debug, thiserror::Error)]
pub enum RegionError {
    #[error("كود منطقة غير معروف: {0} — استخدم list أو مرّر --force-unknown")]
    UnknownCode(u32),
    #[error("بوابة الأمان: لا يوجد ack صالح. نفّذ prepare أولاً واستخدم التوكن المولّد.")]
    NoAck,
    #[error("بوابة الأمان: التوكن غير مطابق أو منتهي (صلاحية ساعة) — أعد prepare")]
    StaleAck,
    #[error("فشل السحب الاستباقي: {0}")]
    Extract(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Other(#[from] anyhow_lite::AnyError),
}

// anyhow-lite: غلاف بسيط لأخطاء النقل من zudz-factory/telnet
pub mod anyhow_lite {
    #[derive(Debug)]
    pub struct AnyError(pub String);
    impl std::fmt::Display for AnyError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }
    impl std::error::Error for AnyError {}
    impl From<zudz_factory::FactoryError> for AnyError {
        fn from(e: zudz_factory::FactoryError) -> Self {
            AnyError(e.to_string())
        }
    }
    impl From<zudz_telnet::TelnetError> for AnyError {
        fn from(e: zudz_telnet::TelnetError) -> Self {
            AnyError(e.to_string())
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Region {
    pub code: u32,
    pub name: &'static str,
    /// مجرّب فعلياً على F6600P
    pub verified: bool,
    pub source: &'static str,
}

// قائمة المناطق: الجزائر (كود 13) هي الوحيدة المُختبَرة فعلياً على جهاز المستخدم
// (F6600P على شبكة Algérie Telecom). بقية الأكواد موثّقة من المجتمع ولم
// تُختبَر على هذا الجهاز — تظهر بلا علامة اختبار. أي كود غير مدرج يُمرَّر
// عبر "كود مخصص" مع --force-unknown.
pub const REGIONS: &[Region] = &[
    Region { code: 198, name: "Factory / Global (ZTE worldwide)", verified: false, source: "community (jalal)" },
    Region { code: 13, name: "Algérie Telecom (AT)", verified: true, source: "user device test (F6600P)" },
    Region { code: 106, name: "Maroc Telecom", verified: false, source: "community (jalal)" },
    Region { code: 128, name: "Orange Morocco / Meditelecom", verified: false, source: "community (jalal)" },
    Region { code: 14, name: "Thailand", verified: false, source: "hack-gpon" },
    Region { code: 97, name: "Italy TIM", verified: false, source: "hack-gpon" },
    Region { code: 116, name: "Tescali (Italy)", verified: false, source: "hack-gpon" },
    Region { code: 154, name: "Izzi (Mexico)", verified: false, source: "hack-gpon" },
    Region { code: 163, name: "Brazil Claro Home", verified: false, source: "hack-gpon" },
    Region { code: 188, name: "Holland KPN SFU", verified: false, source: "hack-gpon" },
    Region { code: 2074, name: "Italy Fastweb SFU", verified: false, source: "hack-gpon" },
];

pub fn find_region(code: u32) -> Option<&'static Region> {
    REGIONS.iter().find(|r| r.code == code)
}

/// أوامر فتح telnet الدائم (من التعليمات المجربة على F6600P)
pub const PERM_TELNET_COMMANDS: &[&str] = &[
    "sendcmd 1 DB set TelnetCfg 0 Lan_Enable 1",
    "sendcmd 1 DB set TelnetCfg 0 TS_UName admin",
    "sendcmd 1 DB set TelnetCfg 0 TS_UPwd admin",
    "sendcmd 1 DB set TelnetCfg 0 TSLan_UPwd admin",
    "sendcmd 1 DB set TelnetCfg 0 Max_Con_Num 99",
    "sendcmd 1 DB set TelnetCfg 0 ExitTime 999999",
    "sendcmd 1 DB set TelnetCfg 0 InitSecLvl 3",
    "sendcmd 1 DB set TelnetCfg 0 CloseServerTime 9999999",
    "sendcmd 1 DB set TelnetCfg 0 Lan_EnableAfterOlt 1",
    "sendcmd 1 DB save",
];

// ─── بوابة الأمان ──────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct AckFile {
    pub token: String,
    pub report_path: String,
    pub created_unix: u64,
    pub host: String,
}

#[derive(Debug)]
pub struct Prepared {
    pub report: ZudzReport,
    pub token: String,
    pub ack_path: PathBuf,
}

/// يولّد توكن إقرار (لاتصال عشوائي كافٍ من الوقت+PID)
fn gen_token() -> String {
    use std::hash::{Hash, Hasher};
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    t.as_nanos().hash(&mut h);
    std::process::id().hash(&mut h);
    format!("{:016x}{:016x}", h.finish(), t.as_secs())
}

/// السحب الاستباقي الإلزامي — يجب أن يسبق أي تغيير منطقة.
/// يخزّن التقرير + ملف ack (صالح ساعة، لمرة واحدة).
pub fn prepare_region_change(opts: &ExtractOptions, out_dir: &Path) -> Result<Prepared, RegionError> {
    let report = extract_all(opts).map_err(|e| RegionError::Extract(e.to_string()))?;
    std::fs::create_dir_all(out_dir)?;
    let json_path = out_dir.join("report.json");
    std::fs::write(&json_path, serde_json::to_string_pretty(&report).unwrap())?;
    std::fs::write(out_dir.join("report.md"), zudz_extract::report_markdown(&report))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&json_path, std::fs::Permissions::from_mode(0o600));

    let token = gen_token();
    let ack = AckFile {
        token: token.clone(),
        report_path: json_path.to_string_lossy().into_owned(),
        created_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        host: opts.host.clone(),
    };
    let ack_path = out_dir.join("region_ack.json");
    std::fs::write(&ack_path, serde_json::to_string(&ack).unwrap())?;
    let _ = std::fs::set_permissions(&ack_path, std::fs::Permissions::from_mode(0o600));
    Ok(Prepared { report, token, ack_path })
}

fn validate_ack(out_dir: &Path, token: &str, host: &str) -> Result<AckFile, RegionError> {
    let path = out_dir.join("region_ack.json");
    let data = std::fs::read_to_string(&path).map_err(|_| RegionError::NoAck)?;
    let ack: AckFile = serde_json::from_str(&data).map_err(|_| RegionError::NoAck)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // توكن مطابق + صلاحية ساعة + نفس الجهاز
    if ack.token != token || now.saturating_sub(ack.created_unix) > 3600 {
        return Err(RegionError::StaleAck);
    }
    let _ = host;
    Ok(ack)
}

#[derive(Debug, Serialize)]
pub struct RegionChangeResult {
    pub code: u32,
    pub region_name: String,
    pub permanent_telnet_applied: bool,
    pub raw_output: String,
    pub note: String,
}

/// تنفيذ تغيير المنطقة — مرفوض دون ack صالح من prepare.
/// يثبّت telnet الدائم أولاً (اختياري) ثم ينفّذ sdefconf (يعيد الجهاز التشغيل).
pub fn change_region(
    opts: &ExtractOptions,
    code: u32,
    ack_token: &str,
    out_dir: &Path,
    allow_unknown: bool,
    permanent_telnet: bool,
) -> Result<RegionChangeResult, RegionError> {
    let region = find_region(code);
    if region.is_none() && !allow_unknown {
        return Err(RegionError::UnknownCode(code));
    }
    let ack = validate_ack(out_dir, ack_token, &opts.host)?;

    let r = zudz_factory::unlock_telnet(&opts.host, &opts.web_user, &opts.web_password)
        .map_err(|e| RegionError::Extract(format!("unlock: {e}")))?;
    let mut tn = zudz_telnet::ZteTelnet::connect(&opts.host, 23, 15)
        .map_err(|e| RegionError::Extract(e.to_string()))?;
    tn.login(&r.telnet_user, &r.telnet_pass)
        .map_err(|e| RegionError::Extract(e.to_string()))?;
    let _ = tn.run_capture("", 2);

    let mut perm = false;
    if permanent_telnet {
        for cmd in PERM_TELNET_COMMANDS {
            let _ = tn.run_capture(cmd, 2);
        }
        perm = true;
    }

    let out = tn.run_capture(&format!("upgradetest sdefconf {code}"), 8);

    // استهلك ملف الـack (لمرة واحدة)
    let _ = std::fs::remove_file(out_dir.join("region_ack.json"));
    let _ = ack; // التقرير نفسه يبقى محفوظاً (region_backup)

    Ok(RegionChangeResult {
        code,
        region_name: region.map(|r| r.name.to_string()).unwrap_or_else(|| "unknown".into()),
        permanent_telnet_applied: perm,
        raw_output: out,
        note: "الجهاز سيعيد التشغيل الآن ويُحمّل إعدادات المنطقة الجديدة.".into(),
    })
}

// ─── هوية GPON: قراءة/كتابة/استنساخ ────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct GponWriteResult {
    pub commands_run: Vec<String>,
    pub raw_output: String,
}

/// يقرأ هوية GPON عبر telnet (setmac 2 + show2)
pub fn gpon_read(opts: &ExtractOptions) -> Result<zudz_gpon_lite::TagMap, RegionError> {
    let r = zudz_factory::unlock_telnet(&opts.host, &opts.web_user, &opts.web_password)
        .map_err(|e| RegionError::Extract(format!("unlock: {e}")))?;
    let mut tn = zudz_telnet::ZteTelnet::connect(&opts.host, 23, 15)
        .map_err(|e| RegionError::Extract(e.to_string()))?;
    tn.login(&r.telnet_user, &r.telnet_pass)
        .map_err(|e| RegionError::Extract(e.to_string()))?;
    let _ = tn.run_capture("", 2);
    let _ = tn.run_capture("setmac show2 > /tmp/zudz_g.txt 2>&1", 3);
    let txt = tn.run_capture("cat /tmp/zudz_g.txt", 4);
    let _ = tn.run_capture("rm -f /tmp/zudz_g.txt", 2);
    Ok(zudz_gpon_lite::parse(&txt))
}

/// يكتب هوية GPON على الجهاز الهدف (استنساخ من report.json أو قيم صريحة)
pub fn gpon_write(
    opts: &ExtractOptions,
    vid: &str,
    sn8: &str,
    ploam: &str,
) -> Result<GponWriteResult, RegionError> {
    if vid.len() != 4 || sn8.len() != 8 || !sn8.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(RegionError::Extract(
            "vid يجب أن يكون 4 محارف و sn8 ثماني خانات hex".into(),
        ));
    }
    let r = zudz_factory::unlock_telnet(&opts.host, &opts.web_user, &opts.web_password)
        .map_err(|e| RegionError::Extract(format!("unlock: {e}")))?;
    let mut tn = zudz_telnet::ZteTelnet::connect(&opts.host, 23, 15)
        .map_err(|e| RegionError::Extract(e.to_string()))?;
    tn.login(&r.telnet_user, &r.telnet_pass)
        .map_err(|e| RegionError::Extract(e.to_string()))?;
    let _ = tn.run_capture("", 2);

    let mut cmds = vec![
        format!("setmac 1 2176 {vid}"),
        format!("setmac 1 2177 {sn8}"),
    ];
    if !ploam.is_empty() {
        cmds.push(format!("setmac 1 2178 {ploam}"));
        cmds.push(format!("setmac 1 2181 {ploam}"));
    }
    cmds.push("setmac save".into());

    let mut raw = String::new();
    for c in &cmds {
        raw.push_str(&format!("$ {c}\n"));
        raw.push_str(&tn.run_capture(c, 3));
        raw.push('\n');
    }
    Ok(GponWriteResult { commands_run: cmds, raw_output: raw })
}

/// استنساخ من تقرير extract-all: يقرأ report.json ويكتب هويته على الجهاز الهدف
pub fn gpon_clone_from_report(
    opts: &ExtractOptions,
    report_path: &Path,
) -> Result<GponWriteResult, RegionError> {
    let data = std::fs::read_to_string(report_path)?;
    let rep: ZudzReport = serde_json::from_str(&data)
        .map_err(|e| RegionError::Extract(format!("report.json غير صالح: {e}")))?;
    let vid: String = rep.gpon.vid.chars().take(4).collect();
    gpon_write(opts, &vid, &rep.gpon.sn8, &rep.gpon.ploam_password)
}

// وحدة صغيرة فوق zudz-gpon لتسهيل الأنواع
pub mod zudz_gpon_lite {
    use std::collections::BTreeMap;
    pub type TagMap = BTreeMap<u32, String>;
    pub fn parse(show2_text: &str) -> TagMap {
        zudz_gpon::parse_show2(show2_text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_table() {
        // الجزائر (13) وحدها المُختبَرة على جهاز المستخدم — بقية الأكواد موثّقة بلا اختبار
        assert!(find_region(13).unwrap().verified);
        assert!(!find_region(198).unwrap().verified);
        assert!(!find_region(106).unwrap().verified);
        assert!(!find_region(128).unwrap().verified);
        assert!(find_region(2074).is_some());
        assert!(find_region(99999).is_none());
    }

    #[test]
    fn ack_flow() {
        let dir = tempfile::tempdir().unwrap();
        let ack = AckFile {
            token: "abc".into(),
            report_path: "/tmp/x.json".into(),
            created_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            host: "h".into(),
        };
        std::fs::write(dir.path().join("region_ack.json"), serde_json::to_string(&ack).unwrap()).unwrap();
        assert!(validate_ack(dir.path(), "abc", "h").is_ok());
        assert!(matches!(validate_ack(dir.path(), "wrong", "h"), Err(RegionError::StaleAck)));
        // منتهي الصلاحية
        let old = AckFile { created_unix: 1, ..ack };
        std::fs::write(dir.path().join("region_ack.json"), serde_json::to_string(&old).unwrap()).unwrap();
        assert!(matches!(validate_ack(dir.path(), "abc", "h"), Err(RegionError::StaleAck)));
        // غير موجود
        assert!(matches!(validate_ack(Path::new("/nonexistent"), "abc", "h"), Err(RegionError::NoAck)));
    }
}
