//! ZUDZ meta — المعلومات الرسمية للمشروع: المطوّر والترخيص والغرض
//!
//! مصدر مركزي وحيد تستهلكه واجهة CLI والخادم والواجهة الرسومية،
//! حتى تظهر معلومات المطوّر والترخيص متطابقة في كل السطوح.

pub const NAME: &str = "ZUDZ";
pub const TAGLINE: &str = "ZTE Unlock, Decrypt & Zone-changer";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// المطوِّر — الحساب الرسمي
pub const AUTHOR: &str = "dreamzone-cc";
pub const HOMEPAGE: &str = "https://github.com/dreamzone-cc";
/// التواصل الشخصي — منصة Discord
pub const DISCORD: &str = "yuuyu_gg";

/// الترخيص — GNU Affero General Public License
pub const LICENSE: &str = "AGPL-3.0-or-later";
pub const LICENSE_NAME: &str = "GNU Affero General Public License v3.0";
pub const LICENSE_URL: &str = "https://www.gnu.org/licenses/agpl-3.0.html";
pub const LICENSE_FILE: &str = "LICENSE";

/// الغرض المصرّح به
pub const PURPOSE: &str = "Maintenance tool for personal ZTE GPON devices";
/// نطاق الاستخدام: الأجهزة الشخصية فقط
pub const PERSONAL_ONLY: &str =
    "For personal devices only — devices you own or hold explicit written authorization to manage";
/// التحريم: لا أعمال غير قانونية
pub const NO_ILLEGAL: &str =
    "Unlawful use is strictly prohibited — the user bears full responsibility";
/// ملف إخلاء المسؤولية
pub const DISCLAIMER_FILE: &str = "DISCLAIMER.md";
pub const REPORT_FILE: &str = "REPORT.md";

/// الإشعار الكامل — يُطبع في about/help
pub fn notice() -> String {
    format!(
        "{NAME} — {TAGLINE}\n\
         Version: {VERSION}\n\
         Developer: {AUTHOR} — {HOMEPAGE}\n\
         Discord: {DISCORD}\n\
         License: {LICENSE_NAME} ({LICENSE})\n  {LICENSE_URL}\n\
         Purpose: {PURPOSE}.\n\
         Scope: {PERSONAL_ONLY}.\n\
         Rule: {NO_ILLEGAL}. See {DISCLAIMER_FILE} and {REPORT_FILE}."
    )
}

/// السجل المهيكل — ليستخدمه الخادم في /api/version
#[derive(Debug, Clone)]
pub struct Meta {
    pub name: &'static str,
    pub version: &'static str,
    pub tagline: &'static str,
    pub author: &'static str,
    pub homepage: &'static str,
    pub discord: &'static str,
    pub license: &'static str,
    pub license_name: &'static str,
    pub license_url: &'static str,
    pub purpose: &'static str,
    pub personal_only: &'static str,
    pub no_illegal: &'static str,
    pub disclaimer: &'static str,
}

pub fn meta() -> Meta {
    Meta {
        name: NAME,
        version: VERSION,
        tagline: TAGLINE,
        author: AUTHOR,
        homepage: HOMEPAGE,
        discord: DISCORD,
        license: LICENSE,
        license_name: LICENSE_NAME,
        license_url: LICENSE_URL,
        purpose: PURPOSE,
        personal_only: PERSONAL_ONLY,
        no_illegal: NO_ILLEGAL,
        disclaimer: DISCLAIMER_FILE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_identity() {
        let m = meta();
        assert_eq!(m.author, "dreamzone-cc");
        assert_eq!(m.homepage, "https://github.com/dreamzone-cc");
        assert_eq!(m.discord, "yuuyu_gg");
        assert!(m.license.starts_with("AGPL-3.0"));
        assert!(m.license_url.contains("agpl"));
    }

    #[test]
    fn notice_contains_all() {
        let n = notice();
        for needle in ["dreamzone-cc", "yuuyu_gg", "AGPL", "personal devices only"] {
            assert!(n.contains(needle), "notice missing: {needle}");
        }
    }
}
