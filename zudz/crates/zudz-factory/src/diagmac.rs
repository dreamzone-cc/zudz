//! توجيه MAC التشخيصي — الجذر الحقيقي لعدم فتح telnet.
//!
//! الجهاز (F6600P V9.x) لا يقبل اتصال telnet إلا إذا جاء من العنوان
//! التشخيصي `00:07:29:55:35:57` (تحقق ميداني 2026-10-12: لا يكفي أن تحمل
//! الحمولة العنوان؛ بل يجب أن يكون مصدر اتصال TCP الفعلي به أيضاً).
//!
//! نُنشئ واجهة `macvlan` بهذا العنوان ونوجّه حركة الجهاز عبرها — دون
//! لمس الواجهة الأساسية. **كل العمليات تُنجَز مباشرة عبر netlink**
//! (`crate::netlink`) — بلا `iproute2` ولا `docker`: الأداة مستقلة تماماً
//! عند التشغيل، وتحتاج فقط صلاحية `CAP_NET_ADMIN` (أي root) لإنشاء الواجهة.

use std::net::Ipv4Addr;

use crate::netlink;

pub const DIAG_MAC: &str = "00:07:29:55:35:57";
pub const DIAG_IFACE: &str = "diag0";

#[derive(Debug, thiserror::Error)]
pub enum DiagError {
    #[error("تعذّر إعداد مسار MAC التشخيصي: {0}")]
    Setup(String),
    #[error(
        "لا صلاحية لإنشاء واجهة macvlan (تحتاج root / CAP_NET_ADMIN) — \
         شغّل الأداة بـ sudo، أو غيّر MAC كرت الشبكة إلى {DIAG_MAC} يدوياً"
    )]
    NoCapability,
    #[error(transparent)]
    Nl(#[from] netlink::NlError),
}

/// كيف أُكتُشف/أُنشئ المسار (للتشخيص)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagMode {
    /// كرت الشبكة نفسه يحمل MAC التشخيصي — لا حاجة لأي إعداد
    NativeNic,
    /// مسار تشخيصي موجود مسبقاً (واجهة diag0) — نتركه كما هو
    Existing,
    /// أُنشئ عبر netlink (واجهة macvlan)
    Netlink,
}

impl std::fmt::Display for DiagMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DiagMode::NativeNic => "كرت الشبكة يحمل MAC التشخيصي أصلاً",
            DiagMode::Existing => "مسار تشخيصي موجود مسبقاً",
            DiagMode::Netlink => "واجهة macvlan (netlink مدمج)",
        };
        f.write_str(s)
    }
}

/// حارس مسار MAC التشخيصي — يزيل ما أنشأه عند Drop (إلا ما كان موجوداً مسبقاً).
#[derive(Debug)]
pub struct DiagRoute {
    created: bool,
    mode: DiagMode,
}

impl DiagRoute {
    pub fn mode(&self) -> DiagMode {
        self.mode
    }
}

impl Drop for DiagRoute {
    fn drop(&mut self) {
        if self.created {
            let _ = remove_diag();
        }
    }
}

/// هل كرت الشبكة الموصل للجهاز يحمل MAC التشخيصي أصلاً؟ (لا يحسب واجهة
/// macvlan الخاصة بنا — إن كان المسار عبر diag0 فالكرت الحقيقي ليس تشخيصياً).
pub fn nic_is_diagnostic(host: &str) -> bool {
    match crate::unlock::nic_mac_towards(host) {
        Ok(Some((dev, mac))) => dev != DIAG_IFACE && mac == crate::unlock::DIAGNOSTIC_MAC,
        _ => false,
    }
}

/// هل مسار الجهاز يمرّ عبر واجهة diag0؟
pub fn diag_route_active(host: &str) -> bool {
    let Ok(ip) = host.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(Some(route)) = netlink::route_lookup(ip) else {
        return false;
    };
    matches!(netlink::ifindex(DIAG_IFACE), Ok(idx) if idx == route.ifindex)
}

/// يفعّل مسار MAC التشخيصي ويبقيه (بلا حارس) — للاستخدام اليدوي
/// (`zudz diag-route setup`). أزله بـ `remove_diag_route`.
pub fn setup_diag_route(host: &str) -> Result<DiagMode, DiagError> {
    if nic_is_diagnostic(host) {
        return Ok(DiagMode::NativeNic);
    }
    if diag_route_active(host) {
        return Ok(DiagMode::Existing);
    }
    create_diag_route(host)?;
    Ok(DiagMode::Netlink)
}

/// يضمن مسار MAC التشخيصي أثناء العملية — حارس يزيل ما أنشأه عند انتهائها
/// (إلا ما كان موجوداً مسبقاً).
pub fn ensure_diag_route(host: &str) -> Result<DiagRoute, DiagError> {
    if nic_is_diagnostic(host) {
        return Ok(DiagRoute { created: false, mode: DiagMode::NativeNic });
    }
    if diag_route_active(host) {
        return Ok(DiagRoute { created: false, mode: DiagMode::Existing });
    }
    create_diag_route(host)?;
    Ok(DiagRoute { created: true, mode: DiagMode::Netlink })
}

/// يزيل واجهة macvlan التشخيصية إن وُجدت.
pub fn remove_diag_route(_host: &str) {
    let _ = remove_diag();
}

fn remove_diag() -> Result<(), DiagError> {
    if let Ok(idx) = netlink::ifindex(DIAG_IFACE) {
        netlink::del_link(idx)?;
    }
    Ok(())
}

// ─── التنفيذ ───────────────────────────────────────────────────

fn create_diag_route(host: &str) -> Result<(), DiagError> {
    let ip: Ipv4Addr = host
        .parse()
        .map_err(|_| DiagError::Setup(format!("عنوان غير صالح: {host}")))?;

    // نظّف أي واجهة diag0 متبقية
    let _ = remove_diag();

    let route = netlink::route_lookup(ip)?
        .ok_or_else(|| DiagError::Setup("لا مسار شبكي إلى الجهاز".into()))?;
    let (parent_ip, prefix) = netlink::iface_ipv4(route.ifindex)?
        .ok_or_else(|| DiagError::Setup("لا عنوان IPv4 على واجهة الخروج".into()))?;

    // مرشحو آخر ثماني للـ diag IP: نفس شبكة الكرت، بعيداً عن نطاق DHCP.
    const CANDS: [u8; 4] = [50, 51, 52, 250];
    let mut last_err: Option<DiagError> = None;
    for last in CANDS {
        let diag_ip = set_last_octet(parent_ip, last);
        match try_create(route.ifindex, diag_ip, prefix, ip) {
            Ok(()) => return Ok(()),
            Err(e) => {
                let _ = remove_diag();
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or(DiagError::Setup("تعذّر إنشاء واجهة macvlan".into())))
}

fn try_create(parent_index: u32, diag_ip: Ipv4Addr, prefix: u8, dst: Ipv4Addr) -> Result<(), DiagError> {
    let mac = crate::unlock::DIAGNOSTIC_MAC;
    let idx = netlink::create_macvlan(parent_index, DIAG_IFACE, mac).map_err(|e| {
        // EPERM/EACCES ⇒ لا صلاحية
        DiagError::Setup(e.to_string())
    })?;
    netlink::set_up(idx)?;
    netlink::add_addr(idx, diag_ip, prefix)?;
    netlink::add_route(dst, 32, idx, diag_ip)?;
    Ok(())
}

/// يستبدل آخر ثماني من عنوان IPv4 (لاشتقاق عنوان macvlan حر)
fn set_last_octet(ip: Ipv4Addr, last: u8) -> Ipv4Addr {
    let o = (u32::from(ip) & 0xFFFF_FF00) | last as u32;
    Ipv4Addr::from(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_last_octet_works() {
        let ip: Ipv4Addr = "192.168.1.9".parse().unwrap();
        assert_eq!(set_last_octet(ip, 50).to_string(), "192.168.1.50");
        assert_eq!(set_last_octet(ip, 250).to_string(), "192.168.1.250");
    }

    #[test]
    fn diag_mac_constant_matches_tool() {
        assert_eq!(DIAG_MAC, crate::unlock::DIAGNOSTIC_MAC_STR);
        assert_eq!(DIAG_MAC, "00:07:29:55:35:57");
    }
}
