//! توجيه MAC التشخيصي — الجذر الحقيقي لعدم فتح telnet.
//!
//! الجهاز (F6600P V9.x) لا يُنشئ خادم telnet المؤقت إلا إذا جاء طلب
//! وضع المصنع من العنوان التشخيصي `00:07:29:55:35:57` — لا يكفي أن تحمل
//! الحمولة هذا العنوان؛ بل يجب أن يكون مصدر اتصال TCP الفعلي بهذا العنوان
//! أيضاً (قُوِّبل الادعاء المعاكس في v0.3.0، ثم عُدل بعد التحقق الميداني
//! 2026-10-11: البروتوكول يكتمل ويعيد بيانات، لكن المنفذ 23 لا يُفتح).
//!
//! نُنشئ واجهة `macvlan` بهذا العنوان ونوجّه حركة الجهاز عبرها — دون
//! لمس الواجهة الأساسية. التنفيذ:
//!   • `docker` (`--privileged --net=host`) — بلا صلاحيات root على المضيف.
//!   • `ip` مباشرة — عندما يعمل البرنامج كـ root.
//! إن كان كرت الشبكة الموصل للجهاز يحمل العنوان التشخيصي أصلاً فلا حاجة
//! لأي إعداد (وهذا ما تفعله أداة zteonu الأصلية بتغيير MAC الكرت).

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

pub const DIAG_MAC: &str = "00:07:29:55:35:57";
pub const DIAG_IFACE: &str = "diag0";

#[derive(Debug, thiserror::Error)]
pub enum DiagError {
    #[error("تعذّر إعداد مسار MAC التشخيصي: {0}")]
    Setup(String),
    #[error(
        "لا صلاحية (root أو docker) لإنشاء واجهة macvlan — غيّر MAC كرت الشبكة \
         إلى {DIAG_MAC} يدوياً أو ثبّت docker"
    )]
    NoCapability,
}

/// كيف أُنشئ/أُكتُشف المسار (للتشخيص)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagMode {
    /// كرت الشبكة نفسه يحمل MAC التشخيصي — لا حاجة لأي إعداد
    NativeNic,
    /// مسار تشخيصي موجود مسبقاً (أُنشئ سابقاً) — نتركه كما هو
    Existing,
    /// أُنشئ عبر docker (بدون root)
    Docker,
    /// أُنشئ عبر ip مباشرة (root)
    Native,
}

impl std::fmt::Display for DiagMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DiagMode::NativeNic => "كرت الشبكة يحمل MAC التشخيصي أصلاً",
            DiagMode::Existing => "مسار تشخيصي موجود مسبقاً",
            DiagMode::Docker => "macvlan عبر docker",
            DiagMode::Native => "macvlan عبر ip (root)",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Via { Docker, Native }

/// حارس مسار MAC التشخيصي — يزيل ما أنشأه عند Drop (إلا ما كان موجوداً مسبقاً).
#[derive(Debug)]
pub struct DiagRoute {
    created: bool,
    via: Option<Via>,
    host: String,
    mode: DiagMode,
}

impl DiagRoute {
    pub fn mode(&self) -> DiagMode {
        self.mode
    }
    fn remove(&self) {
        if let Some(via) = self.via {
            let _ = remove_diag(via, &self.host);
        }
    }
}

impl Drop for DiagRoute {
    fn drop(&mut self) {
        if self.created {
            self.remove();
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

/// هل يوجد مسار نشط إلى المضيف عبر واجهة macvlan التشخيصية؟
pub fn diag_route_active(host: &str) -> bool {
    let Some(out) = run("ip", &["route", "get", host]) else {
        return false;
    };
    crate::unlock::parse_route_dev(&out).map(|d| d == DIAG_IFACE).unwrap_or(false)
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
    let via = create_diag_route(host)?;
    Ok(if via == Via::Docker { DiagMode::Docker } else { DiagMode::Native })
}

/// يضمن مسار MAC التشخيصي أثناء العملية — حارس يزيل ما أنشأه عند انتهائها
/// (إلا ما كان موجوداً مسبقاً). المسار ضروري لبروتوكول الفتح فقط؛
/// جلسة telnet نفسها تعمل من أي مصدر بمجرد أن يُنشأ الخادم.
pub fn ensure_diag_route(host: &str) -> Result<DiagRoute, DiagError> {
    if nic_is_diagnostic(host) {
        return Ok(DiagRoute { created: false, via: None, host: host.into(), mode: DiagMode::NativeNic });
    }
    if diag_route_active(host) {
        return Ok(DiagRoute { created: false, via: None, host: host.into(), mode: DiagMode::Existing });
    }
    let via = create_diag_route(host)?;
    Ok(DiagRoute {
        created: true,
        via: Some(via),
        host: host.into(),
        mode: if via == Via::Docker { DiagMode::Docker } else { DiagMode::Native },
    })
}

/// يزيل واجهة/macvlan والمسار التشخيصي إن وُجدت.
pub fn remove_diag_route(host: &str) {
    let _ = remove_diag(Via::Docker, host);
    let _ = remove_diag(Via::Native, host);
}

// ─── التنفيذ ───────────────────────────────────────────────────

/// الأوامر الخام التي تُنشئ الواجهة والمسار (تُجرَّب بعدة عناوين IP).
fn create_diag_route(host: &str) -> Result<Via, DiagError> {
    let (parent, parent_ip, prefix) = parent_info(host)
        .ok_or_else(|| DiagError::Setup("لا مسار شبكي إلى الجهاز".into()))?;
    let via = if docker_available() {
        Via::Docker
    } else if is_root() {
        Via::Native
    } else {
        return Err(DiagError::NoCapability);
    };
    // مرشحو آخر ثماني للـ diag IP: نفس شبكة الكرت، بعيداً عن نطاق DHCP.
    const CANDS: [u8; 4] = [50, 51, 52, 250];
    for last in CANDS {
        let diag_ip = set_last_octet(parent_ip, last);
        if try_create(via, &parent, diag_ip, prefix, host) {
            return Ok(via);
        }
        let _ = remove_diag(via, host); // نظّف المحاولة الفاشلة قبل التالية
    }
    Err(DiagError::Setup("تعذّر إنشاء واجهة macvlan (جرّبت عدة عناوين IP)".into()))
}

fn try_create(via: Via, parent: &str, diag_ip: IpAddr, prefix: u8, host: &str) -> bool {
    match via {
        Via::Docker => try_create_docker(parent, diag_ip, prefix, host),
        Via::Native => try_create_native(parent, diag_ip, prefix, host),
    }
}

fn try_create_docker(parent: &str, diag_ip: IpAddr, prefix: u8, host: &str) -> bool {
    let script = format!(
        "ip link add link {parent} name {iface} type macvlan mode bridge && \
         ip link set {iface} address {mac} && \
         ip addr add {diag_ip}/{prefix} dev {iface} && \
         ip link set {iface} up && \
         ip route add {host}/32 dev {iface} src {diag_ip}",
        parent = parent,
        iface = DIAG_IFACE,
        mac = DIAG_MAC,
        diag_ip = diag_ip,
        prefix = prefix,
        host = host,
    );
    Command::new("docker")
        .args(["run", "--rm", "--privileged", "--net=host", "alpine", "sh", "-c", &script])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn try_create_native(parent: &str, diag_ip: IpAddr, prefix: u8, host: &str) -> bool {
    let steps: [&[&str]; 5] = [
        &["link", "add", "link", parent, "name", DIAG_IFACE, "type", "macvlan", "mode", "bridge"],
        &["link", "set", DIAG_IFACE, "address", DIAG_MAC],
        &["addr", "add", &format!("{diag_ip}/{prefix}"), "dev", DIAG_IFACE],
        &["link", "set", DIAG_IFACE, "up"],
        &["route", "add", &format!("{host}/32"), "dev", DIAG_IFACE, "src", &diag_ip.to_string()],
    ];
    for s in steps {
        let ok = Command::new("ip").args(s).status().map(|x| x.success()).unwrap_or(false);
        if !ok {
            return false;
        }
    }
    true
}

fn remove_diag(via: Via, host: &str) -> std::io::Result<()> {
    match via {
        Via::Docker => {
            let script = format!(
                "ip route del {host}/32 dev {iface} 2>/dev/null; ip link del {iface} 2>/dev/null; true",
                host = host,
                iface = DIAG_IFACE,
            );
            let st = Command::new("docker")
                .args(["run", "--rm", "--privileged", "--net=host", "alpine", "sh", "-c", &script])
                .status()?;
            if !st.success() {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "docker remove failed"));
            }
            Ok(())
        }
        Via::Native => {
            use std::process::Stdio;
            let _ = Command::new("ip")
                .args(["route", "del", &format!("{host}/32"), "dev", DIAG_IFACE])
                .stdout(Stdio::null()).stderr(Stdio::null())
                .status();
            let _ = Command::new("ip")
                .args(["link", "del", DIAG_IFACE])
                .stdout(Stdio::null()).stderr(Stdio::null())
                .status();
            Ok(())
        }
    }
}

/// (الواجهة الموصلة للجهاز، عنوان IPv4 لها، البادئة)
fn parent_info(host: &str) -> Option<(String, IpAddr, u8)> {
    let route = run("ip", &["route", "get", host])?;
    let dev = crate::unlock::parse_route_dev(&route)?;
    let addr = run("ip", &["-4", "-o", "addr", "show", "dev", &dev])?;
    let (ip, prefix) = parse_addr_cidr(&addr)?;
    Some((dev, ip, prefix))
}

/// `2: enp6s0 … inet 192.168.1.9/24 brd …` → (192.168.1.9, 24)
fn parse_addr_cidr(out: &str) -> Option<(IpAddr, u8)> {
    for line in out.lines() {
        let Some(pos) = line.find("inet ") else {
            continue;
        };
        let rest = &line[pos + 5..];
        let cidr = rest.split_whitespace().next()?;
        let (ip, p) = cidr.split_once('/')?;
        let ip: IpAddr = ip.parse().ok()?;
        let prefix: u8 = p.parse().ok()?;
        return Some((ip, prefix));
    }
    None
}

/// يستبدل آخر ثماني من عنوان IPv4 (لاشتقاق عنوان macvlan حر)
fn set_last_octet(ip: IpAddr, last: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let o = (u32::from(v4) & 0xFFFF_FF00) | last as u32;
            IpAddr::V4(Ipv4Addr::from(o))
        }
        IpAddr::V6(_) => ip,
    }
}

fn is_root() -> bool {
    run("id", &["-u"]).map(|s| s.trim() == "0").unwrap_or(false)
}

fn docker_available() -> bool {
    run("docker", &["--version"]).is_some()
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_addr_cidr_works() {
        let out = "2: enp6s0 <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    link/ether 00:e0:4c:e1:08:70 brd ff:ff:ff:ff:ff:ff\n    inet 192.168.1.9/24 brd 192.168.1.255 scope global dynamic noprefixroute enp6s0\n";
        let (ip, prefix) = parse_addr_cidr(out).unwrap();
        assert_eq!(ip.to_string(), "192.168.1.9");
        assert_eq!(prefix, 24);
    }

    #[test]
    fn set_last_octet_works() {
        let ip: IpAddr = "192.168.1.9".parse().unwrap();
        assert_eq!(set_last_octet(ip, 50).to_string(), "192.168.1.50");
        assert_eq!(set_last_octet(ip, 250).to_string(), "192.168.1.250");
    }

    #[test]
    fn diag_mac_constant_matches_tool() {
        assert_eq!(DIAG_MAC, crate::unlock::DIAGNOSTIC_MAC_STR);
        assert_eq!(DIAG_MAC, "00:07:29:55:35:57");
    }
}
