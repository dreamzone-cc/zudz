//! التحكم بـ MAC بطاقة الشبكة — تغيير تلقائي مؤقت مع استرجاع مضمون
//!
//! النمط: عند بدء التطبيق تُنشأ عملية حارسة مرتفعة الصلاحيات (عبر نافذة كلمة
//! سر مخصصة عند الحاجة) تضبط العنوان التشخيصي على كرت الشبكة الموصل للجهاز،
//! ثم تراقب حياة الخادم عبر /proc؛ متى مات الخادم — إغلاقاً طبيعياً أو انهياراً —
//! تُعيد العنوان الأصلي تلقائياً خلال ثانية. لا يبقى أي تغيير بعد الإغلاق.

use crate::unlock::{mac_str, DIAGNOSTIC_MAC};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// آلية الترقية المتاحة — بترتيب الأفضلية
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    /// sudo بدون كلمة سر (مُكوَّن مسبقاً)
    SudoNoPrompt,
    /// نافذة المصادقة الرسومية لـ polkit
    PkexecDialog,
    /// نافذة كلمة سر مخصصة عبر kdialog ثم sudo -S
    Kdialog,
    /// نافذة كلمة سر مخصصة عبر zenity ثم sudo -S
    Zenity,
    /// sudo داخل الطرفية (عند التشغيل اليدوي من طرفية فقط)
    SudoTty,
    /// لا شيء متاح
    None,
}

/// اختيار آلية الترقية — دالة نقية قابلة للاختبار
pub fn choose_elevation(
    sudo_n: bool,
    pkexec: bool,
    kdialog: bool,
    zenity: bool,
    has_tty: bool,
) -> Elevation {
    if sudo_n {
        Elevation::SudoNoPrompt
    } else if pkexec {
        Elevation::PkexecDialog
    } else if kdialog {
        Elevation::Kdialog
    } else if zenity {
        Elevation::Zenity
    } else if has_tty {
        Elevation::SudoTty
    } else {
        Elevation::None
    }
}

fn have(prog: &str) -> bool {
    let ok = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {prog} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    ok
}

/// اكتشاف الآلية المتاحة على هذا النظام الآن
pub fn detect_elevation() -> Elevation {
    let sudo_n = Command::new("sudo")
        .args(["-n", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    choose_elevation(
        sudo_n,
        have("pkexec"),
        have("kdialog"),
        have("zenity"),
        std::io::stdin().is_terminal(),
    )
}

/// اسم واجهة صالح فقط إن كان أبجدياً رقمياً بلا محارف خاصة (يُمرَّر لسطر أوامر)
pub fn valid_iface(iface: &str) -> bool {
    !iface.is_empty()
        && iface.len() <= 15
        && iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// يقرأ MAC بنص "aa:bb:cc:dd:ee:ff"
pub fn parse_mac_str(s: &str) -> Option<[u8; 6]> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() != 12 {
        return None;
    }
    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(mac)
}

/// يضبط MAC واجهة (down ← address ← up)
pub fn set_mac(iface: &str, mac: &[u8; 6]) -> std::io::Result<()> {
    if !valid_iface(iface) {
        return Err(std::io::Error::other(format!("اسم واجهة غير صالح: {iface:?}")));
    }
    let addr = mac_str(mac);
    for step in [
        vec!["link", "set", "dev", iface, "down"],
        vec!["link", "set", "dev", iface, "address", &addr],
        vec!["link", "set", "dev", iface, "up"],
    ] {
        let st = Command::new("ip").args(&step).status()?;
        if !st.success() {
            return Err(std::io::Error::other(format!(
                "فشل الأمر: ip {} (هل نعمل بصفة root؟)",
                step.join(" ")
            )));
        }
    }
    Ok(())
}

const DIALOG_TITLE: &str = "ZUDZ — temporary MAC change";

/// يطلق العملية الحارسة المرتفعة الصلاحيات التي تدير دورة حياة MAC كاملة.
/// تُرجع Ok بعد إثبات أن العنوان التشخيصي صار فعّالاً على الواجهة.
pub fn spawn_mac_watch(
    parent_pid: u32,
    iface: &str,
    original: &str,
    log_path: &Path,
) -> Result<(), String> {
    if !valid_iface(iface) || parse_mac_str(original).is_none() {
        return Err(format!("معطيات غير صالحة: iface={iface:?} original={original:?}"));
    }
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let args = [
        "--mac-watch".to_string(),
        parent_pid.to_string(),
        iface.to_string(),
        original.to_string(),
    ];
    if let Some(dir) = log_path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| format!("فتح سجل الحارس: {e}"))?;

    let mode = detect_elevation();
    match mode {
        Elevation::SudoNoPrompt | Elevation::PkexecDialog | Elevation::SudoTty => {
            let mut cmd = Command::new(match mode {
                Elevation::SudoNoPrompt => "sudo",
                Elevation::PkexecDialog => "pkexec",
                _ => "sudo",
            });
            if mode == Elevation::SudoNoPrompt {
                cmd.arg("-n");
            }
            cmd.arg(&exe)
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
                .stderr(Stdio::from(log))
                .spawn()
                .map_err(|e| format!("إطلاق الحارس ({mode:?}): {e}"))?;
        }
        Elevation::Kdialog | Elevation::Zenity => {
            // نافذة كلمة السر المخصصة، ثم sudo -S (لا تُطبع كلمة السر في أي سجل)
            let (prog, dlg_args): (&str, Vec<&str>) = if mode == Elevation::Kdialog {
                ("kdialog", vec!["--password", "ZUDZ يحتاج صلاحيات المدير لتغيير MAC مؤقتاً — يُسترجع تلقائياً عند الإغلاق"])
            } else {
                ("zenity", vec!["--password", "--title", DIALOG_TITLE])
            };
            let out = Command::new(prog)
                .args(&dlg_args)
                .output()
                .map_err(|e| format!("تشغيل {prog}: {e}"))?;
            if !out.status.success() {
                return Err("أُلغي إدخال كلمة المرور".into());
            }
            let pw = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if pw.is_empty() {
                return Err("كلمة مرور فارغة".into());
            }
            let mut child = Command::new("sudo")
                .args(["-S", "-p", "", "--"])
                .arg(&exe)
                .args(&args)
                .stdin(Stdio::piped())
                .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
                .stderr(Stdio::from(log))
                .spawn()
                .map_err(|e| format!("إطلاق الحارس عبر sudo: {e}"))?;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(pw.as_bytes());
                let _ = stdin.write_all(b"\n");
                let _ = stdin.flush();
            }
            drop(pw);
        }
        Elevation::None => {
            return Err(
                "لا توجد طريقة ترقية متاحة: شغّل التطبيق من طرفية، أو ثبّت pkexec (polkit) أو zenity/kdialog".into(),
            );
        }
    }

    // انتظار إثبات التفعيل: MAC الواجهة الهدف يصبح التشخيصي (حتى 10 ثوانٍ)
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(250));
        if let Ok(out) = Command::new("ip").args(["-o", "link", "show", "dev", iface]).output() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(mac) = crate::unlock::parse_link_mac(&text) {
                if mac == DIAGNOSTIC_MAC {
                    return Ok(());
                }
            }
        }
    }
    Err("انتهت مهلة انتظار تفعيل MAC التشخيصي — راجع سجل الحارس".into())
}

/// جسم العملية الحارسة (تعمل بصفة root): يفعّل التشخيصي ثم يراقب الأب ويعيد الأصلي
pub fn mac_watch_main(parent_pid: u32, iface: &str, original: &str) -> i32 {
    let Some(orig) = parse_mac_str(original) else {
        eprintln!("mac-watch: عنوان أصلي غير صالح: {original:?}");
        return 2;
    };
    if !valid_iface(iface) {
        eprintln!("mac-watch: اسم واجهة غير صالح: {iface:?}");
        return 2;
    }
    // الأب مات قبل البدء — لا نغيّر شيئاً
    if !Path::new(&format!("/proc/{parent_pid}")).exists() {
        eprintln!("mac-watch: العملية الأم ({parent_pid}) غير موجودة — لا حاجة للتغيير");
        return 0;
    }
    if let Err(e) = set_mac(iface, &DIAGNOSTIC_MAC) {
        eprintln!("mac-watch: فشل ضبط MAC التشخيصي على {iface}: {e}");
        return 3;
    }
    eprintln!("mac-watch: ✔ MAC التشخيصي {} مفعل على {iface}", mac_str(&DIAGNOSTIC_MAC));

    loop {
        std::thread::sleep(Duration::from_millis(1000));
        if !Path::new(&format!("/proc/{parent_pid}")).exists() {
            break;
        }
    }

    match set_mac(iface, &orig) {
        Ok(()) => {
            eprintln!("mac-watch: ✔ استُرجع MAC الأصلي {} على {iface}", mac_str(&orig));
            0
        }
        Err(e) => {
            eprintln!("mac-watch: ✗ فشل استرجاع MAC الأصلي على {iface}: {e}");
            eprintln!("mac-watch: استرجعه يدوياً: sudo ip link set dev {iface} address {}", mac_str(&orig));
            4
        }
    }
}

/// مسار سجل الحارس الافتراضي
pub fn default_log_path() -> PathBuf {
    let state = std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".local/state")
        });
    state.join("zudz/mac-watch.log")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevation_order() {
        use Elevation::*;
        assert_eq!(choose_elevation(true, true, true, true, true), SudoNoPrompt);
        assert_eq!(choose_elevation(false, true, false, false, true), PkexecDialog);
        assert_eq!(choose_elevation(false, false, true, true, true), Kdialog);
        assert_eq!(choose_elevation(false, false, false, true, false), Zenity);
        assert_eq!(choose_elevation(false, false, false, false, true), SudoTty);
        assert_eq!(choose_elevation(false, false, false, false, false), None);
    }

    #[test]
    fn iface_validation() {
        assert!(valid_iface("enp6s0"));
        assert!(valid_iface("eth0"));
        assert!(valid_iface("wlan-1.x"));
        assert!(!valid_iface(""));
        assert!(!valid_iface("a;b"));
        assert!(!valid_iface("$(reboot)"));
        assert!(!valid_iface("with space"));
        assert!(!valid_iface("toolonginterface-name"));
    }

    #[test]
    fn mac_parsing() {
        assert_eq!(parse_mac_str("00:07:29:55:35:57"), Some(DIAGNOSTIC_MAC));
        assert_eq!(parse_mac_str("000729553557"), Some(DIAGNOSTIC_MAC));
        assert_eq!(parse_mac_str("00:07:29"), None);
        assert_eq!(parse_mac_str("zz:07:29:55:35:57"), None);
        assert_eq!(parse_mac_str(""), None);
    }
}
