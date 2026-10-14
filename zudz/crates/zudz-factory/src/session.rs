//! ذاكرة جلسة telnet (صلاحية 600).
//!
//! بعد تثبيت telnet الدائم (`CloseServerTime`/`ExitTime` ضخمة) يبقى
//! خادم telnet المصنع عاملاً بعد انتهاء الجلسة، وتعمل بياناته
//! المؤقتة لجلسات متعددة. فخزّنها هنا حتى تُعيد العمليات التالية
//! (`gpon-read` …) استخدام الجلسة العاملة دون فتح مصنع جديد —
//! لأن فتحاً جديداً لا يستطيع استبدال خادم عامل (المنفذ مشغول
//! ببيانات الجلسة القديمة).

use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct SessionFile {
    host: String,
    user: String,
    pass: String,
}

/// هل منفذ telnet (23) مفتوح على الجهاز؟ (فحص TCP قصير بلا اتصال فعلي)
pub fn port_open(host: &str, timeout_ms: u64) -> bool {
    use std::net::ToSocketAddrs;
    use std::time::Duration;
    let Ok(mut addrs) = (host, 23u16).to_socket_addrs() else {
        return false;
    };
    let Some(addr) = addrs.next() else {
        return false;
    };
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).is_ok()
}

/// ينتظر حتى يُفتح منفذ telnet (استطلاع دوري حتى المهلة الكلية).
/// يُستخدَم بعد فتح المصنع — telnetd قد يتأخر عن الاستماع لحظة.
pub fn wait_port_open(host: &str, total_ms: u64) -> bool {
    let start = std::time::Instant::now();
    loop {
        if port_open(host, 1000) {
            return true;
        }
        if start.elapsed().as_millis() >= total_ms as u128 {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

fn state_dir() -> PathBuf {
    if let Ok(d) = std::env::var("XDG_STATE_HOME") {
        if !d.is_empty() {
            return PathBuf::from(d).join("zudz");
        }
    }
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return PathBuf::from(h).join(".local").join("state").join("zudz");
        }
    }
    PathBuf::from("/tmp/zudz-state")
}

/// مسار ملف ذاكرة الجلسة للجهاز
pub fn session_path(host: &str) -> PathBuf {
    state_dir().join(format!("telnet-{host}.json"))
}

/// يخزّن بيانات الجلسة المؤقتة (صلاحية 600 — حساسة)
pub fn save_session(host: &str, user: &str, pass: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir())?;
    let p = session_path(host);
    let s = SessionFile {
        host: host.into(),
        user: user.into(),
        pass: pass.into(),
    };
    std::fs::write(&p, serde_json::to_vec(&s).unwrap_or_default())?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
}

/// يقرأ بيانات الجلسة المخزّنة للجهاز (إن وُجدت وصحت)
pub fn load_session(host: &str) -> Option<(String, String)> {
    let Ok(data) = std::fs::read_to_string(session_path(host)) else {
        return None;
    };
    let Ok(s) = serde_json::from_str::<SessionFile>(&data) else {
        return None;
    };
    if s.host != host {
        return None;
    }
    Some((s.user, s.pass))
}

/// يزيل ذاكرة الجلسة (بعد فشل دخول مثلاً)
pub fn clear_session(host: &str) {
    let _ = std::fs::remove_file(session_path(host));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_roundtrip() {
        // مضيف اختباري غير قابل للتوجيه (TEST-NET-2) — لا يمسّ ذاكرة جهاز حقيقي
        let h = "198.51.100.9";
        save_session(h, "u", "p").unwrap();
        assert_eq!(load_session(h), Some(("u".into(), "p".into())));
        clear_session(h);
        assert_eq!(load_session(h), None);
    }
}
