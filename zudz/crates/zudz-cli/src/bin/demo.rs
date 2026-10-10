//! ZUDZ demo — التدفق الكامل في أمر واحد على الجهاز الحي:
//! unlock → telnet → هوية GPON + خيارات pppd → فك كلمة المرور.

use zudz_gpon::parse_show2;

fn hex_ascii_to_string(out: &str) -> String {
    let bytes: Vec<u8> = out
        .split_whitespace()
        .filter_map(|t| u8::from_str_radix(t, 16).ok())
        .filter(|b| b.is_ascii_graphic())
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn main() {
    let host = std::env::args().nth(1).unwrap_or_else(|| "192.168.1.1".into());
    println!("╔══════════════════════════════════════════════╗");
    println!("║   ZUDZ — ZTE Unlock, Decrypt & Zone-changer  ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("الهدف: {host}\n");

    // ① وضع المصنع
    println!("[1/4] فتح وضع المصنع (STEP 0-5)…");
    let r = match zudz_factory::unlock_telnet(&host, "admin", "admin") {
        Ok(r) => r,
        Err(e) => {
            eprintln!("❌ {e} — قد يكون تقييد المعدل، أعد المحاولة بعد ثوانٍ");
            std::process::exit(1);
        }
    };
    println!("      ✅ telnet: {} / {}", r.telnet_user, r.telnet_pass);

    // ② telnet
    println!("[2/4] تسجيل الدخول عبر telnet…");
    let mut tn = match zudz_telnet::ZteTelnet::connect(&host, 23, 12) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("❌ {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = tn.login(&r.telnet_user, &r.telnet_pass) {
        eprintln!("❌ {e}");
        std::process::exit(1);
    }
    println!("      ✅ داخل الجهاز");
    let _ = tn.run_capture("", 2);

    // ③ هوية GPON
    println!("[3/4] قراءة هوية GPON…");
    let _ = tn.run_capture("setmac show2 > /tmp/zudz_show2.txt 2>&1", 3);
    let show2_raw = tn.run_capture("cat /tmp/zudz_show2.txt", 4);
    let parsed = parse_show2(&show2_raw);
    let vid = parsed.get(&2176).cloned().unwrap_or_default();
    let sn8 = parsed.get(&2177).cloned().unwrap_or_default();
    let pwd = parsed.get(&2178).cloned().unwrap_or_default();
    println!("      GPON SN : {vid}{sn8}");
    println!("      PLOAM   : {pwd}");
    println!("      MAC     : {}", parsed.get(&256).cloned().unwrap_or_default());

    // ④ خيارات pppd
    println!("[4/4] قراءة خيارات pppd…");
    let opts = tn.run_capture("cat /var/tmp/ppp/options.* 2>/dev/null", 4);
    let mut user = String::new();
    let mut encpwd = String::new();
    let mut vlan = String::new();
    for line in opts.lines() {
        if let Some(v) = line.strip_prefix("user ") {
            user = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("encrypasswd ") {
            encpwd = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("vlan ") {
            vlan = v.trim().to_string();
        }
    }
    let _ = tn.run_capture("rm -f /tmp/zudz_show2.txt", 2);
    println!("      PPPoE   : {user} @ VLAN {vlan}");
    if !encpwd.is_empty() {
        match zudz_crypto::decrypt_encrypasswd(&encpwd) {
            Ok(p) => println!("      كلمة المرور: {p}"),
            Err(e) => println!("      (فك encrypasswd فشل: {e})"),
        }
    }

    println!("\n✅ اكتمل التشغيل — كل هذه البيانات من نواة Rust مباشرة.");
}
