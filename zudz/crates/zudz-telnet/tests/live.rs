//! اختبار حي اختياري: يُفعَّل بـ ZUDZ_LIVE=192.168.1.1
//! يفتح المصنع (zudz-factory) ثم يسجل telnet (zudz-telnet) ويقرأ هوية GPON.

fn hex_ascii_to_string(out: &str) -> String {
    // الجهاز يطبع القيم كسلسلة بايتات ASCII مفصولة بمسافات: "44 39 ..." → "D9..."
    let bytes: Vec<u8> = out
        .split_whitespace()
        .filter_map(|t| u8::from_str_radix(t, 16).ok())
        .filter(|b| b.is_ascii_graphic())
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
#[ignore = "تشغيل يدوي: ZUDZ_LIVE=ip cargo test -p zudz-telnet --test live -- --ignored"]
fn live_unlock_and_show2() {
    let host = match std::env::var("ZUDZ_LIVE") {
        Ok(h) if !h.is_empty() => h,
        _ => return, // بلا متغير: تخطَّ بهدوء
    };
    let r = zudz_factory::unlock_telnet(&host, "admin", "admin").expect("unlock");
    eprintln!("🔓 {}/{}", r.telnet_user, r.telnet_pass);

    let mut tn = zudz_telnet::ZteTelnet::connect(&host, 23, 12).expect("telnet connect");
    tn.login(&r.telnet_user, &r.telnet_pass).expect("login");
    let _ = tn.run_capture("", 2); // تسخين

    let out = tn.run_capture("setmac 2 2177", 6);
    eprintln!("setmac 2 2177 → {out}");
    let decoded = hex_ascii_to_string(&out);
    assert!(
        decoded.len() == 8 && decoded.chars().all(|c| c.is_ascii_hexdigit()),
        "GPON SN غير صحيح: {decoded}"
    );

    let out2 = tn.run_capture("setmac 2 2178", 6);
    let decoded2 = hex_ascii_to_string(&out2);
    eprintln!("setmac 2 2178 → {decoded2}");
    assert!(!decoded2.is_empty(), "GPON PWD فارغ");
}
