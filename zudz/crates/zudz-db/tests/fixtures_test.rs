//! اختبارات zudz-db على أصول Oracle
//!
//! العينة العامة (h298n) موجودة دائماً في المستودع،
//! أما عينتا F6600P/تايلاند فهما ملفان محليان خاصان (يحتويان بيانات أجهزة حقيقية
//! فلا تُرفع للمستودع) — يُتخطى الاختباران تلقائياً في غيابهما.
//! ضع الملف محلياً في المسار المذكور لتشغيل الاختبار.

use zudz_db::{extract, parse_db};

fn try_fixture(p: &str) -> Option<String> {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::fs::read_to_string(base.join(p)).ok()
}

#[test]
fn f6600p_sample_extraction() {
    let Some(xml) = try_fixture("tests/fixtures/configs/f6600p_type5.xml") else {
        eprintln!("⏭ تخطٍّ: عينة F6600P الخاصة غير موجودة محلياً");
        return;
    };
    let db = parse_db(&xml);
    assert!(db.len() > 200, "عدد الجداول: {}", db.len());
    let ex = extract(&db);

    assert_eq!(ex.device.config_label, "F660A");
    assert_eq!(ex.device.provisioning_code, "TLCO.GRP2");

    // WiFi: يوجد نطاقان على الأقل (2.4G/5G) بكلمة مرور WPA من 8 أحرف
    assert!(ex.wifi.len() >= 2, "شبكات WiFi: {}", ex.wifi.len());
    assert!(ex
        .wifi
        .iter()
        .all(|w| w.ssid.starts_with("ZTE_") && w.password.len() >= 8));

    // حسابات الويب: مستخدم غير فارغ بكلمة مرور، وحساب telnet = root
    assert!(ex
        .accounts
        .web
        .iter()
        .all(|a| !a.user.is_empty() && !a.password.is_empty()));
    assert_eq!(ex.accounts.telnet_user, "root");
    assert!(ex.accounts.telnet_password.starts_with("ZTEG"));

    // WAN: DHCP مع VLAN 10
    assert!(ex.wan.iter().any(|w| w.vlan == "10" && w.kind == "DHCP"));
    assert!(ex.wan.iter().any(|w| w.kind == "PPPoE"));
}

#[test]
fn thailand_sample_extraction() {
    let Some(xml) = try_fixture("../db_default_Thailand_cfg1.xml") else {
        eprintln!("⏭ تخطٍّ: عينة تايلاند غير موجودة محلياً");
        return;
    };
    let db = parse_db(&xml);
    let ex = extract(&db);
    assert_eq!(ex.device.config_label, "F660A");
    let names: Vec<&str> = ex.wan.iter().map(|w| w.name.as_str()).collect();
    assert!(names.contains(&"TR069_INTERNET"), "WAN: {names:?}");
    assert!(names.contains(&"THSi"));
}
