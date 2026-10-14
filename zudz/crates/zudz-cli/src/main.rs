//! ZUDZ CLI — ZTE Unlock, Decrypt & Zone-changer

use clap::{Parser, Subcommand};
use zudz_crypto::{decrypt_auto, inspect, DecryptParams};
use zudz_meta::{self as meta};

#[derive(Parser)]
#[command(name = "zudz", version, about = "ZUDZ — ZTE Unlock, Decrypt & Zone-changer",
    long_about = meta::notice())]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// فحص بنية ملف إعدادات ZTE
    Inspect { file: String },
    /// فك تشفير ملف إعدادات (أنواع 0-5)
    Decrypt {
        infile: String,
        outfile: String,
        #[arg(long)] signature: Option<String>,
        #[arg(long)] serial: Option<String>,
        #[arg(long)] mac: Option<String>,
        #[arg(long)] password: Option<String>,
        #[arg(long)] key: Option<String>,
        #[arg(long)] iv: Option<String>,
        #[arg(long)] model: Option<String>,
    },
    /// فك كلمة مرور pppd (encrypasswd)
    EncryPasswd { hex: String },
    /// فتح telnet على الجهاز (وضع المصنع)
    Unlock {
        #[arg(long, default_value = "192.168.1.1")] host: String,
        #[arg(long, default_value = "admin")] user: String,
        #[arg(long, default_value = "admin")] password: String,
    },
    /// إدارة مسار MAC التشخيصي (الجهاز يفتح telnet فقط من 00:07:29:55:35:57)
    DiagRoute {
        /// setup | remove | status
        action: String,
        #[arg(long, default_value = "192.168.1.1")] host: String,
    },
    /// تحليل مخرجات setmac show2
    TagParams { file: String },
    /// الاستخراج الموحد من الجهاز الحي (مصنع + telnet + pppd + ذاكرة cspd + ويب)
    ExtractAll {
        #[arg(long, default_value = "192.168.1.1")] host: String,
        #[arg(long, default_value = "admin")] user: String,
        #[arg(long, default_value = "admin")] password: String,
        #[arg(long)] out: Option<String>,
        #[arg(long, default_value = "true")] with_web: bool,
        /// لا تُثبّت telnet الدائم (CloseServerTime/ExitTime) بعد الفتح
        #[arg(long, default_value = "false")] no_perm_telnet: bool,
    },
    /// جدول مناطق ZTE (sdefconf)
    RegionList,
    /// بوابة الأمان: سحب كامل إلزامي قبل تغيير المنطقة — يولّد ack token
    RegionPrepare {
        #[arg(long, default_value = "192.168.1.1")] host: String,
        #[arg(long, default_value = "admin")] user: String,
        #[arg(long, default_value = "admin")] password: String,
        #[arg(long, default_value = "region_backup")] out: String,
    },
    /// تنفيذ تغيير المنطقة (يمسح إعدادات المزود! — تُسحب نسخة احتياطية تلقائياً قبل التنفيذ عند ترك ack فارغاً)
    RegionChange {
        #[arg(long, default_value = "192.168.1.1")] host: String,
        #[arg(long, default_value = "admin")] user: String,
        #[arg(long, default_value = "admin")] password: String,
        #[arg(long)] code: u32,
        /// اختياري: توكن من region-prepare — عند تركه فارغاً يُسحب احتياطياً كاملاً تلقائياً أولاً
        #[arg(long, default_value = "")] ack: String,
        #[arg(long, default_value = "region_backup")] out: String,
        #[arg(long)] force_unknown: bool,
        #[arg(long, default_value = "true")] perm_telnet: bool,
    },
    /// قراءة هوية GPON من الجهاز
    GponRead {
        #[arg(long, default_value = "192.168.1.1")] host: String,
        #[arg(long, default_value = "admin")] user: String,
        #[arg(long, default_value = "admin")] password: String,
    },
    /// استنساخ هوية GPON من report.json إلى الجهاز الهدف (تُسحب نسخة تلقائية لهوية الجهاز الهدف أولاً)
    GponClone {
        #[arg(long, default_value = "192.168.1.1")] host: String,
        #[arg(long, default_value = "admin")] user: String,
        #[arg(long, default_value = "admin")] password: String,
        /// مسار report.json من extract-all/prepare
        #[arg(long)] report: String,
        #[arg(long, default_value = "zudz_gpon_backup")] out: String,
    },
    /// كتابة هوية GPON بقيم صريحة (تُسحب نسخة تلقائية لهوية الجهاز الحالية أولاً)
    GponWrite {
        #[arg(long, default_value = "192.168.1.1")] host: String,
        #[arg(long, default_value = "admin")] user: String,
        #[arg(long, default_value = "admin")] password: String,
        #[arg(long)] vid: String,
        #[arg(long)] sn8: String,
        #[arg(long, default_value = "")] ploam: String,
        #[arg(long, default_value = "zudz_gpon_backup")] out: String,
    },
    /// معلومات المشروع: المطوّر والترخيص والغرض
    About,
}

fn main() {
    let cli = Cli::parse();
    let rc = match cli.cmd {
        Cmd::Inspect { file } => cmd_inspect(&file),
        Cmd::Decrypt { infile, outfile, signature, serial, mac, password, key, iv, model } => {
            cmd_decrypt(&infile, &outfile, signature, serial, mac, password, key, iv, model)
        }
        Cmd::EncryPasswd { hex } => match zudz_crypto::decrypt_encrypasswd(&hex) {
            Ok(p) => {
                println!("{p}");
                0
            }
            Err(e) => {
                eprintln!("❌ {e}");
                1
            }
        },
        Cmd::Unlock { host, user, password } => cmd_unlock(&host, &user, &password),
        Cmd::DiagRoute { action, host } => cmd_diag_route(&action, &host),
        Cmd::TagParams { file } => match std::fs::read_to_string(&file) {
            Ok(text) => {
                let parsed = zudz_gpon::parse_show2(&text);
                for (id, v) in &parsed {
                    println!("{id:>5} | {} | {v}", zudz_gpon::tag_name(*id));
                }
                0
            }
            Err(e) => {
                eprintln!("❌ {e}");
                1
            }
        },
        Cmd::ExtractAll { host, user, password, out, with_web, no_perm_telnet } =>
            cmd_extract_all(&host, &user, &password, out, with_web, no_perm_telnet),
        Cmd::RegionList => {
            println!("{:>5} | {:<34} | {:<6} | source", "code", "region", "tested");
            for r in zudz_region::REGIONS {
                println!("{:>5} | {:<34} | {:<6} | {}",
                    r.code, r.name, if r.verified { "YES" } else { "-" }, r.source);
            }
            0
        }
        Cmd::RegionPrepare { host, user, password, out } => cmd_region_prepare(&host, &user, &password, &out),
        Cmd::RegionChange { host, user, password, code, ack, out, force_unknown, perm_telnet } =>
            cmd_region_change(&host, &user, &password, code, &ack, &out, force_unknown, perm_telnet),
        Cmd::GponRead { host, user, password } => cmd_gpon_read(&host, &user, &password),
        Cmd::GponClone { host, user, password, report, out } => cmd_gpon_clone(&host, &user, &password, &report, &out),
        Cmd::GponWrite { host, user, password, vid, sn8, ploam, out } =>
            cmd_gpon_write(&host, &user, &password, &vid, &sn8, &ploam, &out),
        Cmd::About => {
            println!("{}", meta::notice());
            0
        }
    };
    std::process::exit(rc);
}

/// فتح telnet عبر وضع المصنع — مع توجيه MAC التشخيصي وفحص المنفذ وتخزين الجلسة.
fn cmd_unlock(host: &str, user: &str, password: &str) -> i32 {
    // توجيه عبر MAC التشخيصي — يبقى فعّالاً حتى تستطيع telnet بنفسك
    match zudz_factory::diagmac::setup_diag_route(host) {
        Ok(mode) => println!("🔌 مسار MAC التشخيصي فعّال: {mode}"),
        Err(e) => eprintln!("⚠️  {e} — سأحاول الفتح مباشرة (قد لا يُنشأ telnetd)"),
    }
    match zudz_factory::unlock_telnet(host, user, password) {
        Ok(r) => {
            println!("✅ factory mode — telnet: {} / {}", r.telnet_user, r.telnet_pass);
            println!("   aes_key={} server_mac={}", r.aes_key, r.server_mac);
            let _ = zudz_factory::session::save_session(host, &r.telnet_user, &r.telnet_pass);
            if zudz_factory::session::wait_port_open(host, 8000) {
                println!("   المنفذ 23 مفتوح ✅ (خُزّنت الجلسة — يمكن للعمليات التالية إعادة استخدامها)");
                0
            } else {
                eprintln!(
                    "⚠️  المنفذ 23 مغلق — الجهاز يشترط أن يأتي الطلب من MAC التشخيصي {}. \
                     فعّله بـ: zudz diag-route setup",
                    zudz_factory::DIAGNOSTIC_MAC_STR
                );
                1
            }
        }
        Err(e) => {
            eprintln!("❌ {e}");
            1
        }
    }
}

/// إدارة مسار MAC التشخيصي (setup | remove | status).
fn cmd_diag_route(action: &str, host: &str) -> i32 {
    match action {
        "setup" => match zudz_factory::diagmac::setup_diag_route(host) {
            Ok(mode) => {
                println!("✅ مسار MAC التشخيصي فعّال ({mode})");
                println!("   المنفذ 23 الآن: {}", if zudz_factory::session::port_open(host, 1200) { "مفتوح" } else { "مغلق (افتح المصنع: zudz unlock)" });
                0
            }
            Err(e) => {
                eprintln!("❌ {e}");
                1
            }
        },
        "remove" => {
            zudz_factory::diagmac::remove_diag_route(host);
            println!("✅ أُزيل مسار MAC التشخيصي");
            0
        }
        "status" => {
            if zudz_factory::diagmac::nic_is_diagnostic(host) {
                println!("✅ كرت الشبكة الموصل للجهاز يحمل MAC التشخيصي أصلاً");
            } else if zudz_factory::diagmac::diag_route_active(host) {
                println!("✅ مسار MAC التشخيصي نشط");
            } else if let Ok(Some((dev, mac))) = zudz_factory::nic_mac_towards(host) {
                println!(
                    "❌ لا مسار تشخيصي — كرت {dev} ماكه {} (ليس {}). \
                     فعّله بـ: zudz diag-route setup",
                    zudz_factory::mac_str(&mac),
                    zudz_factory::DIAGNOSTIC_MAC_STR
                );
            } else {
                println!("❌ لا مسار شبكي إلى {host}");
            }
            println!("   المنفذ 23: {}", if zudz_factory::session::port_open(host, 1200) { "مفتوح" } else { "مغلق" });
            0
        }
        _ => {
            eprintln!("❌ استخدم: zudz diag-route <setup|remove|status> [--host H]");
            1
        }
    }
}

fn cmd_extract_all(host: &str, user: &str, password: &str, out: Option<String>, with_web: bool, no_perm_telnet: bool) -> i32 {
    let opts = zudz_extract::ExtractOptions {
        host: host.to_string(),
        web_user: user.to_string(),
        web_password: password.to_string(),
        with_web,
        with_perm_telnet: !no_perm_telnet,
    };
    println!("🔎 ZUDZ extract-all → {host} (مسارات: tagparams + pppd + cspd-shm{}{})",
        if with_web { " + web" } else { "" }, "");
    match zudz_extract::extract_all(&opts) {
        Ok(rep) => {
            let md = zudz_extract::report_markdown(&rep);
            println!("{md}");
            if let Some(dir) = out {
                let p = std::path::Path::new(&dir);
                let _ = std::fs::create_dir_all(p);
                let _ = std::fs::write(p.join("report.json"), zudz_extract::report_json(&rep));
                let _ = std::fs::write(p.join("report.md"), &md);
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(p.join("report.json"), std::fs::Permissions::from_mode(0o600));
                let _ = std::fs::set_permissions(p.join("report.md"), std::fs::Permissions::from_mode(0o600));
                println!("✅ حُفظ {dir}/report.json و report.md (صلاحية 600)");
            }
            0
        }
        Err(e) => {
            eprintln!("❌ {e}");
            1
        }
    }
}

fn cmd_region_prepare(host: &str, user: &str, password: &str, out: &str) -> i32 {
    println!("⛔ بوابة الأمان: سحب كامل إلزامي قبل تغيير المنطقة (لأن sdefconf يمسح إعدادات المزود)…");
    let opts = zudz_extract::ExtractOptions {
        host: host.into(), web_user: user.into(), web_password: password.into(), with_web: true, with_perm_telnet: true,
    };
    match zudz_region::prepare_region_change(&opts, std::path::Path::new(out)) {
        Ok(p) => {
            let r = &p.report;
            println!("✅ السحب الاستباقي اكتمل — النسخة الاحتياطية في {out}/");
            println!("   PPPoE: {} / {} @ VLAN {}", r.pppoe.username, r.pppoe.password, r.pppoe.vlan);
            println!("   SIP  : {} / {}", r.voip.sip_uri, r.voip.password);
            println!("   GPON : {} / {}", r.gpon.full_sn, r.gpon.ploam_password);
            println!();
            println!("🔑 ACK TOKEN (صالح ساعة، لمرة واحدة):");
            println!("   {}", p.token);
            println!();
            println!("للتنفيذ: zudz region-change --host {host} --code <N> --ack {}", p.token);
            0
        }
        Err(e) => { eprintln!("❌ {e}"); 1 }
    }
}

fn cmd_region_change(host: &str, user: &str, password: &str, code: u32, ack: &str, out: &str, force_unknown: bool, perm_telnet: bool) -> i32 {
    if let Some(r) = zudz_region::find_region(code) {
        println!("🌍 تغيير المنطقة إلى {code} ({})", r.name);
    } else if force_unknown {
        println!("🌍 كود مخصص {code} (--force-unknown)");
    } else {
        eprintln!("❌ كود غير معروف — region-list للاستعراض أو --force-unknown");
        return 1;
    }
    println!("⚠️  هذا سيمسح إعدادات المزود الحالية ويعيد التشغيل!");
    if ack.trim().is_empty() {
        println!("🛡️  لا توكن — سيُسحب احتياطياً كاملاً تلقائياً قبل التنفيذ (الإلغاء تلقائي إن فشل السحب)");
    }
    let opts = zudz_extract::ExtractOptions {
        host: host.into(), web_user: user.into(), web_password: password.into(), with_web: false, with_perm_telnet: true,
    };
    match zudz_region::change_region(&opts, code, ack, std::path::Path::new(out), force_unknown, perm_telnet) {
        Ok(res) => {
            if let Some(b) = &res.backup {
                println!("🛡️  نسخة احتياطية تلقائية قبل التنفيذ: {}", b.report_path);
            }
            println!("✅ نُفّذ sdefconf {} — {}", res.code, res.note);
            if res.permanent_telnet_applied {
                println!("   telnet دائم: admin/admin");
            }
            println!("─── مخرجات الجهاز ───");
            println!("{}", res.raw_output);
            0
        }
        Err(e) => { eprintln!("❌ {e}"); 1 }
    }
}

fn cmd_gpon_read(host: &str, user: &str, password: &str) -> i32 {
    let opts = zudz_extract::ExtractOptions {
        host: host.into(), web_user: user.into(), web_password: password.into(), with_web: false, with_perm_telnet: true,
    };
    match zudz_region::gpon_read(&opts) {
        Ok(tp) => {
            println!("VID  [2176]: {}", tp.get(&2176).cloned().unwrap_or_default());
            println!("SN8  [2177]: {}", tp.get(&2177).cloned().unwrap_or_default());
            println!("PWD  [2178]: {}", tp.get(&2178).cloned().unwrap_or_default());
            println!("MAC  [256] : {}", tp.get(&256).cloned().unwrap_or_default());
            0
        }
        Err(e) => { eprintln!("❌ {e}"); 1 }
    }
}

fn cmd_gpon_clone(host: &str, user: &str, password: &str, report: &str, out: &str) -> i32 {
    println!("🧬 استنساخ هوية GPON من {report} → {host}");
    println!("🛡️  ستُسحب نسخة تلقائية لهوية الجهاز الهدف الحالية إلى {out} قبل الكتابة");
    let opts = zudz_extract::ExtractOptions {
        host: host.into(), web_user: user.into(), web_password: password.into(), with_web: false, with_perm_telnet: true,
    };
    match zudz_region::gpon_clone_from_report(&opts, std::path::Path::new(report), std::path::Path::new(out)) {
        Ok(res) => {
            if let Some(b) = &res.backup {
                println!("🛡️  نسخة احتياطية تلقائية: {}", b.report_path);
            }
            for c in &res.commands_run { println!("  $ {c}"); }
            println!("─── مخرجات الجهاز ───");
            println!("{}", res.raw_output);
            println!("✅ اكتمل — أعد تشغيل الجهاز الهدف وراقب مؤشر PON");
            0
        }
        Err(e) => { eprintln!("❌ {e}"); 1 }
    }
}

fn cmd_gpon_write(host: &str, user: &str, password: &str, vid: &str, sn8: &str, ploam: &str, out: &str) -> i32 {
    println!("🛡️  ستُسحب نسخة تلقائية لهوية الجهاز الحالية إلى {out} قبل الكتابة");
    let opts = zudz_extract::ExtractOptions {
        host: host.into(), web_user: user.into(), web_password: password.into(), with_web: false, with_perm_telnet: true,
    };
    match zudz_region::gpon_write(&opts, vid, sn8, ploam, std::path::Path::new(out)) {
        Ok(res) => {
            if let Some(b) = &res.backup {
                println!("🛡️  نسخة احتياطية تلقائية: {}", b.report_path);
            }
            println!("{}", res.raw_output);
            println!("✅ اكتملت الكتابة");
            0
        }
        Err(e) => { eprintln!("❌ {e}"); 1 }
    }
}

fn cmd_inspect(file: &str) -> i32 {
    match inspect(file) {
        Ok(info) => {
            println!(
                "{{\"signature\": {}, \"payload_type\": {}, \"has_zte_header\": {}}}",
                opt_str(&info.signature),
                info.payload_type.map(|t| t.to_string()).unwrap_or_else(|| "null".into()),
                info.has_zte_header
            );
            0
        }
        Err(e) => {
            eprintln!("❌ {e}");
            1
        }
    }
}

fn opt_str(s: &Option<String>) -> String {
    match s {
        Some(v) => format!("\"{v}\""),
        None => "null".into(),
    }
}

fn cmd_decrypt(
    infile: &str,
    outfile: &str,
    signature: Option<String>,
    serial: Option<String>,
    mac: Option<String>,
    password: Option<String>,
    key: Option<String>,
    iv: Option<String>,
    model: Option<String>,
) -> i32 {
    let params = DecryptParams {
        signature, serial, mac, password, key, iv, model,
        ..Default::default()
    };
    let raw = match std::fs::read(infile) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("❌ {e}");
            return 1;
        }
    };
    match decrypt_auto(&raw, &params) {
        Ok((xml, desc)) => {
            if let Err(e) = std::fs::write(outfile, &xml) {
                eprintln!("❌ {e}");
                return 1;
            }
            println!("✅ {} bytes → {outfile}", xml.len());
            println!("🔑 {desc}");
            0
        }
        Err(e) => {
            eprintln!("❌ {e}");
            1
        }
    }
}
