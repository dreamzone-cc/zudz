//! zudz-server — API موحد + خدمة واجهة SvelteKit المبنية.
//! ثنائي واحد: zudz-server [port] [dist_dir]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Response, Server};
use zudz_extract::ExtractOptions;
use zudz_meta;
use zudz_web::LuaSession;

struct State {
    inner: Mutex<StateInner>,
}

struct StateInner {
    last_report: Option<serde_json::Value>,
    ack_token: Option<(String, u64)>, // (token, created_unix)
    /// حالة إعداد MAC التلقائي (يعرضها /api/mac-status)
    mac: serde_json::Value,
}

/// خيط الإعداد التلقائي للـ MAC: يفعّل العنوان التشخيصي على كرت الشبكة نحو
/// الجهاز عند الحاجة — عبر عملية حارسة مرتفعة الصلاحيات (نافذة كلمة سر عند
/// طلبها sudo) تعيد الأصلي تلقائياً متى أُغلق التطبيق أو انهار.
fn mac_auto_setup(state: &Arc<State>) {
    let host = std::env::var("ZUDZ_HOST").unwrap_or_else(|_| "192.168.1.1".into());
    let set_status = |v: serde_json::Value| {
        if let Ok(mut st) = state.inner.lock() {
            st.mac = v;
        }
    };

    // افتراضياً: لا تغيير فعلي للـ MAC — الفحوص الميدانية على F6600P
    // (V9.0.10P25N1) أثبتت أن الحمولة وحدها تكفي (تحمل العنوان التشخيصي)
    // والجهاز لا يطابق MAC مصدر الطلب. التفعيل الاختياري لبقية البرمجيات:
    // ZUDZ_AUTO_MAC=1
    let enabled = std::env::var("ZUDZ_AUTO_MAC").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    if !enabled {
        let note = if let Ok(Some((iface, mac))) = zudz_factory::nic_mac_towards(&host) {
            format!("الحمولة تحمل MAC التشخيصي (يكفي على هذه العائلة) — كرت {iface} بـ {} كما هو؛ فعّل ZUDZ_AUTO_MAC=1 إن ألزمت برمجيتك التغيير الفعلي", zudz_factory::mac_str(&mac))
        } else {
            "لا مسار نحو الجهاز — مسارات الويب وفك التشفير تعمل بلا تغيير".into()
        };
        set_status(serde_json::json!({ "status": "skipped", "mode": "payload-only", "note": note }));
        return;
    }

    let (iface, mac) = match zudz_factory::nic_mac_towards(&host) {
        Ok(Some(pair)) => pair,
        _ => {
            set_status(serde_json::json!({ "status": "skipped", "reason": "لا مسار شبكي نحو الجهاز — تعمل مسارات الويب وفك التشفير دون تغيير MAC" }));
            return;
        }
    };
    if mac == zudz_factory::DIAGNOSTIC_MAC {
        set_status(serde_json::json!({ "status": "active", "iface": iface, "mode": "already-set", "note": "MAC التشخيصي مثبّت على الكرت بالفعل" }));
        return;
    }
    let original = zudz_factory::mac_str(&mac);
    println!("🛡️  MAC: تفعيل العنوان التشخيصي على {iface} (الأصلي {original} — يُسترجع تلقائياً عند الإغلاق)");
    match zudz_factory::macctl::spawn_mac_watch(
        std::process::id(),
        &iface,
        &original,
        &zudz_factory::macctl::default_log_path(),
    ) {
        Ok(()) => set_status(serde_json::json!({
            "status": "active", "iface": iface, "original": original,
            "note": "MAC التشخيصي مفعّل مؤقتاً — يعود الأصلي تلقائياً عند إغلاق التطبيق"
        })),
        Err(e) => set_status(serde_json::json!({
            "status": "failed", "iface": iface, "error": e,
            "note": "عمليات telnet تحتاج MAC التشخيصي — راجع docs/set-diagnostic-mac.md"
        })),
    }
}

fn opts_from(v: &serde_json::Value) -> ExtractOptions {
    ExtractOptions {
        host: v.get("host").and_then(|x| x.as_str()).unwrap_or("192.168.1.1").to_string(),
        web_user: v.get("user").and_then(|x| x.as_str()).unwrap_or("admin").to_string(),
        web_password: v.get("password").and_then(|x| x.as_str()).unwrap_or("admin").to_string(),
        with_web: v.get("with_web").and_then(|x| x.as_bool()).unwrap_or(true),
    }
}

fn json_resp(mut req: tiny_http::Request, code: u16, body: String) {
    let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json; charset=utf-8"[..]).unwrap();
    let r = Response::from_string(body).with_status_code(code).with_header(h);
    req.respond(r).ok();
}

fn ok_json(req: tiny_http::Request, body: serde_json::Value) {
    json_resp(req, 200, body.to_string())
}

fn err_json(req: tiny_http::Request, msg: impl std::fmt::Display) {
    let body = serde_json::json!({ "ok": false, "error": msg.to_string() }).to_string();
    json_resp(req, 200, body);
}

fn read_body(req: &mut tiny_http::Request) -> serde_json::Value {
    let mut s = String::new();
    let _ = req.as_reader().read_to_string(&mut s);
    serde_json::from_str(&s).unwrap_or(serde_json::json!({}))
}

/// فك ترميز base64 — مدمج بلا تبعيات
fn b64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("حرف base64 غير صالح: {}", c as char)),
        }
    }
    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return Err("طول base64 غير صالح — يجب أن يكون مضاعفاً لـ 4".into());
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = [0u8; 4];
    for chunk in bytes.chunks(4) {
        let n = chunk.iter().position(|&b| b == b'=').unwrap_or(4);
        for i in 0..4 {
            buf[i] = if i < n { val(chunk[i])? } else { 0 };
        }
        out.push((buf[0] << 2) | (buf[1] >> 4));
        if n > 2 {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if n > 3 {
            out.push((buf[2] << 6) | buf[3]);
        }
    }
    Ok(out)
}

/// اختبار الاتصال بالجهاز — TCP على المنافذ المعروفة + محاولة دخول ويب
fn device_ping(host: &str, user: &str, password: &str) -> serde_json::Value {
    use std::net::ToSocketAddrs;
    use std::time::{Duration, Instant};
    let mut connected = false;
    let mut port = 0u16;
    let mut latency = 0u128;
    let mut detail = String::new();
    let mut model = String::new();
    let mut serial = String::new();
    for p in [80u16, 443, 23] {
        let addr = format!("{host}:{p}");
        let start = Instant::now();
        let resolved = addr.to_socket_addrs().map(|mut it| it.next());
        match resolved {
            Ok(Some(sock)) => match std::net::TcpStream::connect_timeout(&sock, Duration::from_secs(2)) {
                Ok(_) => {
                    latency = start.elapsed().as_millis();
                    connected = true;
                    port = p;
                    detail = format!("TCP {host}:{p} مفتوح");
                    break;
                }
                Err(e) => detail = format!("{host}:{p} — {e}"),
            },
            Ok(None) => detail = format!("لا عنوان لـ {host}"),
            Err(e) => {
                detail = format!("تحليل العنوان فشل: {e}");
                break;
            }
        }
    }
    // عند نجاح المنفذ 80 — جرّب دخول الويب لجلب طراز الجهاز (أفضل جهد)
    if connected && port == 80 {
        match LuaSession::login(host, user, password) {
            Ok(mut s) => match s.scrape() {
                Ok(w) => {
                    model = w.model;
                    serial = w.serial_label;
                    detail = format!("{detail} — دخول الويب ناجح");
                }
                Err(e) => detail = format!("{detail} — سحب البيانات فشل: {e}"),
            },
            Err(e) => detail = format!("{detail} — بيانات الدخول غير صحيحة أو مرفوضة: {e}"),
        }
    }
    if !connected && detail.is_empty() {
        detail = "فشل الاتصال".into();
    }
    serde_json::json!({
        "ok": true, "connected": connected, "host": host,
        "port": port, "latency_ms": latency, "detail": detail,
        "model": model, "serial": serial,
    })
}

fn mime(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "application/javascript",
        "mjs" => "application/javascript",
        "css" => "text/css",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "wasm" => "application/wasm",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn serve_static(mut req: tiny_http::Request, dist: &Path, url: &str) {
    let rel = url.split('?').next().unwrap_or("/");
    let mut p = dist.join(rel.trim_start_matches('/'));
    if rel == "/" || !p.exists() {
        p = dist.join("index.html"); // SPA fallback
    }
    match std::fs::read(&p) {
        Ok(data) => {
            let h = Header::from_bytes(&b"Content-Type"[..], mime(&p).as_bytes()).unwrap();
            req.respond(Response::from_data(data).with_header(h)).ok();
        }
        Err(_) => {
            req.respond(Response::from_string("UI not built. Run: cd app && bun run build").with_status_code(404)).ok();
        }
    }
}

fn main() {
    // وضع العملية الحارسة: zudz-server --mac-watch <parent_pid> <iface> <orig_mac>
    // (تُطلق مرتفعة الصلاحيات من الخادم الرئيسي — تدير دورة MAC كاملة ثم تخرج)
    let argv: Vec<String> = std::env::args().collect();
    if let Some(i) = argv.iter().position(|a| a == "--mac-watch") {
        let pid: u32 = argv.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let iface = argv.get(i + 2).cloned().unwrap_or_default();
        let orig = argv.get(i + 3).cloned().unwrap_or_default();
        std::process::exit(zudz_factory::macctl::mac_watch_main(pid, &iface, &orig));
    }

    let port: u16 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(8790);
    let dist = std::env::args()
        .nth(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("app/build"));
    let state = Arc::new(State {
        inner: Mutex::new(StateInner {
            last_report: None,
            ack_token: None,
            mac: serde_json::json!({ "status": "checking" }),
        }),
    });

    // تغيير MAC التلقائي: خيط خلفي — يفعّل العنوان التشخيصي عند الحاجة
    // (بنافذة كلمة سر مخصصة عند طلبها sudo) ويعيد الأصلي تلقائياً عند إغلاق
    // التطبيق عبر عملية حارسة تراقب حياتنا في /proc.
    {
        let st = state.clone();
        std::thread::spawn(move || mac_auto_setup(&st));
    }

    let server = Server::http(("127.0.0.1", port)).expect("bind");
    println!("╔══════════════════════════════════════════╗");
    println!("║  ZUDZ server — UI: http://127.0.0.1:{port} ║");
    println!("╚══════════════════════════════════════════╝");
    println!("   UI dir: {}", dist.display());

    for req in server.incoming_requests() {
        let url = req.url().to_string();
        let method = req.method().clone();
        let dist = dist.clone();
        let mut st = state.inner.lock().unwrap_or_else(|e| e.into_inner());


        if url.starts_with("/api/") {
            handle_api(req, &method, &url, &mut st);
        } else {
            serve_static(req, &dist, &url);
        }
        drop(st);
    }
}

fn handle_api(mut req: tiny_http::Request, method: &Method, url: &str, st: &mut StateInner) {
    if *method == Method::Get {
        match url {
            "/api/version" => {
                let m = zudz_meta::meta();
                ok_json(req, serde_json::json!({
                    "name": m.name,
                    "version": m.version,
                    "tagline": m.tagline,
                    "author": m.author,
                    "homepage": m.homepage,
                    "discord": m.discord,
                    "license": m.license,
                    "license_name": m.license_name,
                    "license_url": m.license_url,
                    "purpose": m.purpose,
                    "personal_only": m.personal_only,
                    "no_illegal": m.no_illegal,
                    "disclaimer": m.disclaimer,
                }));
            }
            "/api/regions" => {
                let regions: Vec<serde_json::Value> = zudz_region::REGIONS
                    .iter()
                    .map(|r| serde_json::json!({ "code": r.code, "name": r.name, "verified": r.verified, "source": r.source }))
                    .collect();
                ok_json(req, serde_json::json!({ "regions": regions }));
            }
            "/api/mac-status" => {
                let v = st.mac.clone();
                ok_json(req, v);
            }
            _ => err_json(req, "not found"),
        }
        return;
    }

    if *method != Method::Post {
        err_json(req, "method not allowed");
        return;
    }

    let v = read_body(&mut req);
    match url {
        "/api/extract" => {
            let o = opts_from(&v);
            match zudz_extract::extract_all(&o) {
                Ok(rep) => {
                    let j = serde_json::to_value(&rep).unwrap_or_default();
                    st.last_report = Some(j.clone());
                    ok_json(req, serde_json::json!({ "ok": true, "report": j }));
                }
                Err(e) => err_json(req, e),
            }
        }
        "/api/region/prepare" => {
            let o = opts_from(&v);
            let dir = std::path::Path::new("zudz_region_backup");
            match zudz_region::prepare_region_change(&o, dir) {
                Ok(p) => {
                    let j = serde_json::to_value(&p.report).unwrap_or_default();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    st.ack_token = Some((p.token.clone(), now));
                    st.last_report = Some(j.clone());
                    ok_json(req, serde_json::json!({ "ok": true, "token": p.token, "summary": j }));
                }
                Err(e) => err_json(req, e),
            }
        }
        "/api/region/change" => {
            let o = opts_from(&v);
            let code = v.get("code").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let ack = v.get("ack").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
            let perm = v.get("perm_telnet").and_then(|x| x.as_bool()).unwrap_or(true);
            let force = v.get("force_unknown").and_then(|x| x.as_bool()).unwrap_or(false);

            // وضعان:
            //  - ack مُقدَّم: تدفق يدوي — يلزم توكن صالح من prepare (بوابة الذاكرة)
            //  - ack فارغ: نسخة احتياطية كاملة تلقائية داخل change_region
            //    (وإن فشل السحب تُلغى العملية قبل لمس الجهاز)
            if !ack.is_empty() {
                let valid = match &st.ack_token {
                    Some((tok, created)) => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        *tok == ack && now.saturating_sub(*created) <= 3600
                    }
                    None => false,
                };
                if !valid {
                    err_json(req, "بوابة الأمان: توكن غير صالح/منتهي — نفّذ السحب الاحتياطي أولاً أو اترك التوكن فارغاً للنسخ التلقائي");
                    return;
                }
            }
            match zudz_region::change_region(&o, code, &ack, Path::new("zudz_region_backup"), force, perm) {
                Ok(res) => {
                    st.ack_token = None; // لمرة واحدة
                    let auto = res.backup.is_some();
                    let j = serde_json::to_value(&res).unwrap_or_default();
                    ok_json(req, serde_json::json!({ "ok": true, "auto_backup": auto, "result": j }));
                }
                Err(e) => err_json(req, e),
            }
        }
        "/api/gpon/read" => {
            let o = opts_from(&v);
            match zudz_region::gpon_read(&o) {
                Ok(tp) => {
                    let mut m = serde_json::Map::new();
                    for (k, v) in &tp {
                        m.insert(k.to_string(), serde_json::Value::String(v.clone()));
                    }
                    ok_json(req, serde_json::json!({ "ok": true, "tags": m }));
                }
                Err(e) => err_json(req, e),
            }
        }
        "/api/gpon/clone" => {
            let o = opts_from(&v);
            // من آخر تقرير محفوظ، أو ملف النسخة الاحتياطية.
            // نسخة تلقائية لهوية الجهاز الهدف الحالية تُسحب قبل الكتابة.
            let report_path = Path::new("zudz_region_backup/report.json");
            match zudz_region::gpon_clone_from_report(&o, report_path, Path::new("zudz_gpon_backup")) {
                Ok(res) => {
                    let backup = serde_json::to_value(&res.backup).unwrap_or_default();
                    let j = serde_json::to_value(&res).unwrap_or_default();
                    ok_json(req, serde_json::json!({ "ok": true, "backup": backup, "commands": res.commands_run, "output": res.raw_output, "result": j }));
                }
                Err(e) => err_json(req, e),
            }
        }
        "/api/gpon/write" => {
            let o = opts_from(&v);
            let vid = v.get("vid").and_then(|x| x.as_str()).unwrap_or("");
            let sn8 = v.get("sn8").and_then(|x| x.as_str()).unwrap_or("");
            let ploam = v.get("ploam").and_then(|x| x.as_str()).unwrap_or("");
            match zudz_region::gpon_write(&o, vid, sn8, ploam, Path::new("zudz_gpon_backup")) {
                Ok(res) => {
                    let backup = serde_json::to_value(&res.backup).unwrap_or_default();
                    ok_json(req, serde_json::json!({ "ok": true, "backup": backup, "commands": res.commands_run, "output": res.raw_output }));
                }
                Err(e) => err_json(req, e),
            }
        }
        "/api/inspect" => {
            let path = v.get("path").and_then(|x| x.as_str()).unwrap_or("");
            match zudz_crypto::inspect(path) {
                Ok(i) => ok_json(req, serde_json::json!({
                    "ok": true, "signature": i.signature, "payload_type": i.payload_type
                })),
                Err(e) => err_json(req, e),
            }
        }
        "/api/decrypt" => {
            let path = v.get("path").and_then(|x| x.as_str()).unwrap_or("");
            let out = v.get("out").and_then(|x| x.as_str()).unwrap_or("");
            match std::fs::read(path)
                .map_err(|e| e.to_string())
                .and_then(|raw| zudz_crypto::decrypt_auto(&raw, &zudz_crypto::DecryptParams::default()).map_err(|e| e.to_string()))
            {
                Ok((xml, method)) => {
                    let saved = if !out.is_empty() {
                        match std::fs::write(out, &xml) {
                            Ok(_) => Some(out.to_string()),
                            Err(e) => {
                                return err_json(req, format!("كتابة الملف فشلت: {e}"));
                            }
                        }
                    } else {
                        None
                    };
                    let mut j = serde_json::json!({ "ok": true, "size": xml.len(), "method": method });
                    if let Some(s) = saved {
                        j["saved_to"] = serde_json::Value::String(s);
                    }
                    // النص المفكوك للعرض المنظم في الواجهة
                    j["xml"] = serde_json::Value::String(String::from_utf8_lossy(&xml).into_owned());
                    ok_json(req, j);
                }
                Err(e) => err_json(req, e),
            }
        }
        "/api/inspect-content" => {
            let content_b64 = v.get("content_b64").and_then(|x| x.as_str()).unwrap_or("");
            match b64_decode(content_b64)
                .map_err(|e| e.to_string())
                .and_then(|raw| zudz_crypto::inspect_bytes(&raw).map_err(|e| e.to_string()))
            {
                Ok(i) => ok_json(req, serde_json::json!({
                    "ok": true, "signature": i.signature, "payload_type": i.payload_type,
                    "has_zte_header": i.has_zte_header
                })),
                Err(e) => err_json(req, e),
            }
        }
        "/api/decrypt-content" => {
            let content_b64 = v.get("content_b64").and_then(|x| x.as_str()).unwrap_or("");
            let save = v.get("save").and_then(|x| x.as_bool()).unwrap_or(false);
            let out = v.get("out").and_then(|x| x.as_str()).unwrap_or("");
            match b64_decode(content_b64)
                .map_err(|e| e.to_string())
                .and_then(|raw| zudz_crypto::decrypt_auto(&raw, &zudz_crypto::DecryptParams::default()).map_err(|e| e.to_string()))
            {
                Ok((xml, method)) => {
                    let saved = if save && !out.is_empty() {
                        match std::fs::write(out, &xml) {
                            Ok(_) => Some(out.to_string()),
                            Err(e) => {
                                return err_json(req, format!("كتابة الملف فشلت: {e}"));
                            }
                        }
                    } else {
                        None
                    };
                    let mut j = serde_json::json!({ "ok": true, "size": xml.len(), "method": method });
                    if let Some(s) = saved {
                        j["saved_to"] = serde_json::Value::String(s);
                    }
                    j["xml"] = serde_json::Value::String(String::from_utf8_lossy(&xml).into_owned());
                    ok_json(req, j);
                }
                Err(e) => err_json(req, e),
            }
        }
        "/api/device/ping" => {
            let host = v.get("host").and_then(|x| x.as_str()).unwrap_or("192.168.1.1");
            let user = v.get("user").and_then(|x| x.as_str()).unwrap_or("admin");
            let password = v.get("password").and_then(|x| x.as_str()).unwrap_or("admin");
            let r = device_ping(host, user, password);
            ok_json(req, r);
        }
        _ => err_json(req, "not found"),
    }
}
