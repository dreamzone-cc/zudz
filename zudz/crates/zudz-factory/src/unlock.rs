//! تسلسل وضع المصنع الكامل (STEP 0-5) — منقول من onufactory.py

use crate::http::{HttpError, RawHttp};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes192;

#[derive(Debug, thiserror::Error)]
pub enum FactoryError {
    #[error("STEP{step}: توقّع {expected}، حصلنا {got}")]
    Step { step: u8, expected: &'static str, got: String },
    #[error("STEP2: رد تحدٍّ غير متوقع: {0}")]
    Challenge(String),
    #[error("STEP4: رد غير متوقع بعد الدخول: {0}")]
    AuthResult(String),
    #[error("لم تُستخرج بيانات telnet من الرد: {0}")]
    NoTelnetCreds(String),
    #[error("لم يُعثر على ماك بطاقة شبكة")]
    LocalMacNotFound,
    #[error(transparent)]
    Nl(#[from] crate::netlink::NlError),
    #[error(
        "بوابة MAC: كرت الشبكة الموصل للجهاز هو «{iface}» وماكه {current} \
         — الجهاز لا يفتح telnet إلا إذا كان ماك الكرت {required} \
         (المصنع يقفل المنفذ 23 على هذا العنوان التشخيصي). أصلِح بكتابة:\n  \
         sudo ip link set dev {iface} down\n  \
         sudo ip link set dev {iface} address {required}\n  \
         sudo ip link set dev {iface} up\n\
         ثم أعد المحاولة (المؤقت: يعود الأصلي بعد إعادة التشغيل)."
    )]
    MacGate { iface: String, current: String, required: &'static str },
    #[error(transparent)]
    Http(#[from] HttpError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// العنوان التشخيصي الإلزامي — من أداة zteonu الأصلية: الجهاز لا يفتح telnet
/// إلا إذا كان ماك كرت الشبكة الفعلي (وحمولة المصنع) بهذه القيمة بالضبط.
pub const DIAGNOSTIC_MAC: [u8; 6] = [0x00, 0x07, 0x29, 0x55, 0x35, 0x57];
pub const DIAGNOSTIC_MAC_STR: &str = "00:07:29:55:35:57";

pub fn mac_str(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

#[derive(Debug, Clone)]
pub struct UnlockResult {
    pub telnet_user: String,
    pub telnet_pass: String,
    pub aes_key: String,
    pub server_mac: String,
    pub raw: String,
    /// هل منفذ telnet 23 مفتوح فعلاً بعد الفتح؟ (تشخيص موثوقية)
    pub port_open: bool,
}

fn aes192_ecb_encrypt(key: &[u8; 24], data: &[u8]) -> Vec<u8> {
    let cipher = Aes192::new(key.into());
    let mut out = data.to_vec();
    let pad_len = 16 - out.len() % 16;
    out.extend(std::iter::repeat_n(0u8, pad_len));
    for chunk in out.chunks_exact_mut(16) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    out
}

fn aes192_ecb_decrypt(key: &[u8; 24], data: &[u8]) -> Vec<u8> {
    let cipher = Aes192::new(key.into());
    let mut out = vec![0u8; data.len() + (16 - data.len() % 16) % 16];
    out[..data.len()].copy_from_slice(data);
    for chunk in out.chunks_exact_mut(16) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
    out.truncate(data.len());
    out
}

/// أول ماك كرت فيزيائي حقيقي (عبر netlink — بلا `iproute2`)
pub fn get_local_mac() -> Result<[u8; 6], FactoryError> {
    crate::netlink::first_physical_mac().ok_or(FactoryError::LocalMacNotFound)
}

// ─── بوابة MAC التشخيصي ────────────────────────────────────────────────

/// يستخرج اسم واجهة الخروج نحو المضيف من مخرجات `ip route get <host>`
/// مثال: "192.168.1.1 dev enp3s0 src 192.168.1.10" → Some("enp3s0")
pub fn parse_route_dev(route_out: &str) -> Option<String> {
    let mut it = route_out.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == "dev" {
            return it.next().map(|s| s.trim().to_string());
        }
    }
    None
}

/// يستخرج MAC الواجهة من مخرجات `ip -o link show dev <iface>`
pub fn parse_link_mac(link_out: &str) -> Option<[u8; 6]> {
    let pos = link_out.find("link/ether ")?;
    let mac_str = link_out[pos + 11..].split_whitespace().next()?;
    let clean: String = mac_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() != 12 {
        return None;
    }
    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(mac)
}

/// (اسم واجهة الخروج نحو المضيف، ماكها) — عبر netlink (بلا `iproute2`)
pub fn nic_mac_towards(host: &str) -> Result<Option<(String, [u8; 6])>, FactoryError> {
    let Ok(ip) = host.parse::<std::net::Ipv4Addr>() else {
        return Ok(None);
    };
    let Some(route) = crate::netlink::route_lookup(ip)? else {
        return Ok(None);
    };
    let links = crate::netlink::links()?;
    Ok(links
        .into_iter()
        .find(|l| l.index == route.ifindex)
        .and_then(|l| l.mac.map(|m| (l.name, m))))
}

/// فحص إلزامي قبل الفتح: ماك كرت الشبكة نحو الجهاز يجب أن يساوي DIAGNOSTIC_MAC.
/// يطابق سلوك أداة zteonu الأصلية التي ترفض العمل بدونه.
pub fn check_diagnostic_mac(host: &str) -> Result<(), FactoryError> {
    match nic_mac_towards(host)? {
        Some((iface, mac)) if mac != DIAGNOSTIC_MAC => Err(FactoryError::MacGate {
            iface,
            current: mac_str(&mac),
            required: DIAGNOSTIC_MAC_STR,
        }),
        _ => Ok(()),
    }
}

/// التنفيذ الكامل: يفتح telnet ويعيد البيانات المؤقتة.
/// user/password = بيانات واجهة الويب (admin/admin على هذه العائلة؛ حساب
/// factorymode يُرفض بـ 401 على F6600P V9.0.10P25N1).
///
/// يطابق الأداة المرجعية المُتحقَّق منها فعلياً على الجهاز (تقرير 02_DEVICE_TEST):
/// الحمولة تحمل DIAGNOSTIC_MAC دائماً — وهو شرط فتح telnet — بينما MAC كرت
/// الشبكة الفعلي **لا يلزم تغييره** (الجهاز لا يطابقه مع مصدر الطلب).
///
/// الموثوقية (علاج الاستكشاف الرسمي §9 في الحزمة المرجعية):
/// 1. تدوير المجمّعات: Python ← Go-new ← Go-old (عند قطع الاتصال عند SendInfo).
/// 2. تدوير الإصدار: version50 ← version61 (عند فشل خطوة الدخول).
/// 3. جولتان كاملتان بفاصل 1.5 ثانية.
/// 4. بعد النجاح: فحص فتح المنفذ 23 — إن بقي مسدوداً يُعاد التفعيل مرة
///    إضافية (يستيقظ telnetd أحياناً في الجولة التالية).
/// فتح مع فحص المنفذ — للاستخدام التشخيصي (CLI فقط). عمليات السحب الفعلية
/// تستخدم `unlock_telnet_quiet`: فحص المنفذ يفتح اتصالاً TCP على 23 يستهلك
/// حصة telnetd المحدودة (Max_Con_Num) وقد يزاحم الاتصال الحقيقي التالي،
/// وإعادة التفعيل الثانية تستهلك جولة mode=2 دون داعٍ.
pub fn unlock_telnet(host: &str, user: &str, password: &str) -> Result<UnlockResult, FactoryError> {
    let mut r = unlock_telnet_quiet(host, user, password)?;
    r.port_open = port_open(host, 1500);
    Ok(r)
}

/// الفتح القياسي الصامت: بروتوكول نظيف واحد ثم الاتصال الفعلي مباشرة —
/// لا أي لمس للمنفذ 23 قبل الاتصال الحقيقي.
pub fn unlock_telnet_quiet(
    host: &str,
    user: &str,
    password: &str,
) -> Result<UnlockResult, FactoryError> {
    let combos: &[(&[u8; 96], ProtocolVersion)] = &[
        (&crate::KEY_POOL, ProtocolVersion::V50),
        (&crate::KEY_POOL, ProtocolVersion::V61),
        (&crate::KEY_POOL_GO_NEW, ProtocolVersion::V50),
        (&crate::KEY_POOL_GO_OLD, ProtocolVersion::V50),
    ];
    let mut last_err: Option<FactoryError> = None;
    for round in 0..2 {
        if round > 0 {
            std::thread::sleep(std::time::Duration::from_millis(1500));
        }
        for (pool, ver) in combos {
            match unlock_once(host, user, password, &DIAGNOSTIC_MAC, pool, *ver) {
                Ok(r) => return Ok(r),
                // خطأ شبكة (الجهاز غير قابل للوصول) — تدوير المجمّعات بلا جدوى
                Err(e @ FactoryError::Http(_)) => return Err(e),
                Err(e) => last_err = Some(e),
            }
        }
    }
    Err(last_err.unwrap_or(FactoryError::LocalMacNotFound))
}

/// هل منفذ telnet مفتوح على الجهاز؟ (فحص TCP قصير بلا اتصال فعلي)
fn port_open(host: &str, timeout_ms: u64) -> bool {
    use std::net::ToSocketAddrs;
    let Ok(mut addrs) = (host, 23u16).to_socket_addrs() else { return false };
    let Some(addr) = addrs.next() else { return false };
    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(timeout_ms)).is_ok()
}

/// إصدار صيغة CheckLoginAuth — كلاهما مقبول على هذه العائلة
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// `CheckLoginAuth.gch?version50&user=..&pass=..` (محرك Python)
    V50,
    /// `CheckLoginAuth.gch?&version61&user=..&pass=..` (محرك Go — لاحظ ?&)
    V61,
}

impl ProtocolVersion {
    fn login_payload(&self, user: &str, password: &str) -> String {
        match self {
            ProtocolVersion::V50 => {
                format!("CheckLoginAuth.gch?version50&user={user}&pass={password}")
            }
            ProtocolVersion::V61 => {
                format!("CheckLoginAuth.gch?&version61&user={user}&pass={password}")
            }
        }
    }
}

/// الجسم البروتوكولي لمصافحة واحدة كاملة (الخطوات 0–5) بمجمّع وإصدار محددين.
/// مفتاح الاشتقاق من المجمّع المعطى (وليس KEY_POOL العام).
pub fn unlock_telnet_with_mac(
    host: &str,
    user: &str,
    password: &str,
    client_mac: &[u8; 6],
) -> Result<UnlockResult, FactoryError> {
    unlock_once(host, user, password, client_mac, &crate::KEY_POOL, ProtocolVersion::V50)
}

/// نسخة عامة للاختبارات من derive_key_from_pool
pub fn derive_key_from_pool_pub(pool: &[u8; 96], server_rand: u64) -> ([u8; 24], u64) {
    derive_key_from_pool(pool, server_rand)
}

fn derive_key_from_pool(pool: &[u8; 96], server_rand: u64) -> ([u8; 24], u64) {
    let index = ((0u64 & crate::MASK) ^ server_rand) % 60;
    let mut key = [0u8; 24];
    for i in 0..24 {
        key[i] = pool[index as usize + i] ^ 0xA5;
    }
    (key, index)
}

fn unlock_once(
    host: &str,
    user: &str,
    password: &str,
    client_mac: &[u8; 6],
    pool: &[u8; 96],
    ver: ProtocolVersion,
) -> Result<UnlockResult, FactoryError> {
    let mut s = RawHttp::new(host, 8);

    // STEP 0 — reset (متوقع 400)
    let r = s.post_text("/webFac", "SendSq.gch")?;
    if r.status != 400 {
        return Err(FactoryError::Step { step: 0, expected: "400", got: r.status.to_string() });
    }

    // STEP 1 — طلب وضع المصنع (متوقع قطع اتصال)
    match s.post_text("/webFac", "RequestFactoryMode.gch") {
        Ok(_) => { /* بعض البرمجيات ترد 200 — نتابع */ }
        Err(HttpError::Disconnected) | Err(HttpError::Io(_)) => {}
    }

    // STEP 2 — التحدّي
    let r = s.post_text("/webFac", "SendSq.gch?rand=0\r\n")?;
    let text = latin1(&r.body);
    let Some(rest) = text.strip_prefix("re_rand=") else {
        return Err(FactoryError::Challenge(text.chars().take(120).collect()));
    };
    let mut it = rest.split('&');
    let server_rand: u64 = it
        .next()
        .unwrap_or("")
        .trim()
        .parse()
        .map_err(|_| FactoryError::Challenge(text.clone()))?;
    let _seed = it.next().unwrap_or("");
    let server_mac_str = it.next().unwrap_or("");
    let server_mac: Vec<u8> = server_mac_str.chars().map(|c| c as u8).collect();

    // STEP 3 — المفتاح والحمولة (من المجمّع المعطى)
    let (key, _index) = derive_key_from_pool(pool, server_rand);
    let words = crate::payload_words(&server_mac, client_mac);
    let payload = crate::build_payload_str(&words);
    let enc = aes192_ecb_encrypt(&key, &latin1_bytes(&payload));
    let r = s.post_raw("/webFacEntry", &enc)?;
    if r.status != 200 {
        return Err(FactoryError::Step { step: 3, expected: "200", got: r.status.to_string() });
    }

    // STEP 4 — دخول ببيانات الواجهة (بالصيغة المحددة للإصدار)
    let auth = ver.login_payload(user, password);
    let enc = aes192_ecb_encrypt(&key, &latin1_bytes(&auth));
    let r = s.post_raw("/webFacEntry", &enc)?;
    if r.status != 200 {
        return Err(FactoryError::Step { step: 4, expected: "200", got: r.status.to_string() });
    }
    let res_url = crate::unpad(&aes192_ecb_decrypt(&key, &r.body));
    let expected = b"FactoryMode.gch";
    if res_url != expected.to_vec() && res_url[..res_url.len().min(expected.len())] != expected[..] {
        return Err(FactoryError::AuthResult(hex::encode(&res_url[..res_url.len().min(60)])));
    }

    // STEP 5 — تفعيل ← بيانات telnet
    let fm = "FactoryMode.gch?mode=2&user=notused";
    let enc = aes192_ecb_encrypt(&key, fm.as_bytes());
    let r = s.post_raw("/webFacEntry", &enc)?;
    if r.status != 200 {
        return Err(FactoryError::Step { step: 5, expected: "200", got: r.status.to_string() });
    }
    let dec = aes192_ecb_decrypt(&key, &r.body);
    let dec = trim_zeros(&dec);
    let raw = latin1(&dec);
    let (telnet_user, telnet_pass) = extract_creds(&raw).ok_or_else(|| {
        FactoryError::NoTelnetCreds(raw.chars().take(150).collect())
    })?;

    Ok(UnlockResult {
        telnet_user,
        telnet_pass,
        aes_key: hex::encode(key),
        server_mac: hex::encode(&server_mac),
        raw,
        port_open: true,
    })
}

fn extract_creds(raw: &str) -> Option<(String, String)> {
    // raw مثل: FactoryModeAuth.gch?user=XXXX&pass=YYYY
    let q = raw.split('?').nth(1)?;
    let mut user = None;
    let mut pass = None;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=')?;
        match k {
            "user" => user = Some(v.to_string()),
            "pass" => pass = Some(v.to_string()),
            _ => {}
        }
    }
    Some((user?, pass?))
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|c| *c as char).collect()
}
fn latin1_bytes(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u32 as u8).collect()
}
fn trim_zeros(mut v: &[u8]) -> &[u8] {
    while let Some((&l, rest)) = v.split_last() {
        if l == 0 {
            v = rest;
        } else {
            break;
        }
    }
    v
}
