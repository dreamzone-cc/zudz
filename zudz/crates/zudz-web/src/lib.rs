//! سحب واجهة LUA — منقول من ztk/webscrape.py
//! الدخول: sha256(password+salt) + كوكي SID.
//! البيات: menuView(menu_id) إلزامياً قبل menuData(tag.lua) + X-Requested-With.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zudz_factory::http::{HttpError, RawHttp};

#[derive(Debug, thiserror::Error)]
pub enum WebError {
    #[error("فشل الدخول: {0}")]
    Login(String),
    #[error("رد غير متوقع: {0}")]
    Bad(String),
    #[error(transparent)]
    Http(#[from] HttpError),
}

#[derive(Debug, Default, Serialize)]
pub struct WebInfo {
    pub model: String,
    pub serial_label: String,
    pub gpon_sn: String,
    pub hardware: String,
    pub software: String,
    pub boot: String,
    pub sip_registrar: String,
    pub sip_proxy1: String,
    pub sip_proxy2: String,
}

pub struct LuaSession {
    http: RawHttp,
}

/// صفحات (menu_id، وسم البيانات) — مكتشفة من كود صفحات الجهاز
const PAGES: &[(&str, &str)] = &[
    ("statusMgr", "devmgr_statusmgr_lua"),
    ("sip", "voip_voipsip_lua"),
];

fn latin1(b: &[u8]) -> String {
    b.iter().map(|c| *c as char).collect()
}

/// استخراج قيمة نصية من JSON بدائي: "key":"value"
fn json_str(text: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\":\"");
    let p = text.find(&pat)? + pat.len();
    let rest = &text[p..];
    rest.find('"').map(|e| rest[..e].to_string())
}

/// الترويسات الإلزامية لاكتشفتها الجلسة العملية (بدونها الجهاز يرد SessionTimeout)
const XHR_HEADERS: &[(&str, &str)] = &[
    ("X-Requested-With", "XMLHttpRequest"),
    ("Referer", "/"),
];

impl LuaSession {
    pub fn login(host: &str, user: &str, password: &str) -> Result<Self, WebError> {
        let mut http = RawHttp::new(host, 8);
        // ① token
        let r = http.get_extra("/?_type=loginData&_tag=login_entry", XHR_HEADERS)?;
        let text = latin1(&r.body);
        let token = json_str(&text, "sess_token").ok_or_else(|| WebError::Login("لا sess_token".into()))?;
        // ② salt
        let r = http.get_extra("/?_type=loginData&_tag=login_token", XHR_HEADERS)?;
        let stext = latin1(&r.body);
        let gt = stext.find('>').ok_or_else(|| WebError::Login("لا salt".into()))?;
        let lt = stext[gt + 1..].find('<').map(|e| gt + 1 + e).ok_or_else(|| WebError::Login("لا salt".into()))?;
        let s = stext[gt + 1..lt].to_string();
        // ③ دخول sha256(pass+salt)
        let digest = hex_lower(&Sha256::digest(format!("{password}{s}").as_bytes()));
        let body = format!(
            "action=login&Username={user}&Password={digest}&_sessionTOKEN={token}"
        );
        let r = http.post_extra(
            "/?_type=loginData&_tag=login_entry",
            body.as_bytes(),
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("X-Requested-With", "XMLHttpRequest"),
                ("Referer", "/"),
            ],
        )?;
        let rt = latin1(&r.body);
        if !rt.contains("sess_token") {
            return Err(WebError::Login(format!("رفض الدخول: {rt}")));
        }
        // ④ تفعيل الجلسة (تحميل / كما يفعل المتصفح)
        let _ = http.get_extra("/", XHR_HEADERS)?;
        Ok(Self { http })
    }

    fn menu_data(&mut self, menu_id: &str, tag: &str) -> Result<String, WebError> {
        // menuView (GET) يفتح القفل ثم menuData (GET) يجلب البيانات — بترويسة XHR
        let _ = self.http.get_extra(
            &format!("/?_type=menuView&_tag={menu_id}&Menu3Location=0"),
            XHR_HEADERS,
        )?;
        let r = self.http.get_extra(
            &format!("/?_type=menuData&_tag={tag}.lua"),
            XHR_HEADERS,
        )?;
        Ok(latin1(&r.body))
    }

    /// السحب الكامل للمعلومات غير المشفرة
    pub fn scrape(&mut self) -> Result<WebInfo, WebError> {
        let mut info = WebInfo::default();
        let dev = self.menu_data(PAGES[0].0, PAGES[0].1)?;
        if dev.contains("SessionTimeout") {
            return Err(WebError::Bad("SessionTimeout".into()));
        }
        // parse XML primitives: OBJ → ParaName/ParaValue pairs
        let devinfo = obj_pairs(&dev, "OBJ_DEVINFO_ID");
        let sn = obj_pairs(&dev, "OBJ_SN_INFO_ID");
        info.model = devinfo.get("ModelName").cloned().unwrap_or_default();
        info.serial_label = devinfo.get("SerialNumber").cloned().unwrap_or_default();
        info.gpon_sn = sn.get("Sn").cloned().unwrap_or_default();
        info.hardware = devinfo.get("HardwareVer").cloned().unwrap_or_default();
        info.software = devinfo.get("SoftwareVer").cloned().unwrap_or_default();
        info.boot = devinfo.get("BootVer").cloned().unwrap_or_default();

        if let Ok(sip) = self.menu_data(PAGES[1].0, PAGES[1].1) {
            if let Some(srv) = obj_pairs_opt(&sip, "OBJ_VOIPSIPSERVER_ID") {
                info.sip_registrar = srv.get("RegistrarServer1").cloned().unwrap_or_default();
                info.sip_proxy1 = srv.get("OutboundProxy1").cloned().unwrap_or_default();
                info.sip_proxy2 = srv.get("OutboundProxy2").cloned().unwrap_or_default();
            }
        }
        Ok(info)
    }
}

/// يستخرج أزواج ParaName/ParaValue لأول Instance من الكائن
fn obj_pairs(xml: &str, obj: &str) -> HashMap<String, String> {
    obj_pairs_opt(xml, obj).unwrap_or_default()
}

fn obj_pairs_opt(xml: &str, obj: &str) -> Option<HashMap<String, String>> {
    const OPEN_NAME: &str = "<ParaName>";
    const CLOSE_NAME: &str = "</ParaName>";
    const OPEN_VAL: &str = "<ParaValue>";
    const CLOSE_VAL: &str = "</ParaValue>";
    let start = xml.find(obj)?;
    let end = xml[start..].find("</OBJ_").map(|e| start + e).unwrap_or(xml.len());
    let seg = &xml[start..end];
    let mut map = HashMap::new();
    let mut rest = seg;
    while let Some(p) = rest.find(OPEN_NAME) {
        let after = &rest[p + OPEN_NAME.len()..];
        let ne = after.find(CLOSE_NAME)?;
        let name = &after[..ne];
        let vseg = &after[ne + CLOSE_NAME.len()..];
        let vs = vseg.find(OPEN_VAL)?;
        let vbody = &vseg[vs + OPEN_VAL.len()..];
        let ve = vbody.find(CLOSE_VAL)?;
        map.insert(name.to_string(), vbody[..ve].to_string());
        rest = &vbody[ve + CLOSE_VAL.len()..];
    }
    Some(map)
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
