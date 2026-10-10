//! محلل قاعدة بيانات ZTE بصيغة XML + مستخرج بيانات الاعتماد
//! منقول من ztk/dbparser.py + ztk/extractor.py

use serde::Serialize;
use std::collections::HashMap;

pub type Row = HashMap<String, String>;
pub type Db = HashMap<String, Vec<Row>>;

/// يحلل نص XML — roxmltree أولاً ثم fallback يدوي متسامح (كما في الأصل)
pub fn parse_db(xml: &str) -> Db {
    match roxmltree::Document::parse(xml) {
        Ok(doc) => parse_with_roxml(doc),
        Err(_) => parse_manual(xml),
    }
}

fn parse_with_roxml(doc: roxmltree::Document) -> Db {
    let mut db: Db = HashMap::new();
    for tbl in doc.descendants().filter(|n| n.has_tag_name("Tbl")) {
        let name = tbl.attribute("name").unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        let mut rows = Vec::new();
        for row in tbl.descendants().filter(|n| n.has_tag_name("Row")) {
            let mut r: Row = HashMap::new();
            for dm in row.children().filter(|n| n.has_tag_name("DM")) {
                if let (Some(n), Some(v)) = (dm.attribute("name"), dm.attribute("val")) {
                    r.insert(n.to_string(), v.to_string());
                }
            }
            if !r.is_empty() {
                rows.push(r);
            }
        }
        db.insert(name, rows);
    }
    db
}

fn parse_manual(xml: &str) -> Db {
    // محلل متسامح: Tbl/Row/DM بالمسح النصي (الملفات أحياناً تحوي محارف غير صالحة)
    let mut db: Db = HashMap::new();
    let bytes = xml.as_bytes();
    let mut i = 0;
    while let Some(p) = find(bytes, b"<Tbl ", i) {
        let Some(name) = attr_at(xml, p, b"name") else { i = p + 5; continue };
        let end = find(bytes, b"</Tbl>", p).map(|e| e + 6).unwrap_or(xml.len());
        let body = &xml[p..end];
        let mut rows = Vec::new();
        let bb = body.as_bytes();
        let mut j = 0;
        while let Some(rp) = find(bb, b"<Row ", j) {
            let rend = find(bb, b"</Row>", rp).map(|e| e + 6).unwrap_or(bb.len());
            let mut r: Row = HashMap::new();
            let rb = &body[rp..rend];
            let mut k = 0;
            while let Some(dp) = find(rb.as_bytes(), b"<DM ", k) {
                if let (Some(n), Some(v)) = (attr_at(rb, dp, b"name"), attr_at(rb, dp, b"val")) {
                    r.insert(n, v);
                }
                k = dp + 4;
            }
            if !r.is_empty() {
                rows.push(r);
            }
            j = rend;
        }
        db.insert(name, rows);
        i = end;
    }
    db
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn attr_at(xml: &str, tag_pos: usize, attr: &[u8]) -> Option<String> {
    let end = xml[tag_pos..].find('>').map(|e| tag_pos + e)?;
    let seg = &xml[tag_pos..end];
    let pat = format!("{}=\"", String::from_utf8_lossy(attr));
    let p = seg.find(&pat)? + pat.len();
    let rest = &seg[p..];
    let v = rest.find('"').map(|e| &rest[..e])?;
    Some(
        v.replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'"),
    )
}

pub fn table<'a>(db: &'a Db, name: &str) -> &'a [Row] {
    db.get(name).map(|v| v.as_slice()).unwrap_or(&[])
}

pub fn first<'a>(db: &'a Db, name: &str) -> Option<&'a Row> {
    db.get(name).and_then(|v| v.first())
}

fn pick(row: &Row, names: &[&str]) -> String {
    for n in names {
        if let Some(v) = row.get(*n) {
            if !v.is_empty() {
                return v.clone();
            }
        }
    }
    String::new()
}

// ─── أنواع التقرير المستخرج ─────────────────────────────────────────────

#[derive(Debug, Default, Serialize)]
pub struct DeviceInfo {
    pub config_label: String,
    pub provisioning_code: String,
    pub wifi_base_mac: String,
    pub lan_ip: String,
    pub lan_netmask: String,
}

#[derive(Debug, Default, Serialize)]
pub struct WanConn {
    pub name: String,
    pub kind: String,
    pub conn_type: String,
    pub vlan: String,
    pub service_list: String,
    pub ip: String,
    pub pppoe_user: String,
    pub pppoe_password: String,
}

#[derive(Debug, Default, Serialize)]
pub struct WifiAp {
    pub ap: String,
    pub interface: String,
    pub enabled: bool,
    pub ssid: String,
    pub hidden: bool,
    pub password: String,
}

#[derive(Debug, Default, Serialize)]
pub struct VoipLine {
    pub line: String,
    pub enabled: bool,
    pub phone_number: String,
    pub auth_user: String,
    pub auth_password: String,
    pub digest_user: String,
    pub sip_domain: String,
    pub proxy: String,
    pub registrar: String,
}

#[derive(Debug, Default, Serialize)]
pub struct Accounts {
    pub web: Vec<WebAccount>,
    pub telnet_user: String,
    pub telnet_password: String,
    pub telnet_lan_enabled: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct WebAccount {
    pub user: String,
    pub password: String,
    pub level: String,
    pub app_id: String,
    pub enabled: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct ExtractedDb {
    pub device: DeviceInfo,
    pub wan: Vec<WanConn>,
    pub wifi: Vec<WifiAp>,
    pub voip: Vec<VoipLine>,
    pub accounts: Accounts,
    pub tr069: HashMap<String, String>,
}

fn addr_label(v: &str) -> String {
    match v {
        "0" => "DHCP".into(),
        "1" => "Static".into(),
        "2" => "PPPoE".into(),
        "3" => "Auto".into(),
        "" => String::new(),
        other => other.to_string(),
    }
}

fn conn_label(v: &str) -> String {
    match v {
        "0" => "Bridge".into(),
        "1" => "IP_Routed".into(),
        "2" => "IP_Bridged".into(),
        "4" => "PPPoE".into(),
        "" => String::new(),
        other => other.to_string(),
    }
}

fn vlan_of(db: &Db, view: &str) -> String {
    if view.is_empty() {
        return String::new();
    }
    for tbl in ["EthVlan", "VLAN", "EthVlanCfg"] {
        for r in table(db, tbl) {
            if r.get("ViewName").map(|v| v == view).unwrap_or(false) {
                if let Some(v) = r.get("VLANID").or_else(|| r.get("VlanId")) {
                    return v.clone();
                }
            }
        }
    }
    // DEV.ETH.VLAN<N> → N
    view.rfind("VLAN").map(|p| view[p + 4..].to_string()).unwrap_or_default()
}

/// الاستخراج الكامل — مطابق لمنطق extractor.py
pub fn extract(db: &Db) -> ExtractedDb {
    let mut out = ExtractedDb::default();

    let dev = first(db, "DevInfo").cloned().unwrap_or_default();
    let ws = first(db, "WLANSetting").cloned().unwrap_or_default();
    let lan = first(db, "LANIPCfg").cloned().unwrap_or_default();
    out.device = DeviceInfo {
        config_label: dev.get("CfgLable").cloned().unwrap_or_default(),
        provisioning_code: dev.get("ProvisioningCode").cloned().unwrap_or_default(),
        wifi_base_mac: ws.get("SpecMACAddr").cloned().unwrap_or_default(),
        lan_ip: lan.get("IP").cloned().unwrap_or_default(),
        lan_netmask: lan.get("NetMask").cloned().unwrap_or_default(),
    };

    // WAN + PPPoE
    let pppif: Vec<&Row> = table(db, "PPPIF").iter().collect();
    let mut consumed = 0usize;
    for r in table(db, "WANCIP") {
        out.wan.push(WanConn {
            name: r.get("WANCName").cloned().unwrap_or_default(),
            kind: addr_label(r.get("AddressingType").map(|s| s.as_str()).unwrap_or("")),
            conn_type: conn_label(r.get("ConnType").map(|s| s.as_str()).unwrap_or("")),
            vlan: vlan_of(db, r.get("EthVlan").map(|s| s.as_str()).unwrap_or("")),
            service_list: r.get("ServiceList").cloned().unwrap_or_default(),
            ip: r.get("IPv4Address").cloned().unwrap_or_default(),
            ..Default::default()
        });
    }
    for r in table(db, "WANCPPP") {
        let creds = pppif.get(consumed);
        consumed += 1;
        let ct = conn_label(r.get("ConnType").map(|s| s.as_str()).unwrap_or(""));
        let is_pppoe = r.get("PPPInterface").map(|v| !v.is_empty()).unwrap_or(false)
            || ct == "PPPoE"
            || !pppif.is_empty();
        out.wan.push(WanConn {
            name: r.get("WANCName").cloned().unwrap_or_default(),
            kind: if is_pppoe { "PPPoE".into() } else { ct.clone() },
            conn_type: ct,
            vlan: vlan_of(db, r.get("EthVlan").map(|s| s.as_str()).unwrap_or("")),
            service_list: r.get("ServiceList").cloned().unwrap_or_default(),
            pppoe_user: creds.map(|c| pick(c, &["Username", "User", "PPPUsername"])).unwrap_or_default(),
            pppoe_password: creds.map(|c| pick(c, &["Password", "Pass", "PPPPassword"])).unwrap_or_default(),
            ..Default::default()
        });
    }
    for c in pppif.iter().skip(consumed) {
        out.wan.push(WanConn {
            name: "PPPoE".into(),
            kind: "PPPoE".into(),
            pppoe_user: pick(c, &["Username", "User"]),
            pppoe_password: pick(c, &["Password", "Pass"]),
            ..Default::default()
        });
    }

    // WiFi
    let mut psk: HashMap<String, String> = HashMap::new();
    for r in table(db, "WLANPSK") {
        psk.insert(
            r.get("WLANViewName").cloned().unwrap_or_default(),
            pick(r, &["KeyPassphrase", "PreSharedKey"]),
        );
    }
    for r in table(db, "WLANCfg") {
        let ap = r.get("ViewName").cloned().unwrap_or_default();
        out.wifi.push(WifiAp {
            ap: ap.clone(),
            interface: r.get("IfName").cloned().unwrap_or_default(),
            enabled: r.get("Enable").map(|v| v == "1").unwrap_or(false),
            ssid: r.get("ESSID").cloned().unwrap_or_default(),
            hidden: r.get("ESSIDHideEnable").map(|v| v == "1").unwrap_or(false),
            password: psk.get(&ap).cloned().unwrap_or_default(),
        });
    }

    // VoIP
    let sip_main = first(db, "VoIPSIP").cloned().unwrap_or_default();
    let servers = table(db, "VoIPSIPServer");
    let vp = table(db, "VoIPVPLine");
    for (i, r) in table(db, "VoIPSIPLine").iter().enumerate() {
        let srv = servers.get(i).cloned().unwrap_or_default();
        let vpl = vp.get(i).cloned().unwrap_or_default();
        out.voip.push(VoipLine {
            line: r.get("ViewName").cloned().unwrap_or_else(|| format!("line{}", i + 1)),
            enabled: r.get("Enable").map(|v| v == "1").unwrap_or(false),
            phone_number: vpl.get("DirectoryNumber").cloned().unwrap_or_default(),
            auth_user: r.get("AuthUserName").cloned().unwrap_or_default(),
            auth_password: r.get("AuthPassword").cloned().unwrap_or_default(),
            digest_user: r.get("DigestUserName").cloned().unwrap_or_default(),
            sip_domain: sip_main
                .get("UserAgentDoimain")
                .or_else(|| sip_main.get("UserAgentDomain"))
                .cloned()
                .unwrap_or_default(),
            proxy: pick(&srv, &["ProxyServer1", "ProxyServer2"]),
            registrar: pick(&srv, &["RegistrarServer1", "RegistrarServer2"]),
        });
    }

    // الحسابات
    for r in table(db, "DevAuthInfo") {
        out.accounts.web.push(WebAccount {
            user: r.get("User").cloned().unwrap_or_default(),
            password: r.get("Pass").cloned().unwrap_or_default(),
            level: r.get("Level").cloned().unwrap_or_default(),
            app_id: r.get("AppID").cloned().unwrap_or_default(),
            enabled: r.get("Enable").map(|v| v != "0").unwrap_or(true),
        });
    }
    let tel = first(db, "TelnetCfg").cloned().unwrap_or_default();
    out.accounts.telnet_user = tel.get("TS_UName").cloned().unwrap_or_default();
    out.accounts.telnet_password = tel
        .get("TS_UPwd")
        .or_else(|| tel.get("TSLan_UPwd"))
        .cloned()
        .unwrap_or_default();
    out.accounts.telnet_lan_enabled = tel.get("Lan_Enable").map(|v| v == "1").unwrap_or(false);

    // TR-069 (بحث عام)
    for (tbl, rows) in db {
        let tl = tbl.to_ascii_lowercase();
        if tl.contains("tr069") || tl.contains("cwmp") {
            for r in rows {
                for (k, v) in r {
                    let kl = k.to_ascii_lowercase();
                    if !v.is_empty()
                        && (kl.contains("url")
                            || kl.contains("acs")
                            || kl.contains("server")
                            || kl.contains("user")
                            || kl.contains("pass")
                            || kl.contains("pwd")
                            || kl.contains("period")
                            || kl.contains("enable"))
                    {
                        out.tr069.insert(format!("{tbl}.{k}"), v.clone());
                    }
                }
            }
        }
    }

    out
}
