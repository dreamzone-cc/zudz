//! عمليات الشبكة المدمجة عبر **netlink** — بلا `iproute2` ولا `docker`.
//!
//! تُنجَز كل عمليات الواجهات والعناوين والمسارات مباشرة عبر مقبس
//! `NETLINK_ROUTE`، فتبقى الأداة مستقلة تماماً عند التشغيل (تحتاج فقط
//! صلاحية `CAP_NET_ADMIN` — أي root — لإنشاء واجهة macvlan، وهي صلاحية
//! لا «مكوّن خارجي»).

use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;

// ─── ثوابت netlink ───────────────────────────────────────────────
const NETLINK_ROUTE: i32 = 0;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_SETLINK: u16 = 19;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_ROOT: u16 = 0x100;
const NLM_F_MATCH: u16 = 0x200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;

// ifinfomsg flags
const IFF_UP: u32 = 0x1;

// rtmsg
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;

// rtattr types
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINK: u16 = 5;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const IFLA_MACVLAN_MODE: u16 = 1;
const MACVLAN_MODE_BRIDGE: u32 = 4;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_PREFSRC: u16 = 7;
const RTA_TABLE: u16 = 15;

const RTM_F_LOOKUP_TABLE: u32 = 0x1000;

const AF_INET: u8 = 2;
const AF_UNSPEC: u8 = 0;

#[derive(Debug, thiserror::Error)]
pub enum NlError {
    #[error("netlink: {0}")]
    Io(#[from] io::Error),
    #[error("netlink: {0}")]
    Kernel(String),
    #[error("netlink: واجهة غير موجودة: {0}")]
    NoIface(String),
}

// ─── مقبس netlink ────────────────────────────────────────────────
struct NlSocket {
    fd: RawFd,
    seq: u32,
}

impl NlSocket {
    fn open() -> Result<Self, NlError> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(NlError::Io(io::Error::last_os_error()));
        }
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let r = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if r < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(NlError::Io(e));
        }
        Ok(Self { fd, seq: 1 })
    }

    fn send(&mut self, buf: &[u8]) -> Result<(), NlError> {
        let n = unsafe { libc::send(self.fd, buf.as_ptr() as *const _, buf.len(), 0) };
        if n < 0 {
            return Err(NlError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, NlError> {
        let mut buf = vec![0u8; 131_072];
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n < 0 {
            return Err(NlError::Io(io::Error::last_os_error()));
        }
        buf.truncate(n as usize);
        Ok(buf)
    }

    /// يرسل رسالة طلب/أمر ويقرأ رداً واحداً (يتعامل مع NLMSG_ERROR/ACK).
    fn request(&mut self, msg: Vec<u8>) -> Result<Vec<u8>, NlError> {
        self.send(&msg)?;
        let resp = self.recv()?;
        // افحص الخطأ في أول رسالة
        if resp.len() >= 16 {
            let typ = u16::from_ne_bytes([resp[4], resp[5]]);
            if typ == NLMSG_ERROR {
                let code = i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]]);
                if code != 0 {
                    return Err(NlError::Kernel(format!(
                        "{}",
                        io::Error::from_raw_os_error(-code)
                    )));
                }
            }
        }
        Ok(resp)
    }

    /// يجمع كل رسائل dump حتى NLMSG_DONE.
    fn dump(&mut self, msg: Vec<u8>) -> Result<Vec<Vec<u8>>, NlError> {
        self.send(&msg)?;
        let mut msgs = Vec::new();
        loop {
            let resp = self.recv()?;
            let mut off = 0usize;
            let mut done = false;
            while off + 16 <= resp.len() {
                let len = u32::from_ne_bytes([
                    resp[off],
                    resp[off + 1],
                    resp[off + 2],
                    resp[off + 3],
                ]) as usize;
                let typ = u16::from_ne_bytes([resp[off + 4], resp[off + 5]]);
                if len < 16 || off + len > resp.len() {
                    break;
                }
                if typ == NLMSG_DONE {
                    done = true;
                    break;
                }
                if typ == NLMSG_ERROR {
                    let code =
                        i32::from_ne_bytes([resp[off + 16], resp[off + 17], resp[off + 18], resp[off + 19]]);
                    if code != 0 {
                        return Err(NlError::Kernel(format!(
                            "{}",
                            io::Error::from_raw_os_error(-code)
                        )));
                    }
                } else {
                    msgs.push(resp[off..off + len].to_vec());
                }
                off += (len + 3) & !3;
            }
            if done {
                break;
            }
        }
        Ok(msgs)
    }

    fn next_seq(&mut self) -> u32 {
        self.seq += 1;
        self.seq
    }
}

impl Drop for NlSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

// ─── بناء الرسائل والسمات ────────────────────────────────────────
fn nlmsg(typ: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let len = 16 + payload.len();
    let mut v = vec![0u8; len];
    v[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
    v[4..6].copy_from_slice(&typ.to_ne_bytes());
    v[6..8].copy_from_slice(&flags.to_ne_bytes());
    v[8..12].copy_from_slice(&seq.to_ne_bytes());
    v[16..].copy_from_slice(payload);
    v
}

/// سمة rtattr واحدة (محاذاة 4 بايت)
fn attr(typ: u16, data: &[u8]) -> Vec<u8> {
    let len = 4 + data.len();
    let padded = (len + 3) & !3;
    let mut v = vec![0u8; padded];
    v[0..2].copy_from_slice(&(len as u16).to_ne_bytes());
    v[2..4].copy_from_slice(&typ.to_ne_bytes());
    v[4..4 + data.len()].copy_from_slice(data);
    v
}

/// يفك سمات rtattr من منطقة بايتات
fn parse_attrs(data: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let len = u16::from_ne_bytes([data[i], data[i + 1]]) as usize;
        let typ = u16::from_ne_bytes([data[i + 2], data[i + 3]]);
        if len < 4 || i + len > data.len() {
            break;
        }
        out.push((typ, data[i + 4..i + len].to_vec()));
        i += (len + 3) & !3;
    }
    out
}

fn attr_u16(a: &[(u16, Vec<u8>)], typ: u16) -> Option<u16> {
    a.iter().find(|(t, _)| *t == typ).map(|(_, d)| {
        u16::from_ne_bytes([d[0], d[1]])
    })
}

fn attr_u32(a: &[(u16, Vec<u8>)], typ: u16) -> Option<u32> {
    a.iter().find(|(t, _)| *t == typ).map(|(_, d)| {
        u32::from_ne_bytes([d[0], d[1], d[2], d[3]])
    })
}

fn attr_bytes<'a>(a: &'a [(u16, Vec<u8>)], typ: u16) -> Option<&'a [u8]> {
    a.iter().find(|(t, _)| *t == typ).map(|(_, d)| d.as_slice())
}

// ─── ifinfomsg (16 بايت) ─────────────────────────────────────────
fn ifinfomsg(index: i32, flags: u32, change: u32) -> Vec<u8> {
    let mut v = vec![0u8; 16];
    v[0] = AF_UNSPEC; // ifi_family
    v[2..4].copy_from_slice(&0u16.to_ne_bytes()); // ifi_type
    v[4..8].copy_from_slice(&index.to_ne_bytes());
    v[8..12].copy_from_slice(&flags.to_ne_bytes());
    v[12..16].copy_from_slice(&change.to_ne_bytes());
    v
}

// ─── قراءة الواجهات ──────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct LinkInfo {
    pub index: u32,
    pub name: String,
    pub mac: Option<[u8; 6]>,
    pub up: bool,
}

/// كل الواجهات (RTM_GETLINK dump)
pub fn links() -> Result<Vec<LinkInfo>, NlError> {
    let mut s = NlSocket::open()?;
    let seq = s.next_seq();
    let msg = nlmsg(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, seq, &ifinfomsg(0, 0, 0));
    let replies = s.dump(msg)?;
    let mut out = Vec::new();
    for m in replies {
        let payload = &m[16..];
        if payload.len() < 16 {
            continue;
        }
        let index = u32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let flags = u32::from_ne_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let attrs = parse_attrs(&payload[16..]);
        let name = attr_bytes(&attrs, IFLA_IFNAME)
            .map(|b| String::from_utf8_lossy(b).trim_end_matches('\0').to_string())
            .unwrap_or_default();
        let mac = attr_bytes(&attrs, IFLA_ADDRESS).and_then(|b| {
            if b.len() == 6 {
                let mut m = [0u8; 6];
                m.copy_from_slice(b);
                Some(m)
            } else {
                None
            }
        });
        out.push(LinkInfo { index, name, mac, up: flags & IFF_UP != 0 });
    }
    Ok(out)
}

pub fn ifindex(name: &str) -> Result<u32, NlError> {
    links()?
        .into_iter()
        .find(|l| l.name == name)
        .map(|l| l.index)
        .ok_or_else(|| NlError::NoIface(name.to_string()))
}

pub fn iface_mac(name: &str) -> Result<Option<[u8; 6]>, NlError> {
    Ok(links()?.into_iter().find(|l| l.name == name).and_then(|l| l.mac))
}

/// أول واجهة فيزيائية (غير loopback/virtual) لها MAC
pub fn first_physical_mac() -> Option<[u8; 6]> {
    links()
        .ok()?
        .into_iter()
        .find(|l| l.name != "lo" && l.mac.is_some() && l.mac != Some([0; 6]))
        .and_then(|l| l.mac)
}

// ─── IPv4 للواجهة ────────────────────────────────────────────────
fn ifaddrmsg(index: u32) -> Vec<u8> {
    let mut v = vec![0u8; 8];
    v[0] = AF_INET; // ifa_family
    v[4..8].copy_from_slice(&index.to_ne_bytes());
    v
}

/// (عنوان IPv4، بادئة) لأول عنوان على الواجهة
pub fn iface_ipv4(index: u32) -> Result<Option<(Ipv4Addr, u8)>, NlError> {
    let mut s = NlSocket::open()?;
    let seq = s.next_seq();
    let msg = nlmsg(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, seq, &ifaddrmsg(0));
    let replies = s.dump(msg)?;
    for m in replies {
        let p = &m[16..];
        if p.len() < 8 || p[0] != AF_INET {
            continue;
        }
        let idx = u32::from_ne_bytes([p[4], p[5], p[6], p[7]]);
        if idx != index {
            continue;
        }
        let prefix = p[1];
        let attrs = parse_attrs(&p[8..]);
        // IFA_LOCAL هو العنوان المحلي
        let ip = attr_bytes(&attrs, IFA_LOCAL).or_else(|| attr_bytes(&attrs, IFA_ADDRESS));
        if let Some(b) = ip {
            if b.len() == 4 {
                return Ok(Some((Ipv4Addr::new(b[0], b[1], b[2], b[3]), prefix)));
            }
        }
    }
    Ok(None)
}

// ─── البحث عن مسار إلى عنوان ────────────────────────────────────
pub struct RouteLookup {
    pub ifindex: u32,
    pub src: Option<Ipv4Addr>,
}

/// مسار التوجيه نحو عنوان IPv4 (RTM_GETROUTE مع RTM_F_LOOKUP_TABLE)
pub fn route_lookup(dst: Ipv4Addr) -> Result<Option<RouteLookup>, NlError> {
    let mut s = NlSocket::open()?;
    let seq = s.next_seq();
    let mut rtm = vec![0u8; 12];
    rtm[0] = AF_INET; // rtm_family
    rtm[1] = 32; // rtm_dst_len
    rtm[4] = RT_TABLE_MAIN;
    rtm[8..12].copy_from_slice(&RTM_F_LOOKUP_TABLE.to_ne_bytes());
    let mut payload = rtm;
    payload.extend(attr(RTA_DST, &dst.octets()));
    let msg = nlmsg(RTM_GETROUTE, NLM_F_REQUEST, seq, &payload);
    let resp = s.request(msg)?;
    if resp.len() < 16 {
        return Ok(None);
    }
    let p = &resp[16..];
    if p.len() < 12 {
        return Ok(None);
    }
    let attrs = parse_attrs(&p[12..]);
    let ifindex = attr_u32(&attrs, RTA_OIF).unwrap_or(0);
    let src = attr_bytes(&attrs, RTA_PREFSRC).and_then(|b| {
        if b.len() == 4 {
            Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        } else {
            None
        }
    });
    Ok(Some(RouteLookup { ifindex, src }))
}

// ─── إنشاء/حذف/تهيئة الواجهات ────────────────────────────────────
/// ينشئ واجهة macvlan (mode bridge) على واجهة أب
pub fn create_macvlan(parent_index: u32, name: &str, mac: [u8; 6]) -> Result<u32, NlError> {
    let mut s = NlSocket::open()?;
    let seq = s.next_seq();
    let mut payload = ifinfomsg(0, 0, 0);
    payload.extend(attr(IFLA_IFNAME, format!("{name}\0").as_bytes()));
    payload.extend(attr(IFLA_LINK, &parent_index.to_ne_bytes()));
    payload.extend(attr(IFLA_ADDRESS, &mac));
    // IFLA_LINKINFO { IFLA_INFO_KIND="macvlan", IFLA_INFO_DATA { IFLA_MACVLAN_MODE=bridge } }
    let mut info_data = Vec::new();
    info_data.extend(attr(IFLA_MACVLAN_MODE, &MACVLAN_MODE_BRIDGE.to_ne_bytes()));
    let mut linkinfo = Vec::new();
    linkinfo.extend(attr(IFLA_INFO_KIND, b"macvlan\0"));
    linkinfo.extend(attr(IFLA_INFO_DATA, &info_data));
    payload.extend(attr(IFLA_LINKINFO, &linkinfo));

    let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    let msg = nlmsg(RTM_NEWLINK, flags, seq, &payload);
    s.request(msg)?;
    // اقرأ ifindex الجديد
    ifindex(name)
}

/// يضبط عنوان MAC لواجهة قائمة
pub fn set_mac(index: u32, mac: [u8; 6]) -> Result<(), NlError> {
    let mut s = NlSocket::open()?;
    let seq = s.next_seq();
    let mut payload = ifinfomsg(index as i32, 0, 0);
    payload.extend(attr(IFLA_ADDRESS, &mac));
    let msg = nlmsg(RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, seq, &payload);
    s.request(msg)?;
    Ok(())
}

/// يرفع واجهة (IFF_UP)
pub fn set_up(index: u32) -> Result<(), NlError> {
    let mut s = NlSocket::open()?;
    let seq = s.next_seq();
    let payload = ifinfomsg(index as i32, IFF_UP, 0xFFFF_FFFF);
    let msg = nlmsg(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, seq, &payload);
    s.request(msg)?;
    Ok(())
}

pub fn del_link(index: u32) -> Result<(), NlError> {
    let mut s = NlSocket::open()?;
    let seq = s.next_seq();
    let payload = ifinfomsg(index as i32, 0, 0);
    let msg = nlmsg(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, seq, &payload);
    s.request(msg)?;
    Ok(())
}

/// يضيف عنوان IPv4 لواجهة
pub fn add_addr(index: u32, ip: Ipv4Addr, prefix: u8) -> Result<(), NlError> {
    let mut s = NlSocket::open()?;
    let seq = s.next_seq();
    let mut p = vec![0u8; 8];
    p[0] = AF_INET;
    p[1] = prefix;
    p[4..8].copy_from_slice(&index.to_ne_bytes());
    p.extend(attr(IFA_LOCAL, &ip.octets()));
    p.extend(attr(IFA_ADDRESS, &ip.octets()));
    let msg = nlmsg(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, seq, &p);
    s.request(msg)?;
    Ok(())
}

fn rtmsg(dst_len: u8, scope: u8) -> Vec<u8> {
    let mut v = vec![0u8; 12];
    v[0] = AF_INET; // rtm_family
    v[1] = dst_len; // rtm_dst_len
    v[4] = RT_TABLE_MAIN;
    v[5] = RTPROT_BOOT;
    v[6] = scope;
    v[7] = RTN_UNICAST;
    v
}

/// يضيف مساراً (host/prefix) عبر واجهة بمصدر محدد
pub fn add_route(dst: Ipv4Addr, prefix: u8, index: u32, src: Ipv4Addr) -> Result<(), NlError> {
    let mut s = NlSocket::open()?;
    let seq = s.next_seq();
    let mut p = rtmsg(prefix, RT_SCOPE_LINK);
    p.extend(attr(RTA_DST, &dst.octets()));
    p.extend(attr(RTA_OIF, &index.to_ne_bytes()));
    p.extend(attr(RTA_PREFSRC, &src.octets()));
    let msg = nlmsg(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, seq, &p);
    s.request(msg)?;
    Ok(())
}

pub fn del_route(dst: Ipv4Addr, prefix: u8, index: u32) -> Result<(), NlError> {
    let mut s = NlSocket::open()?;
    let seq = s.next_seq();
    let mut p = rtmsg(prefix, RT_SCOPE_LINK);
    p.extend(attr(RTA_DST, &dst.octets()));
    p.extend(attr(RTA_OIF, &index.to_ne_bytes()));
    let msg = nlmsg(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, seq, &p);
    // تجاهل خطأ «غير موجود»
    let _ = s.request(msg);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_roundtrip() {
        let a = attr(IFLA_IFNAME, b"eth0\0");
        let parsed = parse_attrs(&a);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, IFLA_IFNAME);
        assert_eq!(&parsed[0].1, b"eth0\0");
    }

    #[test]
    fn links_readable() {
        // يستطيع قراءة الواجهات (عادةً ينجح بلا صلاحيات خاصة)
        let l = links();
        assert!(l.is_ok());
        assert!(!l.unwrap().is_empty());
    }

    #[test]
    fn loopback_exists() {
        assert!(links().unwrap().iter().any(|l| l.name == "lo"));
    }
}
