//! عميل HTTP خام فوق TcpStream — تحكم كامل بالترويسات والجسم الخام
//! (مطابق لسلوك http.client البايثوني في الأصل: POST بجسم خام بلا Content-Type).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

pub struct RawHttp {
    host: String,
    pub cookie: String,
    timeout: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("قطع الجهاز الاتصال (متوقع في بعض الخطوات)")]
    Disconnected,
    #[error("خطو شبكة: {0}")]
    Io(String),
}

impl From<std::io::Error> for HttpError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::ConnectionReset
            || e.kind() == std::io::ErrorKind::UnexpectedEof
        {
            HttpError::Disconnected
        } else {
            HttpError::Io(e.to_string())
        }
    }
}

impl RawHttp {
    pub fn new(host: &str, timeout_secs: u64) -> Self {
        Self {
            host: host.to_string(),
            cookie: String::new(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// POST بجسم خام — يعيد الحالة والجسم. يحدّث الكوكي تلقائياً.
    pub fn post_raw(&mut self, path: &str, body: &[u8]) -> Result<Response, HttpError> {
        self.request("POST", path, body, &[])
    }

    /// POST بترويسات إضافية (مثل X-Requested-With لواجهة LUA)
    pub fn post_extra(
        &mut self,
        path: &str,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> Result<Response, HttpError> {
        self.request("POST", path, body, headers)
    }

    /// GET
    pub fn get(&mut self, path: &str) -> Result<Response, HttpError> {
        self.request("GET", path, &[], &[])
    }

    /// GET بترويسات إضافية
    pub fn get_extra(&mut self, path: &str, headers: &[(&str, &str)]) -> Result<Response, HttpError> {
        self.request("GET", path, &[], headers)
    }

    /// POST نموذج (application/x-www-form-urlencoded)
    pub fn post_form(&mut self, path: &str, body: &str) -> Result<Response, HttpError> {
        self.request(
            "POST",
            path,
            body.as_bytes(),
            &[("Content-Type", "application/x-www-form-urlencoded")],
        )
    }

    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> Result<Response, HttpError> {
        let mut stream = TcpStream::connect((self.host.as_str(), 80))
            .map_err(|e| HttpError::Io(e.to_string()))?;
        stream.set_read_timeout(Some(self.timeout)).ok();
        stream.set_write_timeout(Some(self.timeout)).ok();

        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ZUDZ/0.1\r\n",
            self.host
        );
        if !body.is_empty() || method == "POST" {
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        if !self.cookie.is_empty() {
            req.push_str(&format!("Cookie: {}\r\n", self.cookie));
        }
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("Connection: close\r\n\r\n");

        stream.write_all(req.as_bytes())?;
        if !body.is_empty() {
            stream.write_all(body)?;
        }
        stream.flush()?;

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        let Some((head, body_bytes)) = split_response(&buf) else {
            return Err(HttpError::Io("رد HTTP غير مكتمل".into()));
        };
        // انتبه: أسماء الكوكيز حساسة لحالة الأحرف (SID ≠ sid) —
        // نفحص بالحروف الصغيرة لكن نقرأ الزوج من السطر الأصلي
        for line in head.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("set-cookie:") {
                // قص الزوج من السطر الأصلي بعد البادئة (12 محرفاً)
                let pair = line["set-cookie:".len()..].trim().split(';').next().unwrap_or("").trim();
                if pair.is_empty() {
                    continue;
                }
                let name = pair.split('=').next().unwrap_or("");
                let mut parts: Vec<String> = if self.cookie.is_empty() {
                    Vec::new()
                } else {
                    self.cookie.split("; ").map(|s| s.to_string()).collect()
                };
                if let Some(slot) = parts.iter_mut().find(|p| p.starts_with(name)) {
                    *slot = pair.to_string();
                } else {
                    parts.push(pair.to_string());
                }
                self.cookie = parts.join("; ");
            }
        }
        let head = head.to_ascii_lowercase();
        let status = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        Ok(Response { status, body: body_bytes })
    }

    /// POST نصي (ascii/latin-1 آمن بايتياً)
    pub fn post_text(&mut self, path: &str, text: &str) -> Result<Response, HttpError> {
        let bytes: Vec<u8> = text.chars().map(|c| c as u8).collect();
        self.post_raw(path, &bytes)
    }
}

/// يفصل الرأس عن الجسم ويفك chunked إن لزم
fn split_response(buf: &[u8]) -> Option<(String, Vec<u8>)> {
    let text = String::from_utf8_lossy(buf);
    let pos = text.find("\r\n\r\n")?;
    let head = text[..pos].to_string();
    let body_start = pos + 4;
    let lower = head.to_ascii_lowercase();
    if lower.contains("transfer-encoding: chunked") {
        let mut body = Vec::new();
        let mut q = body_start;
        loop {
            let Some(nl) = (q..buf.len().saturating_sub(1)).find(|i| buf[*i] == b'\r' && buf[*i + 1] == b'\n') else { break };
            let size_str = String::from_utf8_lossy(&buf[q..nl]).into_owned();
            let Ok(size) = usize::from_str_radix(size_str.trim(), 16) else { break };
            if size == 0 {
                break;
            }
            let cs = nl + 2;
            if cs + size > buf.len() {
                break;
            }
            body.extend_from_slice(&buf[cs..cs + size]);
            q = cs + size + 2;
        }
        Some((head, body))
    } else {
        Some((head, buf[body_start..].to_vec()))
    }
}
