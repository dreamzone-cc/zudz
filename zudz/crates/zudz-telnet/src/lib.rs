//! عميل telnet لـZTE — منقول من ztk/telnetc.py
//! IAC + تسجيل دخول + تنفيذ أوامر + بث hex-stream لنقل الملفات.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;

#[derive(Debug, thiserror::Error)]
pub enum TelnetError {
    #[error("تعذّر الاتصال بـ {host}:{port}: {reason}")]
    Connect { host: String, port: u16, reason: String },
    #[error("انتهت مهلة انتظار البيانات")]
    Timeout,
    #[error("أغلق الجهاز الاتصال")]
    Closed,
    #[error("لم تصل العلامة المنتظرة خلال المهلة. آخر المخرجات: {0}")]
    MarkerTimeout(String),
}

pub struct ZteTelnet {
    pub stream: TcpStream,
    timeout: Duration,
}

impl ZteTelnet {
    pub fn connect(host: &str, port: u16, timeout_secs: u64) -> Result<Self, TelnetError> {
        let addr = (host, port)
            .to_socket_addrs()
            .map_err(|e| TelnetError::Connect { host: host.into(), port, reason: e.to_string() })?
            .next()
            .ok_or_else(|| TelnetError::Connect { host: host.into(), port, reason: "no addr".into() })?;
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs))
            .map_err(|e| TelnetError::Connect { host: host.into(), port, reason: e.to_string() })?;
        stream.set_read_timeout(Some(Duration::from_secs(timeout_secs))).ok();
        Ok(Self { stream, timeout: Duration::from_secs(timeout_secs) })
    }

    /// يقرأ بايتات ويصفّي تسلسلات IAC (يرد WONT/DONT كما في الأصل)
    fn recv_some(&mut self) -> Result<Vec<u8>, TelnetError> {
        let mut buf = [0u8; 4096];
        let n = self.stream.read(&mut buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
                TelnetError::Timeout
            } else if e.kind() == std::io::ErrorKind::UnexpectedEof {
                TelnetError::Closed
            } else {
                TelnetError::Closed
            }
        })?;
        if n == 0 {
            return Err(TelnetError::Closed);
        }
        Ok(filter_iac(&mut self.stream, &buf[..n]))
    }

    /// يقرأ حتى ظهور إحدى العلامات (يسمح بقراءات فارغة متتالية حتى المهلة)
    pub fn read_until(&mut self, markers: &[&[u8]], total_timeout: Option<Duration>) -> Result<Vec<u8>, TelnetError> {
        let deadline_limit = total_timeout.unwrap_or(self.timeout * 4);
        let start = std::time::Instant::now();
        let mut acc = Vec::new();
        self.stream.set_read_timeout(Some(Duration::from_millis(800))).ok();
        loop {
            if start.elapsed() > deadline_limit {
                return Err(TelnetError::MarkerTimeout(hex_or_ascii(&acc)));
            }
            match self.recv_some() {
                Ok(mut chunk) => {
                    acc.append(&mut chunk);
                    if markers.iter().any(|m| find_sub(&acc, m).is_some()) {
                        self.stream.set_read_timeout(Some(self.timeout)).ok();
                        return Ok(acc);
                    }
                }
                Err(TelnetError::Timeout) => continue,
                Err(e) => {
                    self.stream.set_read_timeout(Some(self.timeout)).ok();
                    return Err(e);
                }
            }
        }
    }

    pub fn sendline(&mut self, line: &str) {
        let _ = self.stream.write_all(line.as_bytes());
        let _ = self.stream.write_all(b"\r\n");
        let _ = self.stream.flush();
    }

    /// اتصال مع إعادة محاولة — خادم telnet الخاص بوضع المصنع قد يتأخر لحظة
    /// بعد رد mode=2 قبل أن يستمع، فالمحاولة الفورية قد تسبقه (سباق زمني).
    pub fn connect_retry(
        host: &str,
        port: u16,
        timeout_secs: u64,
        attempts: u32,
        delay_ms: u64,
    ) -> Result<Self, TelnetError> {
        let mut last: Option<TelnetError> = None;
        for i in 0..attempts.max(1) {
            if i > 0 {
                std::thread::sleep(Duration::from_millis(delay_ms));
            }
            match Self::connect(host, port, timeout_secs) {
                Ok(t) => return Ok(t),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or(TelnetError::Connect {
            host: host.into(),
            port,
            reason: "فشلت كل المحاولات".into(),
        }))
    }

    /// تسجيل دخول Login/Password ثم انتظار موجه الأوامر
    pub fn login(&mut self, user: &str, password: &str) -> Result<(), TelnetError> {
        self.login_attempt(user, password)
    }

    /// تسجيل دخول بسلسلة محاولات: المؤقتة أولاً ثم البدائل (root الدائم…).
    /// عند رفض الجهاز لمحاولة (Access denied + Login: من جديد) يجرّب التالية.
    pub fn login_fallback(&mut self, attempts: &[(String, String)]) -> Result<(), TelnetError> {
        if attempts.is_empty() {
            return Err(TelnetError::MarkerTimeout("لا محاولات دخول مُقدَّمة".into()));
        }
        for (u, p) in attempts {
            if self.login_attempt(u, p).is_ok() {
                return Ok(());
            }
            // الجهاز بعد الرفض يعيد عرض Login: — جاهزون للمحاولة التالية
        }
        Err(TelnetError::MarkerTimeout(format!(
            "رُفضت كل محاولات الدخول ({}): {}",
            attempts.len(),
            attempts.iter().map(|(u, _)| u.clone()).collect::<Vec<_>>().join(", ")
        )))
    }

    fn login_attempt(&mut self, user: &str, password: &str) -> Result<(), TelnetError> {
        // انتظار Login — بعد رفض سابق تكون العلامة معروضة أصلاً فنكتفي بقراءتها
        let _ = self.read_until(&[b"ogin", b"sername"], Some(Duration::from_secs(6)));
        self.sendline(user);
        let data = self.read_until(&[b"assword", b"denied", b"ncorrect"], Some(Duration::from_secs(6)))?;
        if data.windows(7).any(|w| w == b"ncorrect") || data.windows(6).any(|w| w == b"denied") {
            return Err(TelnetError::MarkerTimeout("Access denied (بعد المستخدم)".into()));
        }
        self.sendline(password);
        let data = self.read_until(&[b">", b"#", b"$", b"denied", b"ncorrect"], Some(Duration::from_secs(9)))?;
        if data.windows(7).any(|w| w == b"ncorrect") || data.windows(6).any(|w| w == b"denied") {
            return Err(TelnetError::MarkerTimeout("Access denied (بعد كلمة المرور)".into()));
        }
        self.drain();
        Ok(())
    }

    pub fn drain(&mut self) {
        self.stream.set_read_timeout(Some(Duration::from_millis(400))).ok();
        let mut buf = [0u8; 4096];
        loop {
            match self.stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        self.stream.set_read_timeout(Some(self.timeout)).ok();
    }

    /// ينفذ أمراً ويعيد مخرجاته (يقرأ حتى صمت قصير — مناسب للمخرجات الكبيرة)
    pub fn run_capture(&mut self, cmd: &str, quiet_rounds: usize) -> String {
        self.sendline(cmd);
        let mut acc = Vec::new();
        let mut quiet = 0;
        self.stream.set_read_timeout(Some(Duration::from_millis(1200))).ok();
        while quiet < quiet_rounds && acc.len() < 16_000_000 {
            match self.recv_some() {
                Ok(mut c) => {
                    acc.append(&mut c);
                    quiet = 0;
                }
                Err(_) => quiet += 1,
            }
        }
        self.stream.set_read_timeout(Some(self.timeout)).ok();
        latin1(&acc)
    }

    /// يبث ملفاً من الجهاز عبر hexdump ويعيد بايتاته (مرشّح الأسطر hex الزوجية ≤32)
    pub fn hex_stream_file(&mut self, path: &str) -> Result<Vec<u8>, TelnetError> {
        let cmd = format!(
            "hexdump -v -e '16/1 \"%02x\" \"\\n\"' {path}; echo ZUDZ_EOF"
        );
        let out = self.run_capture(&cmd, 3);
        let mut hexstr = String::new();
        for line in out.lines() {
            let l = line.trim();
            if !l.is_empty() && l.len() % 2 == 0 && l.len() <= 32 && l.chars().all(|c| c.is_ascii_hexdigit()) {
                hexstr.push_str(l);
            }
        }
        hex::decode(&hexstr).map_err(|e| TelnetError::MarkerTimeout(format!("hex فاسد: {e}")))
    }
}

/// أوامر تمديد عمر خادم telnet المؤقت (من التعليمات المجربة ميدانياً على
/// F6600P): تزيد `CloseServerTime`/`ExitTime` وحد الاتصالات — ليبقى خادم
/// telnet المصنع عاملاً بعد انتهاء الجلسة فتُعيد العمليات التالية استخدامه.
///
/// **لا تشمل `Lan_Enable`/`TS_*`**: تلك تُفعّل خادماً **دائماً** منفصلاً
/// (يعمل بعد الإقلاع) ببيانات لا تقبلها الأداة، فيحجب الفتح الجديد
/// (لا يستطيع استبدال خادم عامل) — وهو ما كسر إعادة الاستخدام ميدانياً.
pub const PERM_TELNET_COMMANDS: &[&str] = &[
    "sendcmd 1 DB set TelnetCfg 0 Max_Con_Num 99",
    "sendcmd 1 DB set TelnetCfg 0 ExitTime 999999",
    "sendcmd 1 DB set TelnetCfg 0 InitSecLvl 3",
    "sendcmd 1 DB set TelnetCfg 0 CloseServerTime 9999999",
    "sendcmd 1 DB save",
];

/// يطبّق تثبيت telnet الدائم على جلسة مفتوحة (يتجاهل أخطاء الأوامر).
pub fn apply_perm_telnet(tn: &mut ZteTelnet) {
    for cmd in PERM_TELNET_COMMANDS {
        let _ = tn.run_capture(cmd, 2);
    }
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn filter_iac<W: Write>(sink: &mut W, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut replies = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if b == IAC && i + 2 < data.len() {
            let (cmd, opt) = (data[i + 1], data[i + 2]);
            match cmd {
                DO => replies.extend_from_slice(&[IAC, WONT, opt]),
                WILL => replies.extend_from_slice(&[IAC, DONT, opt]),
                _ => {}
            }
            i += 3;
        } else if b == IAC && i + 1 < data.len() && data[i + 1] == IAC {
            out.push(IAC);
            i += 2;
        } else {
            out.push(b);
            i += 1;
        }
    }
    if !replies.is_empty() {
        let _ = sink.write_all(&replies);
        let _ = sink.flush();
    }
    out
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|c| *c as char).collect()
}

fn hex_or_ascii(b: &[u8]) -> String {
    let s = latin1(&b[b.len().saturating_sub(200)..]);
    s
}
