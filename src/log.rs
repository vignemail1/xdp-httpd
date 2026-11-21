//! Journalisation sans dépendance.
//!
//! - accès : format Common Log sur stdout (ou une ligne JSON si `--jsonc` / `XDP_JSONC=1`) ;
//! - erreurs : lignes de style Apache sur stderr.
use std::io::Write;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Date civile (UTC) à partir d'un nombre de jours depuis 1970-01-01.
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

struct Now {
    y: i64,
    mo: u32,
    d: u32,
    h: u64,
    mi: u64,
    s: u64,
    ms: u32,
}

fn now() -> Now {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = t.as_secs();
    let (y, mo, d) = civil((secs / 86_400) as i64);
    let rem = secs % 86_400;
    Now { y, mo, d, h: rem / 3600, mi: (rem % 3600) / 60, s: rem % 60, ms: t.subsec_millis() }
}

/// `10/Oct/2026:13:55:36 +0000` (UTC)
fn clf_time() -> String {
    let n = now();
    format!("{:02}/{}/{}:{:02}:{:02}:{:02} +0000", n.d, MONTHS[(n.mo - 1) as usize], n.y, n.h, n.mi, n.s)
}

/// `2026-10-10T13:55:36.123Z` (UTC, milliseconde)
fn iso_time() -> String {
    let n = now();
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", n.y, n.mo, n.d, n.h, n.mi, n.s, n.ms)
}

fn clf_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => o.push_str(&format!("\\x{:02x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// Extrait `(méthode, cible)` de la ligne de requête.
pub fn request_line(req: &[u8]) -> (String, String) {
    let line = req.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let line = String::from_utf8_lossy(line);
    let mut it = line.trim_end_matches('\r').split(' ');
    (it.next().unwrap_or("-").to_string(), it.next().unwrap_or("-").to_string())
}

/// Valeur d'un en-tête (insensible à la casse), si présent.
pub fn header(req: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(req);
    text.split("\r\n")
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
}

pub struct Logger {
    pub json: bool,
}

impl Logger {
    /// Journal d'accès : une ligne par requête traitée.
    pub fn access(&self, ip: Option<Ipv4Addr>, method: &str, target: &str, status: u16, bytes: u64, referer: Option<&str>, ua: Option<&str>) {
        let who = ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into());
        let line = if self.json {
            format!(
                "{{\"datetime\":\"{}\",\"remote\":\"{}\",\"method\":\"{}\",\"target\":\"{}\",\"status\":{},\"bytes\":{},\"referer\":\"{}\",\"user_agent\":\"{}\"}}",
                iso_time(),
                who,
                json_escape(method),
                json_escape(target),
                status,
                bytes,
                json_escape(referer.unwrap_or("")),
                json_escape(ua.unwrap_or(""))
            )
        } else {
            format!(
                "{} - - [{}] \"{} {} HTTP/1.1\" {} {} \"{}\" \"{}\"",
                who,
                clf_time(),
                clf_escape(method),
                clf_escape(target),
                status,
                bytes,
                clf_escape(referer.unwrap_or("-")),
                clf_escape(ua.unwrap_or("-"))
            )
        };
        let out = std::io::stdout();
        let mut o = out.lock();
        let _ = writeln!(o, "{line}");
    }

    /// Journal d'erreurs (stderr), style Apache : `[date] [niveau] message`.
    pub fn error(&self, level: &str, msg: &str) {
        let line = if self.json {
            format!("{{\"datetime\":\"{}\",\"level\":\"{}\",\"message\":\"{}\"}}", iso_time(), level, json_escape(msg))
        } else {
            format!("[{}] [{}] {}", clf_time(), level, msg)
        };
        let _ = writeln!(std::io::stderr(), "{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_epoch() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(20_647), (2026, 8, 31));
    }

    #[test]
    fn request_line_ok() {
        let (m, t) = request_line(b"GET /a/b HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!((m.as_str(), t.as_str()), ("GET", "/a/b"));
    }

    #[test]
    fn header_lookup() {
        let r = b"GET / HTTP/1.1\r\nUser-Agent: curl/8\r\nReferer: http://x/\r\n\r\n";
        assert_eq!(header(r, "user-agent").as_deref(), Some("curl/8"));
        assert_eq!(header(r, "Referer").as_deref(), Some("http://x/"));
        assert_eq!(header(r, "Range"), None);
    }

    #[test]
    fn escapes() {
        assert_eq!(clf_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
    }
}
