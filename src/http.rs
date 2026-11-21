//! Parsing minimal HTTP/1.x, résolution sûre des chemins, Range, MIME.
//!
//! Politique d'accès : seuls les fichiers réguliers situés DANS la racine sont servis.
//! Tout le reste (inexistant, `..`, lien symbolique sortant, dossier sans index.html,
//! fichier illisible) reçoit la même réponse de refus (403 par défaut, personnalisable),
//! afin de ne rien révéler de l'arborescence.
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

pub struct Resp {
    pub hdr: Vec<u8>,
    pub file: Option<File>,
    pub remaining: u64,
    /// Code HTTP de la réponse (journalisation).
    pub status: u16,
}

/// Réponse de refus : code HTTP personnalisable + corps HTML (chargé une seule fois au démarrage).
pub struct Deny {
    pub code: u16,
    pub body: Vec<u8>,
}

const DEFAULT_BODY: &str = "<!doctype html><html><head><meta charset=utf-8><title>Acc\u{e8}s refus\u{e9}</title></head>\
<body><h1>Acc\u{e8}s refus\u{e9}</h1></body></html>";

fn reason(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        410 => "Gone",
        451 => "Unavailable For Legal Reasons",
        _ => "Denied",
    }
}

impl Deny {
    /// `file` : chemin du HTML de refus (optionnel) ; `code` : code HTTP (défaut 403).
    pub fn load(file: Option<&str>, code: Option<u16>) -> Result<Deny, String> {
        let code = code.unwrap_or(403);
        if !(400..=599).contains(&code) {
            return Err(format!("XDP_DENY_CODE={code} invalide (attendu 400-599)"));
        }
        let body = match file {
            Some(p) => std::fs::read(p).map_err(|e| format!("XDP_403_FILE {p}: {e}"))?,
            None => DEFAULT_BODY.as_bytes().to_vec(),
        };
        Ok(Deny { code, body })
    }

    /// Construit la réponse de refus (le corps est omis pour HEAD).
    fn response(&self, head: bool) -> Resp {
        let hdr = format!(
            "HTTP/1.1 {} {}\r\nServer: xdp-httpd\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.code,
            reason(self.code),
            self.body.len()
        );
        let mut hdr = hdr.into_bytes();
        if !head {
            hdr.extend_from_slice(&self.body); // corps ajouté à l'en-tête : un seul envoi, pas de fichier
        }
        Resp { hdr, file: None, remaining: 0, status: self.code }
    }
}

fn simple(code: &str, extra: &str) -> Resp {
    let status = code.split(' ').next().and_then(|c| c.parse().ok()).unwrap_or(500);
    Resp {
        hdr: format!("HTTP/1.1 {code}\r\nServer: xdp-httpd\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n")
            .into_bytes(),
        file: None,
        remaining: 0,
        status,
    }
}

fn mime(p: &Path) -> &'static str {
    match p.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).as_deref().unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css",
        "js" | "mjs" => "text/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "txt" | "md" => "text/plain; charset=utf-8",
        "wasm" => "application/wasm",
        "woff2" => "font/woff2",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mkv" => "video/x-matroska",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "xz" => "application/x-xz",
        "zst" => "application/zstd",
        _ => "application/octet-stream",
    }
}

fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Résout la cible vers un fichier RÉGULIER situé dans la racine, sinon `None`.
/// Refuse `..`, chemins absolus, octets nuls et liens symboliques sortant de la racine.
fn resolve(root: &Path, target: &str) -> Option<PathBuf> {
    let path = target.split(['?', '#']).next()?;
    let path = pct_decode(path)?;
    if path.contains('\0') {
        return None;
    }
    let mut p = root.to_path_buf();
    for c in Path::new(&path).components() {
        match c {
            Component::Normal(s) => p.push(s),
            Component::RootDir | Component::CurDir => {}
            _ => return None, // ParentDir, Prefix
        }
    }
    if p.is_dir() {
        p.push("index.html");
    }
    // anti-symlink sortant de la racine (root est déjà canonique)
    let canon = p.canonicalize().ok()?;
    (canon.starts_with(root) && canon.is_file()).then_some(canon)
}

/// `bytes=a-b`, `bytes=a-`, `bytes=-n` (une seule plage).
fn parse_range(v: &str, size: u64) -> Option<Result<(u64, u64), ()>> {
    let r = v.trim().strip_prefix("bytes=")?;
    if r.contains(',') {
        return None; // multi-plages : on renvoie tout le fichier
    }
    let (a, b) = r.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    let res = if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        if n == 0 || size == 0 { Err(()) } else { Ok((size.saturating_sub(n), size - 1)) }
    } else {
        let s: u64 = a.parse().ok()?;
        let e: u64 = if b.is_empty() { size.saturating_sub(1) } else { b.parse::<u64>().ok()?.min(size.saturating_sub(1)) };
        if s >= size || s > e { Err(()) } else { Ok((s, e)) }
    };
    Some(res)
}

/// Construit la réponse à partir d'une requête complète (jusqu'à \r\n\r\n).
pub fn respond(root: &Path, deny: &Deny, req: &[u8]) -> Resp {
    let Ok(text) = std::str::from_utf8(req) else { return simple("400 Bad Request", "") };
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (method, target) = (first.next().unwrap_or(""), first.next().unwrap_or(""));
    let head = match method {
        "GET" => false,
        "HEAD" => true,
        _ => return simple("405 Method Not Allowed", "Allow: GET, HEAD\r\n"),
    };
    let range_hdr = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("range"))
        .map(|(_, v)| v.to_string());

    // Tout ce qui n'est pas un fichier régulier lisible de la racine => même refus.
    let Some(path) = resolve(root, target) else { return deny.response(head) };
    let Ok(mut file) = File::open(&path) else { return deny.response(head) };
    let Ok(meta) = file.metadata() else { return deny.response(head) };
    if !meta.is_file() {
        return deny.response(head);
    }
    let size = meta.len();
    let ct = mime(&path);

    let (status, start, len, extra) = match range_hdr.and_then(|v| parse_range(&v, size)) {
        Some(Ok((s, e))) => ("206 Partial Content", s, e - s + 1, format!("Content-Range: bytes {s}-{e}/{size}\r\n")),
        Some(Err(())) => return simple("416 Range Not Satisfiable", &format!("Content-Range: bytes */{size}\r\n")),
        None => ("200 OK", 0, size, String::new()),
    };
    if start > 0 && file.seek(SeekFrom::Start(start)).is_err() {
        return simple("500 Internal Server Error", "");
    }
    let code: u16 = status.split(' ').next().and_then(|c| c.parse().ok()).unwrap_or(200);
    let hdr = format!(
        "HTTP/1.1 {status}\r\nServer: xdp-httpd\r\nContent-Type: {ct}\r\nContent-Length: {len}\r\nAccept-Ranges: bytes\r\n{extra}Connection: close\r\n\r\n"
    )
    .into_bytes();
    if head {
        Resp { hdr, file: None, remaining: 0, status: code }
    } else {
        Resp { hdr, file: Some(file), remaining: len, status: code }
    }
}
