mod dev;
mod http;

use aya::maps::XskMap;
use aya::programs::{Xdp, XdpFlags};
use aya::EbpfLoader;
use dev::XdpDev;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Address};
use std::io::Read;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use xsk_rs::config::{BindFlags, Interface as XskIf, LibxdpFlags, SocketConfig, UmemConfig};
use xsk_rs::{Socket, Umem};

// ---- Réglages d'empreinte (voir README) ----
const FRAMES: u32 = 4096; // UMEM = FRAMES x 4 Kio
const RX_FRAMES: usize = 2048;
const MAX_CONN: usize = 32;
const RX_BUF: usize = 8 * 1024;
const TX_BUF: usize = 128 * 1024;
const CHUNK: usize = 16 * 1024;
const MAX_REQ: usize = 8 * 1024;

static BPF_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp_httpd.o"));

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

// ---------------- État d'une connexion ----------------
struct Conn {
    handle: SocketHandle,
    port: u16,
    tls: bool,
    #[cfg(feature = "tls")]
    sess: Option<rustls::ServerConnection>,
    req: Vec<u8>,
    resp: Option<http::Resp>,
    out: Vec<u8>, // octets prêts à partir sur TCP (chiffrés si TLS)
    closing: bool,
}

impl Conn {
    fn reset(&mut self) {
        #[cfg(feature = "tls")]
        {
            self.sess = None;
        }
        self.req.clear();
        self.resp = None;
        self.out.clear();
        self.closing = false;
    }
}

#[cfg(feature = "tls")]
fn load_tls() -> Res<Option<std::sync::Arc<rustls::ServerConfig>>> {
    use std::{fs::File, io::BufReader, sync::Arc};
    let (Some(c), Some(k)) = (env("XDP_TLS_CERT"), env("XDP_TLS_KEY")) else { return Ok(None) };
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(&c)?)).collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(&k)?))?.ok_or("aucune clé privée trouvée")?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Some(Arc::new(cfg)))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("xdp-httpd: erreur: {e}");
        std::process::exit(1);
    }
}

fn sock_cfg(zc: bool) -> SocketConfig {
    let mut bf = BindFlags::XDP_USE_NEED_WAKEUP;
    bf |= if zc { BindFlags::XDP_ZEROCOPY } else { BindFlags::XDP_COPY };
    SocketConfig::builder()
        .libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD) // notre propre programme
        .bind_flags(bf)
        .build()
}

fn run() -> Res<()> {
    // ---------- Configuration ----------
    let root: PathBuf = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| ".".into()).canonicalize()?;
    let ifname = env("XDP_IF").ok_or("XDP_IF manquant (ex. XDP_IF=eth0)")?;
    let cidr: IpCidr = env("XDP_IP").ok_or("XDP_IP manquant (ex. 192.168.1.50/24)")?.parse().map_err(|_| "XDP_IP invalide")?;
    let IpCidr::Ipv4(c4) = cidr;
    let ip = Ipv4Addr::from(c4.address().0);
    let gw: Option<Ipv4Addr> = env("XDP_GW").map(|g| g.parse()).transpose()?;
    let queue: u32 = env("XDP_QUEUE").map(|q| q.parse()).transpose()?.unwrap_or(0);
    let port: u16 = env("XDP_PORT").map(|q| q.parse()).transpose()?.unwrap_or(80);
    let zc = env("XDP_ZC").as_deref() == Some("1");

    #[cfg(feature = "tls")]
    let tls_cfg = load_tls()?;
    #[cfg(feature = "tls")]
    let tls_port: u16 = if tls_cfg.is_some() { env("XDP_TLS_PORT").map(|q| q.parse()).transpose()?.unwrap_or(443) } else { 0 };
    #[cfg(not(feature = "tls"))]
    let tls_port: u16 = {
        if env("XDP_TLS_CERT").is_some() {
            eprintln!("avertissement: XDP_TLS_CERT ignoré (compilé sans --features tls)");
        }
        0
    };

    let mac_s = std::fs::read_to_string(format!("/sys/class/net/{ifname}/address"))
        .map_err(|e| format!("interface {ifname} introuvable: {e}"))?;
    let mac = EthernetAddress::from_bytes(
        &mac_s.trim().split(':').map(|h| u8::from_str_radix(h, 16)).collect::<Result<Vec<u8>, _>>()?,
    );

    // ---------- Programme XDP (aya) ----------
    let cfg_ip = u32::from_ne_bytes(ip.octets()); // ordre réseau en mémoire
    let cfg_port = u16::from_ne_bytes(port.to_be_bytes());
    let cfg_tls = u16::from_ne_bytes(tls_port.to_be_bytes());
    let mut bpf = EbpfLoader::new()
        .set_global("CFG_IP", &cfg_ip, true)
        .set_global("CFG_PORT", &cfg_port, true)
        .set_global("CFG_PORT_TLS", &cfg_tls, true)
        .load(BPF_OBJ)?;
    let prog: &mut Xdp = bpf.program_mut("xdp_httpd").ok_or("programme xdp_httpd absent")?.try_into()?;
    prog.load()?;
    // Le zero-copy exige le mode natif (pilote).
    let flags = match env("XDP_MODE").as_deref() {
        Some("skb") => XdpFlags::SKB_MODE,
        Some("drv") => XdpFlags::DRV_MODE,
        _ if zc => XdpFlags::DRV_MODE,
        _ => XdpFlags::default(),
    };
    prog.attach(&ifname, flags).map_err(|e| format!("attache XDP sur {ifname}: {e} (essayez XDP_MODE=skb sans XDP_ZC)"))?;

    // ---------- Socket AF_XDP ----------
    let (umem, mut descs) = Umem::new(UmemConfig::default(), NonZeroU32::new(FRAMES).unwrap(), false)?;
    let xif: XskIf = ifname.parse()?;
    let (tx, rx, fqcq, zc_on) = match unsafe { Socket::new(sock_cfg(zc), &umem, &xif, queue) } {
        Ok((t, r, f)) => (t, r, f, zc),
        Err(e) if zc => {
            eprintln!("xdp-httpd: zero-copy refusé ({e}), repli en mode copie");
            let (t, r, f) = unsafe { Socket::new(sock_cfg(false), &umem, &xif, queue) }?;
            (t, r, f, false)
        }
        Err(e) => return Err(e.into()),
    };
    let (mut fq, cq) = fqcq.ok_or("file fill/completion absente")?;

    let mut xsks = XskMap::try_from(bpf.map_mut("xsks").ok_or("map xsks absente")?)?;
    let raw_fd = rx.fd().as_raw_fd();
    xsks.set(queue, raw_fd, 0)?;

    let tx_descs = descs.split_off(RX_FRAMES);
    unsafe { fq.produce(&descs) };
    let mut dev = XdpDev {
        umem,
        rx,
        tx,
        fq,
        cq,
        rx_descs: descs,
        scratch: tx_descs.clone(),
        tx_free: tx_descs,
        rx_buf: vec![0u8; 4096],
    };

    // ---------- Pile TCP/IP ----------
    let mut iface = Interface::new(Config::new(HardwareAddress::Ethernet(mac)), &mut dev, Instant::now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(cidr);
    });
    if let Some(g) = gw {
        iface.routes_mut().add_default_ipv4_route(Ipv4Address::from_bytes(&g.octets()))?;
    }

    let mut sockets = SocketSet::new(vec![]);
    let mut conns: Vec<Conn> = Vec::new();
    let ports: Vec<(u16, bool)> = if tls_port != 0 { vec![(port, false), (tls_port, true)] } else { vec![(port, false)] };
    for &(p, tls) in &ports {
        for _ in 0..MAX_CONN {
            let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; RX_BUF]), tcp::SocketBuffer::new(vec![0; TX_BUF]));
            s.listen(p)?;
            conns.push(Conn {
                handle: sockets.add(s),
                port: p,
                tls,
                #[cfg(feature = "tls")]
                sess: None,
                req: Vec::new(),
                resp: None,
                out: Vec::new(),
                closing: false,
            });
        }
    }

    eprintln!(
        "xdp-httpd: {ip} sur {ifname} file {queue} ({}), HTTP:{port}{}, racine {}",
        if zc_on { "zero-copy" } else { "copie" },
        if tls_port != 0 { format!(" HTTPS:{tls_port}") } else { String::new() },
        root.display()
    );

    // ---------- Boucle principale ----------
    let mut chunk = vec![0u8; CHUNK];
    loop {
        iface.poll(Instant::now(), &mut dev, &mut sockets);
        for c in conns.iter_mut() {
            let s = sockets.get_mut::<tcp::Socket>(c.handle);
            #[cfg(feature = "tls")]
            service(c, s, &root, &mut chunk, tls_cfg.as_ref());
            #[cfg(not(feature = "tls"))]
            service(c, s, &root, &mut chunk);
        }
        iface.poll(Instant::now(), &mut dev, &mut sockets);
        dev.reclaim();

        // Attente passive jusqu'au prochain paquet ou timer TCP
        let busy = conns.iter().any(|c| !c.out.is_empty() || c.resp.as_ref().is_some_and(|r| r.remaining > 0));
        let ms = if busy {
            0
        } else {
            iface.poll_delay(Instant::now(), &sockets).map(|d| d.total_millis().min(1000) as i32).unwrap_or(1000)
        };
        if ms > 0 {
            let mut pfd = libc::pollfd { fd: raw_fd, events: libc::POLLIN, revents: 0 };
            unsafe { libc::poll(&mut pfd, 1, ms) };
        }
    }
}

fn service(
    c: &mut Conn,
    s: &mut tcp::Socket,
    root: &Path,
    chunk: &mut [u8],
    #[cfg(feature = "tls")] tls_cfg: Option<&std::sync::Arc<rustls::ServerConfig>>,
) {
    if !s.is_open() {
        c.reset();
        let _ = s.listen(c.port);
        return;
    }
    if !s.may_send() && !s.may_recv() {
        return;
    }

    // ----- Réception -----
    let mut inbuf = Vec::new();
    while s.can_recv() {
        let got = s.recv(|b| {
            inbuf.extend_from_slice(b);
            (b.len(), b.len())
        });
        if !matches!(got, Ok(n) if n > 0) {
            break;
        }
    }

    #[cfg(feature = "tls")]
    if c.tls {
        let Some(cfg) = tls_cfg else { s.abort(); return };
        if c.sess.is_none() {
            match rustls::ServerConnection::new(cfg.clone()) {
                Ok(x) => c.sess = Some(x),
                Err(_) => { s.abort(); return; }
            }
        }
        let sess = c.sess.as_mut().unwrap();
        let mut rd = &inbuf[..];
        while !rd.is_empty() {
            if sess.read_tls(&mut rd).is_err() { s.abort(); return; }
            if sess.process_new_packets().is_err() {
                let _ = sess.write_tls(&mut c.out);
                let _ = s.send_slice(&c.out);
                s.close();
                return;
            }
        }
        let mut tmp = [0u8; 2048];
        while let Ok(n) = sess.reader().read(&mut tmp) {
            if n == 0 { break; }
            c.req.extend_from_slice(&tmp[..n]);
        }
    }
    if !c.tls {
        c.req.extend_from_slice(&inbuf);
    }

    // ----- Requête complète ? -----
    if c.resp.is_none() && !c.closing {
        if let Some(pos) = c.req.windows(4).position(|w| w == b"\r\n\r\n") {
            let r = http::respond(root, &c.req[..pos + 4]);
            push_plain(c, &r.hdr);
            c.resp = Some(r);
        } else if c.req.len() > MAX_REQ {
            s.abort();
            return;
        }
    }

    // ----- Streaming du fichier par blocs (gros fichiers) -----
    loop {
        if c.out.len() >= CHUNK || s.send_queue() + CHUNK > s.send_capacity() {
            break;
        }
        let Some(r) = c.resp.as_mut() else { break };
        if r.remaining == 0 {
            break;
        }
        let Some(f) = r.file.as_mut() else { break };
        let want = (chunk.len() as u64).min(r.remaining) as usize;
        match f.read(&mut chunk[..want]) {
            Ok(0) | Err(_) => { r.remaining = 0; c.closing = true; break; }
            Ok(n) => {
                r.remaining -= n as u64;
                let data = chunk[..n].to_vec();
                push_plain(c, &data);
            }
        }
    }

    // ----- Émission -----
    if !c.out.is_empty() && s.can_send() {
        if let Ok(n) = s.send_slice(&c.out) {
            c.out.drain(..n);
        }
    }

    let done = c.resp.as_ref().is_some_and(|r| r.remaining == 0) || c.closing;
    if done && c.out.is_empty() {
        #[cfg(feature = "tls")]
        if let Some(sess) = c.sess.as_mut() {
            if !c.closing { sess.send_close_notify(); c.closing = true; let _ = sess.write_tls(&mut c.out); return; }
        }
        s.close();
        c.resp = None;
        c.closing = true;
    }
}

/// Ajoute des octets applicatifs à la file de sortie (chiffrés si TLS).
fn push_plain(c: &mut Conn, data: &[u8]) {
    #[cfg(feature = "tls")]
    if let Some(sess) = c.sess.as_mut() {
        use std::io::Write;
        let _ = sess.writer().write_all(data);
        while sess.wants_write() {
            if sess.write_tls(&mut c.out).is_err() { break; }
        }
        return;
    }
    c.out.extend_from_slice(data);
}
