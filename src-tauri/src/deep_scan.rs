use serde::Serialize;
use std::collections::{BTreeSet, VecDeque};
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Finding {
    pub port: u16,
    pub service: String,
    pub evidence: Option<String>,
    pub connect_ms: f64,
}

const COMMON_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 53, 79, 80, 81, 88, 110, 111, 113, 119, 135, 139, 143, 161,
    179, 389, 427, 443, 445, 465, 500, 514, 515, 548, 554, 587, 593, 623, 631, 636,
    873, 902, 989, 990, 993, 995, 1025, 1080, 1194, 1433, 1521, 1723, 1883, 2049,
    2375, 2376, 3000, 3128, 3268, 3306, 3389, 3690, 4369, 4444, 5000, 5001, 5060,
    5061, 5432, 5555, 5672, 5900, 5901, 5985, 5986, 6379, 7001, 8000, 8008, 8009,
    8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 15672, 27017,
];

pub(super) fn port_list(mode: &str, custom: &str) -> Result<Vec<u16>, String> {
    let mut ports = BTreeSet::new();
    match mode {
        "quick" => ports.extend(COMMON_PORTS.iter().copied()),
        "standard" => ports.extend(1..=1024),
        "full" => ports.extend(1..=u16::MAX),
        "custom" => {
            for token in custom.split(|c: char| c == ',' || c == ';' || c.is_whitespace()).filter(|s| !s.is_empty()) {
                if let Some((start, end)) = token.split_once('-') {
                    let start: u16 = start.parse().map_err(|_| format!("Porta inválida: {token}"))?;
                    let end: u16 = end.parse().map_err(|_| format!("Porta inválida: {token}"))?;
                    if start == 0 || end < start { return Err(format!("Faixa inválida: {token}")) }
                    ports.extend(start..=end);
                } else {
                    let port: u16 = token.parse().map_err(|_| format!("Porta inválida: {token}"))?;
                    if port == 0 { return Err("As portas começam em 1".into()) }
                    ports.insert(port);
                }
            }
        }
        _ => return Err("Modo de varredura inválido".into()),
    }
    if ports.is_empty() { return Err("Informe ao menos uma porta".into()) }
    Ok(ports.into_iter().collect())
}

fn clean_text(bytes: &[u8]) -> Option<String> {
    let line = std::str::from_utf8(bytes).ok()?;
    if line.chars().any(|c| c.is_control() && !matches!(c, '\r' | '\n' | '\t')) { return None }
    let value = line.lines().find(|line| !line.trim().is_empty())?
        .chars().filter(|c| !c.is_control()).take(150).collect::<String>();
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn http_evidence(ip: Ipv4Addr, port: u16, https: bool) -> Option<String> {
    let scheme = if https { "https" } else { "http" };
    let client = reqwest::blocking::Client::builder()
        .no_proxy().danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_millis(500))
        .timeout(Duration::from_millis(1400)).build().ok()?;
    let response = client.head(format!("{scheme}://{ip}:{port}/")).send().ok()?;
    let server = response.headers().get(reqwest::header::SERVER)
        .and_then(|value| clean_text(value.as_bytes()));
    let status = response.status();
    Some(match server {
        Some(server) => format!("HTTP {status} · Server: {server}"),
        None => format!("HTTP {status} · versão não anunciada"),
    })
}

fn greeting(ip: Ipv4Addr, port: u16) -> Option<String> {
    let socket = SocketAddr::from((ip, port));
    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_millis(500)).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(550))).ok()?;
    let mut buffer = [0u8; 512];
    let count = stream.read(&mut buffer).ok()?;
    let text = String::from_utf8_lossy(&buffer[..count]);
    if let Some(ssh) = text.lines().find(|line| line.starts_with("SSH-")) {
        return clean_text(ssh.as_bytes());
    }
    clean_text(&buffer[..count])
}

fn service_label(port: u16) -> &'static str {
    match port {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 | 465 | 587 => "SMTP",
        53 => "DNS", 80 | 81 | 3000 | 5000 | 8000 | 8008 | 8080 | 8081 | 8088 | 8888 | 9000 | 9090 | 9200 => "HTTP",
        110 | 995 => "POP3", 143 | 993 => "IMAP", 135 => "RPC", 139 => "NetBIOS", 161 => "SNMP",
        389 | 636 => "LDAP", 443 | 8443 | 5986 => "HTTPS", 445 => "SMB", 1433 => "SQL Server",
        3306 => "MySQL", 3389 => "RDP", 5432 => "PostgreSQL", 5900 | 5901 => "VNC",
        5985 => "WinRM", 6379 => "Redis", 990 => "FTPS", 2376 => "Docker", 5061 => "SIP", 27017 => "MongoDB", _ => "TCP",
    }
}

fn identify(ip: Ipv4Addr, port: u16) -> (String, Option<String>) {
    let likely = service_label(port);
    if likely == "HTTPS" { return ("HTTPS".into(), http_evidence(ip, port, true)) }
    if [2376, 990, 993, 995, 5061].contains(&port) {
        return (format!("{likely}/TLS"), None);
    }
    if likely == "HTTP" || likely == "WinRM" {
        return ("HTTP".into(), http_evidence(ip, port, false));
    }
    let banner = greeting(ip, port);
    if let Some(ref value) = banner {
        if value.starts_with("SSH-") { return ("SSH".into(), banner) }
        if value.starts_with("HTTP/") { return ("HTTP".into(), banner) }
    }
    if likely == "TCP" {
        if let Some(evidence) = http_evidence(ip, port, false) { return ("HTTP".into(), Some(evidence)) }
    }
    (likely.into(), banner)
}

pub(super) fn scan<F>(ip: Ipv4Addr, ports: Vec<u16>, timeout_ms: u64, cancel: &AtomicBool, progress: F) -> Vec<Finding>
where F: Fn(usize, usize, Option<Finding>) + Sync {
    let total = ports.len();
    let queue = Arc::new(Mutex::new(VecDeque::from(ports)));
    let findings = Arc::new(Mutex::new(Vec::<Finding>::new()));
    let done = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..total.min(48) {
            let queue = queue.clone();
            let findings = findings.clone();
            let progress = &progress;
            let done = &done;
            scope.spawn(move || loop {
                if cancel.load(Ordering::Relaxed) { break }
                let port = queue.lock().expect("fila de portas").pop_front();
                let Some(port) = port else { break };
                let start = Instant::now();
                let connected = TcpStream::connect_timeout(&SocketAddr::from((ip, port)), Duration::from_millis(timeout_ms)).is_ok();
                let connect_ms = start.elapsed().as_secs_f64() * 1000.0;
                let finding = if connected {
                    let (service, evidence) = identify(ip, port);
                    Some(Finding { port, service, evidence, connect_ms })
                } else { None };
                if let Some(ref item) = finding { findings.lock().expect("resultados").push(item.clone()); }
                let completed = done.fetch_add(1, Ordering::Relaxed) + 1;
                if finding.is_some() || completed % 32 == 0 || completed == total {
                    progress(completed, total, finding);
                }
            });
        }
    });
    let completed = done.load(Ordering::Relaxed);
    if completed < total { progress(completed, total, None); }
    let mut result = findings.lock().expect("resultados").clone();
    result.sort_by_key(|finding| finding.port);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_modes_and_ranges_are_bounded() {
        assert!(port_list("quick", "").unwrap().len() > 50);
        assert_eq!(port_list("standard", "").unwrap().len(), 1024);
        assert_eq!(port_list("full", "").unwrap().len(), 65535);
        assert_eq!(port_list("custom", "80, 443, 8000-8002, 80").unwrap(), vec![80, 443, 8000, 8001, 8002]);
        assert!(port_list("custom", "0").is_err());
        assert!(port_list("custom", "100-90").is_err());
    }

    #[test]
    fn scanner_finds_local_tcp_listener() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let done = AtomicBool::new(false);
        let found = scan(Ipv4Addr::LOCALHOST, vec![port], 500, &done, |_, _, _| {});
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].port, port);
    }

    #[test]
    fn identifies_ssh_banner_on_nonstandard_port() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            use std::io::Write;
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"SSH-2.0-TestServer_1.2\r\n").unwrap();
        });
        let (service, evidence) = identify(Ipv4Addr::LOCALHOST, port);
        server.join().unwrap();
        assert_eq!(service, "SSH");
        assert_eq!(evidence.as_deref(), Some("SSH-2.0-TestServer_1.2"));
    }
}
