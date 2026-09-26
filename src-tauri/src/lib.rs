use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, State};

mod deep_scan;

#[cfg(windows)]
fn hidden_command(program: &str) -> Command {
    use std::os::windows::process::CommandExt;
    let mut command = Command::new(program);
    command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    command
}

#[cfg(not(windows))]
fn hidden_command(program: &str) -> Command {
    Command::new(program)
}

#[derive(Default)]
struct ScanState {
    running: AtomicBool,
    cancel: AtomicBool,
}

#[derive(Default)]
struct MonitorState {
    active: Mutex<HashMap<String, Arc<AtomicBool>>>,
}

#[derive(Default)]
struct DeepScanState {
    running: AtomicBool,
    cancel: AtomicBool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Subnet {
    cidr: String,
    label: String,
    source: String,
    host_count: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PortInfo {
    port: u16,
    service: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Host {
    ip: String,
    hostname: Option<String>,
    mac: Option<String>,
    response_ms: Option<u128>,
    ports: Vec<PortInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProbeResult {
    online: bool,
    latency_ms: Option<f64>,
    method: Option<&'static str>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceProbe {
    ip: String,
    checked_at: u128,
    online: bool,
    latency_ms: Option<f64>,
    method: Option<&'static str>,
    error: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeepScanProgress {
    ip: String,
    done: usize,
    total: usize,
    finding: Option<deep_scan::Finding>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeepScanOutcome {
    ip: String,
    findings: Vec<deep_scan::Finding>,
    cancelled: bool,
    scanned: usize,
    total: usize,
    elapsed_ms: u128,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanProgress {
    done: usize,
    total: usize,
    host: Option<Host>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanOutcome {
    hosts: Vec<Host>,
    cancelled: bool,
}

fn powershell(script: &str) -> Result<Value, String> {
    let output = hidden_command("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| format!("Não foi possível abrir o PowerShell: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(text.trim()).map_err(|e| format!("Resposta do Windows inválida: {e}"))
}

fn rows(value: Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items,
        Value::Object(_) => vec![value],
        _ => vec![],
    }
}

fn cidr_range(cidr: &str) -> Result<(u32, u8), String> {
    let (ip, bits) = cidr.split_once('/').ok_or("Use o formato 192.168.1.0/24")?;
    let ip = Ipv4Addr::from_str(ip).map_err(|_| "Endereço IPv4 inválido")?;
    let bits: u8 = bits.parse().map_err(|_| "Prefixo de rede inválido")?;
    if bits > 32 {
        return Err("Prefixo de rede inválido".into());
    }
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Ok((u32::from(ip) & mask, bits))
}

fn normalized_cidr(cidr: &str) -> Option<String> {
    let (network, bits) = cidr_range(cidr).ok()?;
    Some(format!("{}/{}", Ipv4Addr::from(network), bits))
}

fn cidr_from_mask(ip: &str, mask: &str) -> Option<String> {
    let ip = Ipv4Addr::from_str(ip).ok()?;
    let mask = u32::from(Ipv4Addr::from_str(mask).ok()?);
    let bits = mask.count_ones();
    if !(8..=30).contains(&bits) || mask != u32::MAX << (32 - bits) { return None }
    normalized_cidr(&format!("{ip}/{bits}"))
}

fn useful_subnet(cidr: &str) -> Option<(String, u8)> {
    let (network, bits) = cidr_range(cidr).ok()?;
    let ip = Ipv4Addr::from(network);
    if bits < 8 || bits > 30 || ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || ip.is_unspecified() {
        return None;
    }
    Some((format!("{ip}/{bits}"), bits))
}

fn parse_fortigate_networks(routes: &str, interfaces: &str) -> Vec<Subnet> {
    let mut found = HashMap::<String, Subnet>::new();
    for line in routes.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 || !parts[0].chars().all(|c| c.is_ascii_alphabetic() || c == '*') { continue }
        let Some((cidr, bits)) = useful_subnet(parts[1]) else { continue };
        let kind = if parts[0].starts_with('C') { "conectada" } else { "rota" };
        let name = parts.last().unwrap_or(&"FortiGate").trim_end_matches(',');
        found.entry(cidr.clone()).or_insert(Subnet {
            cidr, label: format!("FortiGate · {kind} · {name}"),
            source: "fortigate".into(), host_count: 1u64 << (32 - bits),
        });
    }
    let mut interface_name = String::new();
    for line in interfaces.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("edit ") {
            interface_name = rest.trim_matches('"').to_owned();
        } else if let Some(rest) = trimmed.strip_prefix("set ip ") {
            let mut fields = rest.split_whitespace();
            let Some(ip) = fields.next() else { continue };
            let Some(mask) = fields.next() else { continue };
            let Some(cidr) = cidr_from_mask(ip, mask) else { continue };
            let Some((cidr, bits)) = useful_subnet(&cidr) else { continue };
            found.entry(cidr.clone()).or_insert(Subnet {
                cidr, label: format!("FortiGate · interface · {interface_name}"),
                source: "fortigate".into(), host_count: 1u64 << (32 - bits),
            });
        }
    }
    let mut networks: Vec<_> = found.into_values().collect();
    networks.sort_by(|a, b| a.cidr.cmp(&b.cidr));
    networks
}

fn fortigate_ssh_session(ip: &str, port: u16) -> Result<(ssh2::Session, String), String> {
    let address = Ipv4Addr::from_str(ip).map_err(|_| "IP do FortiGate inválido")?;
    let socket = TcpStream::connect_timeout(&SocketAddr::from((address, port)), Duration::from_secs(8))
        .map_err(|e| format!("Não foi possível conectar ao SSH do FortiGate: {e}"))?;
    socket.set_read_timeout(Some(Duration::from_secs(15))).map_err(|e| e.to_string())?;
    socket.set_write_timeout(Some(Duration::from_secs(15))).map_err(|e| e.to_string())?;
    let mut session = ssh2::Session::new().map_err(|e| e.to_string())?;
    session.set_timeout(15_000);
    session.set_tcp_stream(socket);
    session.handshake().map_err(|e| format!("Falha no handshake SSH: {e}"))?;
    let hash = session.host_key_hash(ssh2::HashType::Sha256)
        .ok_or("O FortiGate não forneceu uma chave SSH verificável")?;
    let fingerprint = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok((session, fingerprint))
}

fn fortigate_ssh_exec(session: &ssh2::Session, command: &str) -> Result<String, String> {
    let mut channel = session.channel_session().map_err(|e| e.to_string())?;
    channel.exec(command).map_err(|e| format!("O FortiGate recusou o comando {command}: {e}"))?;
    let mut output = String::new();
    channel.read_to_string(&mut output).map_err(|e| format!("Falha ao ler a resposta SSH: {e}"))?;
    channel.wait_close().map_err(|e| e.to_string())?;
    if output.contains("Command fail") || output.contains("Permission denied") {
        return Err(format!("O FortiGate não autorizou {command}: {}", output.trim()));
    }
    Ok(output)
}

#[tauri::command]
async fn fortigate_ssh_fingerprint(ip: String, port: u16) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || fortigate_ssh_session(&ip, port).map(|(_, hash)| hash))
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn fortigate_ssh_networks(ip: String, port: u16, username: String, password: Option<String>, fingerprint: String) -> Result<Vec<Subnet>, String> {
    if !valid_username(&username) { return Err("Usuário SSH inválido".into()) }
    if fingerprint.len() != 64 || !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Confirme primeiro a impressão digital SSH do FortiGate".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let (session, actual) = fortigate_ssh_session(&ip, port)?;
        if !actual.eq_ignore_ascii_case(&fingerprint) {
            return Err("A chave SSH do FortiGate mudou. Confira a impressão digital antes de continuar.".into());
        }
        if let Some(password) = password.filter(|p| !p.is_empty()) {
            session.userauth_password(&username, &password).map_err(|e| format!("Falha na autenticação SSH: {e}"))?;
        } else {
            session.userauth_agent(&username).map_err(|e| format!("Falha ao usar o agente SSH. Informe a senha ou configure uma chave: {e}"))?;
        }
        if !session.authenticated() { return Err("O FortiGate não autenticou o usuário SSH".into()) }
        let routes = fortigate_ssh_exec(&session, "get router info routing-table all")?;
        let interfaces = fortigate_ssh_exec(&session, "show system interface")?;
        Ok(parse_fortigate_networks(&routes, &interfaces))
    }).await.map_err(|e| e.to_string())?
}

#[tauri::command]
fn detect_subnets() -> Result<Vec<Subnet>, String> {
    let ip_script = "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.AddressState -eq 'Preferred' -and $_.PrefixLength -lt 32 -and $_.IPAddress -notlike '169.254*' -and $_.IPAddress -notlike '127.*' } | Select-Object InterfaceAlias,IPAddress,PrefixLength | ConvertTo-Json -Compress";
    let route_script = "Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -ne '0.0.0.0/0' -and $_.DestinationPrefix -notlike '*/32' } | Select-Object InterfaceAlias,DestinationPrefix | ConvertTo-Json -Compress";
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    for row in rows(powershell(ip_script)?) {
        let Some(ip) = row["IPAddress"].as_str() else { continue };
        let Some(bits) = row["PrefixLength"].as_u64() else { continue };
        let Some(cidr) = normalized_cidr(&format!("{ip}/{bits}")) else { continue };
        let (_, bits) = cidr_range(&cidr)?;
        if seen.insert(cidr.clone()) {
            found.push(Subnet {
                cidr,
                label: row["InterfaceAlias"].as_str().unwrap_or("Interface local").to_owned(),
                source: "interface".into(),
                host_count: 1u64 << (32 - bits),
            });
        }
    }
    if let Ok(routes) = powershell(route_script) {
        for row in rows(routes) {
            let Some(raw) = row["DestinationPrefix"].as_str() else { continue };
            let Some(cidr) = normalized_cidr(raw) else { continue };
            let (network, bits) = cidr_range(&cidr)?;
            let address = Ipv4Addr::from(network);
            if address.is_loopback() || address.is_link_local() || address.is_multicast() || address.is_unspecified() || bits < 8 || !seen.insert(cidr.clone()) {
                continue;
            }
            found.push(Subnet {
                cidr,
                label: row["InterfaceAlias"].as_str().unwrap_or("Rota conhecida").to_owned(),
                source: "route".into(),
                host_count: 1u64 << (32 - bits),
            });
        }
    }
    found.sort_by(|a, b| a.source.cmp(&b.source).then(a.cidr.cmp(&b.cidr)));
    Ok(found)
}

fn service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP", 53 => "DNS",
        80 => "HTTP", 110 => "POP3", 123 => "NTP", 135 => "RPC", 139 => "NetBIOS",
        143 => "IMAP", 161 => "SNMP", 389 => "LDAP", 443 => "HTTPS", 445 => "SMB",
        587 => "SMTP", 636 => "LDAPS", 1433 => "SQL Server", 3306 => "MySQL",
        3389 => "RDP", 5432 => "PostgreSQL", 5900 => "VNC", 8080 => "HTTP alt",
        8443 => "HTTPS alt", _ => "TCP",
    }
}

fn tcp_open(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> bool {
    let addr = SocketAddr::from((ip, port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).is_ok()
}

fn parse_ping_latency(output: &str) -> Option<f64> {
    for line in output.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("ttl=") { continue }
        let end = lower.find("ms")?;
        let before = &lower[..end];
        let start = before.rfind(|c: char| !c.is_ascii_digit() && c != '.' && c != ',').map_or(0, |i| i + 1);
        let value = before[start..].replace(',', ".").parse::<f64>().ok()?;
        return Some(if before[..start].ends_with('<') { value / 2.0 } else { value });
    }
    None
}

fn ping_once(ip: Ipv4Addr, timeout_ms: u32) -> Result<(bool, Option<f64>), String> {
    let output = hidden_command("ping.exe")
        .args(["-n", "1", "-w", &timeout_ms.to_string(), &ip.to_string()])
        .output()
        .map_err(|e| format!("Não foi possível executar ping: {e}"))?;
    let online = output.status.success();
    let latency = online.then(|| parse_ping_latency(&String::from_utf8_lossy(&output.stdout))).flatten();
    Ok((online, latency))
}

fn probe_device_sync(address: Ipv4Addr, ports: &[u16]) -> Result<ProbeResult, String> {
    let (online, latency_ms) = ping_once(address, 1000)?;
    if online { return Ok(ProbeResult { online: true, latency_ms, method: Some("ICMP") }) }
    let latency = Arc::new(Mutex::new(None::<f64>));
    std::thread::scope(|scope| {
        for &port in ports.iter().filter(|port| **port > 0).take(5) {
            let latency = latency.clone();
            scope.spawn(move || {
                let start = Instant::now();
                if tcp_open(address, port, 300) {
                    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                    let mut fastest = latency.lock().expect("latência TCP");
                    *fastest = Some(fastest.map_or(elapsed, |current| current.min(elapsed)));
                }
            });
        }
    });
    let latency_ms = *latency.lock().map_err(|e| e.to_string())?;
    Ok(ProbeResult { online: latency_ms.is_some(), latency_ms, method: latency_ms.map(|_| "TCP") })
}

#[tauri::command]
fn start_device_monitor(ip: String, ports: Vec<u16>, interval_sec: u64, app: AppHandle, state: State<'_, Arc<MonitorState>>) -> Result<(), String> {
    let address = Ipv4Addr::from_str(&ip).map_err(|_| "IP inválido")?;
    if !(2..=300).contains(&interval_sec) { return Err("Escolha um intervalo entre 2 e 300 segundos".into()) }
    let ports: Vec<u16> = ports.into_iter().filter(|port| *port > 0).take(5).collect();
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut active = state.active.lock().map_err(|_| "Falha no monitor".to_owned())?;
        if !active.contains_key(&ip) && active.len() >= 32 { return Err("Limite de 32 dispositivos monitorados ao mesmo tempo".into()) }
        if let Some(old) = active.insert(ip.clone(), cancel.clone()) { old.store(true, Ordering::SeqCst); }
    }
    tauri::async_runtime::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_sec));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if cancel.load(Ordering::SeqCst) { break }
            let sample_ports = ports.clone();
            let result = tauri::async_runtime::spawn_blocking(move || probe_device_sync(address, &sample_ports)).await;
            if cancel.load(Ordering::SeqCst) { break }
            let (probe, error) = match result {
                Ok(Ok(probe)) => (Some(probe), None),
                Ok(Err(error)) => (None, Some(error)),
                Err(error) => (None, Some(error.to_string())),
            };
            let checked_at = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_millis());
            let _ = app.emit("device-probe", DeviceProbe {
                ip: ip.clone(), checked_at,
                online: probe.as_ref().is_some_and(|value| value.online),
                latency_ms: probe.as_ref().and_then(|value| value.latency_ms),
                method: probe.as_ref().and_then(|value| value.method), error,
            });
        }
    });
    Ok(())
}

#[tauri::command]
fn stop_device_monitor(ip: String, state: State<'_, Arc<MonitorState>>) -> Result<(), String> {
    let mut active = state.active.lock().map_err(|_| "Falha no monitor".to_owned())?;
    if let Some(cancel) = active.remove(&ip) { cancel.store(true, Ordering::SeqCst); }
    Ok(())
}

#[tauri::command]
fn stop_all_device_monitors(state: State<'_, Arc<MonitorState>>) -> Result<(), String> {
    let mut active = state.active.lock().map_err(|_| "Falha no monitor".to_owned())?;
    for (_, cancel) in active.drain() { cancel.store(true, Ordering::SeqCst); }
    Ok(())
}

fn probe_host(ip: Ipv4Addr, ports: &[u16]) -> Option<Host> {
    let ip_text = ip.to_string();
    let ping = hidden_command("ping.exe")
        .args(["-a", "-n", "1", "-w", "400", &ip_text])
        .output()
        .ok();
    let ping_ok = ping.as_ref().is_some_and(|output| output.status.success());
    let hostname = ping.as_ref().and_then(|output| {
        let output = String::from_utf8_lossy(&output.stdout);
        let first = output.lines().find(|line| line.contains(&format!("[{ip_text}]")))?;
        let before = first.split('[').next()?.trim();
        let name = before.split_whitespace().last()?;
        if name == ip_text { None } else { Some(name.to_owned()) }
    });
    let response_ms = ping_ok.then(|| parse_ping_latency(&String::from_utf8_lossy(&ping.as_ref()?.stdout)))
        .flatten().map(|ms| ms.ceil() as u128);
    let mut open = Vec::new();
    let quick_ports = [80, 443, 22, 445, 3389];
    let mut alive = ping_ok;
    if !alive {
        for port in quick_ports {
            if tcp_open(ip, port, 130) {
                alive = true;
                open.push(PortInfo { port, service: service_name(port).into() });
                break;
            }
        }
    }
    if !alive { return None }
    for &port in ports {
        if !open.iter().any(|p| p.port == port) && tcp_open(ip, port, 150) {
            open.push(PortInfo { port, service: service_name(port).into() });
        }
    }
    open.sort_by_key(|p| p.port);
    Some(Host { ip: ip_text, hostname, mac: None, response_ms, ports: open, display_name: None })
}

fn neighbor_map() -> HashMap<String, String> {
    let script = "Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } | Select-Object IPAddress,LinkLayerAddress | ConvertTo-Json -Compress";
    let mut map = HashMap::new();
    if let Ok(value) = powershell(script) {
        for row in rows(value) {
            if let (Some(ip), Some(mac)) = (row["IPAddress"].as_str(), row["LinkLayerAddress"].as_str()) {
                map.insert(ip.to_owned(), mac.to_owned());
            }
        }
    }
    map
}

#[tauri::command]
async fn scan_network(cidr: String, ports: Vec<u16>, app: AppHandle, state: State<'_, Arc<ScanState>>) -> Result<ScanOutcome, String> {
    let (network, bits) = cidr_range(&cidr)?;
    let count = 1u64 << (32 - bits);
    if count > 4096 { return Err("A rede excede 4.096 endereços. Divida-a em faixas menores para evitar sobrecarga.".into()) }
    if state.running.swap(true, Ordering::SeqCst) { return Err("Já existe uma varredura em andamento.".into()) }
    state.cancel.store(false, Ordering::SeqCst);
    let shared = state.inner().clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let mut addresses = VecDeque::new();
        let end = network as u64 + count;
        for value in network as u64..end {
            if bits <= 30 && (value == network as u64 || value == end - 1) { continue }
            addresses.push_back(Ipv4Addr::from(value as u32));
        }
        let total = addresses.len();
        let queue = Arc::new(Mutex::new(addresses));
        let results = Arc::new(Mutex::new(Vec::<Host>::new()));
        let done = Arc::new(AtomicUsize::new(0));
        let ports = Arc::new(ports);
        std::thread::scope(|scope| {
            for _ in 0..total.min(48) {
                let queue = queue.clone();
                let results = results.clone();
                let done = done.clone();
                let ports = ports.clone();
                let app = app.clone();
                let shared = shared.clone();
                scope.spawn(move || loop {
                    if shared.cancel.load(Ordering::Relaxed) { break }
                    let next = queue.lock().expect("fila de IPs").pop_front();
                    let Some(ip) = next else { break };
                    let host = probe_host(ip, &ports);
                    if let Some(host) = &host {
                        results.lock().expect("resultados").push(host.clone());
                    }
                    let complete = done.fetch_add(1, Ordering::Relaxed) + 1;
                    let _ = app.emit("scan-progress", ScanProgress { done: complete, total, host });
                });
            }
        });
        let macs = neighbor_map();
        let mut hosts = results.lock().expect("resultados").clone();
        for host in &mut hosts { host.mac = macs.get(&host.ip).cloned(); }
        hosts.sort_by_key(|host| Ipv4Addr::from_str(&host.ip).map(u32::from).unwrap_or(0));
        ScanOutcome { hosts, cancelled: shared.cancel.load(Ordering::Relaxed) }
    }).await.map_err(|e| e.to_string());
    state.running.store(false, Ordering::SeqCst);
    result
}

#[tauri::command]
fn cancel_scan(state: State<'_, Arc<ScanState>>) {
    state.cancel.store(true, Ordering::SeqCst);
}

#[tauri::command]
async fn deep_scan_device(ip: String, mode: String, custom_ports: String, timeout_ms: u64, app: AppHandle, state: State<'_, Arc<DeepScanState>>) -> Result<DeepScanOutcome, String> {
    let address = Ipv4Addr::from_str(&ip).map_err(|_| "IP inválido")?;
    if !(100..=3000).contains(&timeout_ms) { return Err("O tempo de espera deve ficar entre 100 e 3.000 ms".into()) }
    let ports = deep_scan::port_list(&mode, &custom_ports)?;
    if state.running.swap(true, Ordering::SeqCst) { return Err("Já existe uma análise detalhada em andamento".into()) }
    state.cancel.store(false, Ordering::SeqCst);
    let shared = state.inner().clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let started = Instant::now();
        let count = AtomicUsize::new(0);
        let total = ports.len();
        let findings = deep_scan::scan(address, ports, timeout_ms, &shared.cancel, |done, total, finding| {
            count.store(done, Ordering::Relaxed);
            let _ = app.emit("deep-scan-progress", DeepScanProgress { ip: ip.clone(), done, total, finding });
        });
        DeepScanOutcome {
            ip, findings, cancelled: shared.cancel.load(Ordering::Relaxed),
            scanned: count.load(Ordering::Relaxed), total, elapsed_ms: started.elapsed().as_millis(),
        }
    }).await.map_err(|e| e.to_string());
    state.running.store(false, Ordering::SeqCst);
    result
}

#[tauri::command]
fn cancel_deep_scan(state: State<'_, Arc<DeepScanState>>) {
    state.cancel.store(true, Ordering::SeqCst);
}

#[tauri::command]
fn open_target(ip: String, action: String, username: Option<String>) -> Result<(), String> {
    Ipv4Addr::from_str(&ip).map_err(|_| "IP inválido")?;
    let mut process = match action.as_str() {
        "http" => { let mut c = Command::new("explorer.exe"); c.arg(format!("http://{ip}/")); c }
        "https" => { let mut c = Command::new("explorer.exe"); c.arg(format!("https://{ip}/")); c }
        "rdp" => { let mut c = Command::new("mstsc.exe"); c.arg(format!("/v:{ip}")); c }
        "ssh" => {
            let user = username.unwrap_or_default();
            if !user.is_empty() && !valid_username(&user) { return Err("Usuário SSH inválido".into()) }
            let target = if user.is_empty() { ip } else { format!("{user}@{ip}") };
            let mut c = Command::new("cmd.exe"); c.args(["/k", "ssh", &target]); c
        }
        _ => return Err("Ação desconhecida".into()),
    };
    process.spawn().map_err(|e| e.to_string())?;
    Ok(())
}

fn valid_username(user: &str) -> bool {
    !user.is_empty() && user.len() <= 64 && user.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

#[tauri::command]
fn wake_on_lan(mac: String) -> Result<(), String> {
    let bytes: Vec<u8> = mac.split([':', '-']).map(|s| u8::from_str_radix(s, 16)).collect::<Result<_, _>>().map_err(|_| "MAC inválido")?;
    if bytes.len() != 6 { return Err("MAC inválido".into()) }
    let mut packet = vec![0xff; 6];
    for _ in 0..16 { packet.extend_from_slice(&bytes); }
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket.set_broadcast(true).map_err(|e| e.to_string())?;
    socket.send_to(&packet, "255.255.255.255:9").map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn remote_command(ip: String, username: String, command: String) -> Result<String, String> {
    Ipv4Addr::from_str(&ip).map_err(|_| "IP inválido")?;
    if !valid_username(&username) { return Err("Usuário SSH inválido".into()) }
    if command.trim().is_empty() || command.len() > 2000 { return Err("Comando vazio ou muito longo".into()) }
    tauri::async_runtime::spawn_blocking(move || {
        let output = hidden_command("ssh")
            .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=8", &format!("{username}@{ip}"), &command])
            .output()
            .map_err(|e| format!("Cliente SSH indisponível: {e}"))?;
        let mut text = String::from_utf8_lossy(&output.stdout).to_string();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        text = text.chars().take(100_000).collect();
        if output.status.success() { Ok(text) } else { Err(text) }
    }).await.map_err(|e| e.to_string())?
}

fn csv_cell(value: &str) -> String {
    let guarded = if value.chars().next().is_some_and(|c| "=+-@".contains(c)) { format!("'{value}") } else { value.to_owned() };
    format!("\"{}\"", guarded.replace('"', "\"\""))
}

#[tauri::command]
fn export_csv(path: String, hosts: Vec<Host>) -> Result<(), String> {
    let mut file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    file.write_all("\u{feff}IP;Nome personalizado;Nome DNS;MAC;Resposta_ms;Portas\r\n".as_bytes()).map_err(|e| e.to_string())?;
    for host in hosts {
        let cells = [host.ip, host.display_name.unwrap_or_default(), host.hostname.unwrap_or_default(), host.mac.unwrap_or_default(), host.response_ms.map(|n| n.to_string()).unwrap_or_default(), host.ports.iter().map(|p| format!("{} ({})", p.port, p.service)).collect::<Vec<_>>().join(", ")];
        let row = cells.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(";") + "\r\n";
        file.write_all(row.as_bytes()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn fortigate_query(ip: String, token: String, endpoint: String) -> Result<Value, String> {
    Ipv4Addr::from_str(&ip).map_err(|_| "IP do FortiGate inválido")?;
    if token.trim().is_empty() { return Err("Informe o token da API".into()) }
    let path = match endpoint.as_str() {
        "resources" => "/api/v2/monitor/system/resource/usage?resource=cpu,memory,session",
        "sessions" => "/api/v2/monitor/firewall/session/select",
        "interfaces" => "/api/v2/cmdb/system/interface",
        _ => return Err("Consulta desconhecida".into()),
    };
    tauri::async_runtime::spawn_blocking(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .build().map_err(|e| e.to_string())?;
        let response = client.get(format!("https://{ip}{path}"))
            .bearer_auth(token)
            .send().map_err(|e| format!("Falha de conexão HTTPS com o FortiGate: {e}"))?;
        let status = response.status();
        if !status.is_success() { return Err(format!("FortiGate retornou HTTP {status}. Verifique o token e as permissões de leitura.")) }
        response.json::<Value>().map_err(|e| format!("Resposta inválida do FortiGate: {e}"))
    }).await.map_err(|e| e.to_string())?
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::new(ScanState::default()))
        .manage(Arc::new(MonitorState::default()))
        .manage(Arc::new(DeepScanState::default()))
        .invoke_handler(tauri::generate_handler![
            detect_subnets, scan_network, cancel_scan, start_device_monitor, stop_device_monitor,
            stop_all_device_monitors, deep_scan_device, cancel_deep_scan, open_target,
            wake_on_lan, remote_command, export_csv, fortigate_query,
            fortigate_ssh_fingerprint, fortigate_ssh_networks
        ])
        .run(tauri::generate_context!())
        .expect("erro ao iniciar Firaw Network");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_is_normalized_and_bounded() {
        assert_eq!(normalized_cidr("192.168.5.200/24").as_deref(), Some("192.168.5.0/24"));
        assert_eq!(normalized_cidr("10.0.0.1/33"), None);
        assert_eq!(normalized_cidr("invalid/24"), None);
    }

    #[test]
    fn csv_cells_cannot_start_formulas() {
        assert_eq!(csv_cell("=1+1"), "\"'=1+1\"");
        assert_eq!(csv_cell("host\"name"), "\"host\"\"name\"");
    }

    #[test]
    fn fortigate_routes_and_interfaces_are_discovered() {
        let routes = "S* 0.0.0.0/0 [10/0] via 1.2.3.4, wan1\nC 10.20.30.0/24 is directly connected, internal\nS 10.40.0.0/16 [10/0] via 10.20.30.1, port2";
        let interfaces = "config system interface\n edit \"vlan50\"\n set ip 192.168.50.1 255.255.255.0\n next\nend";
        let found = parse_fortigate_networks(routes, interfaces);
        assert_eq!(found.len(), 3);
        assert!(found.iter().any(|s| s.cidr == "10.20.30.0/24"));
        assert!(found.iter().any(|s| s.cidr == "10.40.0.0/16"));
        assert!(found.iter().any(|s| s.cidr == "192.168.50.0/24"));
    }

    #[test]
    fn ping_latency_uses_icmp_time_not_process_duration() {
        assert_eq!(parse_ping_latency("Resposta de 10.0.0.1: bytes=32 tempo=12ms TTL=64"), Some(12.0));
        assert_eq!(parse_ping_latency("Reply from 10.0.0.1: bytes=32 time<1ms TTL=128"), Some(0.5));
        assert_eq!(parse_ping_latency("Request timed out."), None);
    }


    #[cfg(windows)]
    #[test]
    fn loopback_ping_reports_latency() {
        let (online, latency) = ping_once(Ipv4Addr::LOCALHOST, 1000).expect("ping local");
        assert!(online);
        assert!(latency.is_some());
    }
}
