import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { save } from '@tauri-apps/plugin-dialog';
import FortiSshPanel, { type FoundSubnet } from './FortiSshPanel';
import MonitorPanel, { deviceLabel, type DeviceProbe } from './MonitorPanel';
import DeepScanPanel, { type DeepFinding, type DeepOutcome, type DeepProgress } from './DeepScanPanel';
import appLogo from '../assets/logo.svg';
import {
  Activity, ArrowDownToLine, ArrowUpRight, ChartNoAxesCombined, CircleHelp,
  Command, Download, Globe2, HardDrive, LockKeyhole, Monitor, Network,
  Play, Power, Radar, RefreshCw, Search, Server, Shield, Square, Terminal,
  Wifi, Zap,
} from 'lucide-react';

type Subnet = { cidr: string; label: string; source: 'interface' | 'route' | 'fortigate'; hostCount: number };
type PortInfo = { port: number; service: string };
type Host = { ip: string; hostname: string | null; mac: string | null; responseMs: number | null; ports: PortInfo[] };
type Progress = { done: number; total: number; host: Host | null };
type ScanOutcome = { hosts: Host[]; cancelled: boolean };
type InventoryItem = Host & { lastSeen: string; firstSeen: string; online: boolean; displayName?: string };
type Notice = { time: string; text: string; tone: 'info' | 'success' | 'warning' };
type Section = 'painel' | 'dispositivos' | 'monitoramento' | 'fortigate' | 'configuracoes';

const DEFAULT_PORTS = [21, 22, 23, 53, 80, 135, 139, 161, 389, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8443];
const STORAGE_KEY = 'firaw-network-inventory-v1';
const PORTS_KEY = 'firaw-network-ports-v1';
const NETWORKS_KEY = 'firaw-network-subnets-v1';

function readNetworks(): Subnet[] {
  try { return JSON.parse(localStorage.getItem(NETWORKS_KEY) || '[]') as Subnet[]; }
  catch { return []; }
}

function mergeNetworks(current: Subnet[], added: Subnet[]): Subnet[] {
  const byCidr = new Map(current.map(item => [item.cidr, item]));
  for (const item of added) byCidr.set(item.cidr, item);
  return [...byCidr.values()].sort((a, b) => ipOrder(a.cidr.split('/')[0]) - ipOrder(b.cidr.split('/')[0]));
}

function readInventory(): InventoryItem[] {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]') as InventoryItem[]; }
  catch { return []; }
}

function timestamp(): string { return new Date().toLocaleString('pt-BR'); }
function sizeOf(n?: number | null): string {
  if (typeof n !== 'number' || !Number.isFinite(n)) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function ipOrder(ip: string): number { return ip.split('.').reduce((v, part) => v * 256 + Number(part), 0); }

function responseError(e: unknown): string { return e instanceof Error ? e.message : String(e); }

function resultRows(value: unknown): Record<string, unknown>[] {
  if (!value || typeof value !== 'object') return [];
  const results = (value as Record<string, unknown>).results;
  if (Array.isArray(results)) return results.filter((item): item is Record<string, unknown> => !!item && typeof item === 'object');
  if (results && typeof results === 'object') {
    const nested = Object.values(results).find(Array.isArray);
    if (Array.isArray(nested)) return nested.filter((item): item is Record<string, unknown> => !!item && typeof item === 'object');
  }
  return [];
}

function firstNumber(row: Record<string, unknown>, keys: string[]): number | null {
  for (const key of keys) {
    const value = row[key];
    if (typeof value === 'number') return value;
    if (typeof value === 'string' && /^\d+$/.test(value)) return Number(value);
  }
  return null;
}

function fortiNetworks(value: unknown): Subnet[] {
  const found = new Map<string, Subnet>();
  for (const row of resultRows(value)) {
    const raw = row.ip;
    const parts = typeof raw === 'string' ? raw.trim().split(/[\s/]+/) : Array.isArray(raw) ? raw.map(String) : [];
    if (parts.length < 2) continue;
    const octets = parts[0].split('.').map(Number);
    if (octets.length !== 4 || octets.some(n => !Number.isInteger(n) || n < 0 || n > 255)) continue;
    let bits = Number(parts[1]);
    if (parts[1].includes('.')) {
      const maskParts = parts[1].split('.').map(Number);
      if (maskParts.length !== 4 || maskParts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) continue;
      const binary = maskParts.map(n => n.toString(2).padStart(8, '0')).join('');
      if (!/^1*0*$/.test(binary)) continue;
      bits = binary.indexOf('0') < 0 ? 32 : binary.indexOf('0');
    }
    if (!Number.isInteger(bits) || bits < 8 || bits > 30) continue;
    const mask = (0xffffffff << (32 - bits)) >>> 0;
    const address = ipOrder(parts[0]) >>> 0;
    const network = address & mask;
    const cidr = `${[(network >>> 24) & 255, (network >>> 16) & 255, (network >>> 8) & 255, network & 255].join('.')}/${bits}`;
    found.set(cidr, { cidr, label: `FortiGate · ${String(row.name || row.q_origin_key || 'interface')}`, source: 'fortigate', hostCount: 2 ** (32 - bits) });
  }
  return [...found.values()].sort((a, b) => ipOrder(a.cidr.split('/')[0]) - ipOrder(b.cidr.split('/')[0]));
}

function App() {
  const [section, setSection] = useState<Section>('painel');
  const [subnets, setSubnets] = useState<Subnet[]>(readNetworks);
  const [cidr, setCidr] = useState('');
  const [customCidr, setCustomCidr] = useState('');
  const [hosts, setHosts] = useState<Host[]>([]);
  const [inventory, setInventory] = useState<InventoryItem[]>(readInventory);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [nameDraft, setNameDraft] = useState('');
  const [monitored, setMonitored] = useState<Record<string, number>>({});
  const [monitorSamples, setMonitorSamples] = useState<Record<string, DeviceProbe[]>>({});
  const lastProbe = useRef<Record<string, DeviceProbe>>({});
  const inventoryRef = useRef(inventory);
  inventoryRef.current = inventory;
  const [scanning, setScanning] = useState(false);
  const scanningRef = useRef(false);
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [lastScan, setLastScan] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [showOffline, setShowOffline] = useState(true);
  const [autoMonitor, setAutoMonitor] = useState(false);
  const [intervalSec, setIntervalSec] = useState(60);
  const [portText, setPortText] = useState(() => localStorage.getItem(PORTS_KEY) || DEFAULT_PORTS.join(', '));
  const [notices, setNotices] = useState<Notice[]>([]);
  const [error, setError] = useState('');
  const [deepScanning, setDeepScanning] = useState(false);
  const [deepScanIp, setDeepScanIp] = useState<string | null>(null);
  const [deepProgress, setDeepProgress] = useState<DeepProgress | null>(null);
  const [deepFindings, setDeepFindings] = useState<Record<string, DeepFinding[]>>({});
  const [deepOutcomes, setDeepOutcomes] = useState<Record<string, DeepOutcome>>({});
  const [sshUser, setSshUser] = useState('');
  const [remoteInput, setRemoteInput] = useState('');
  const [remoteOutput, setRemoteOutput] = useState('');
  const [remoteBusy, setRemoteBusy] = useState(false);
  const [fortiIp, setFortiIp] = useState('');
  const [fortiToken, setFortiToken] = useState('');
  const [fortiResources, setFortiResources] = useState<unknown>(null);
  const [fortiSessions, setFortiSessions] = useState<unknown>(null);
  const [fortiBusy, setFortiBusy] = useState(false);

  const addNotice = useCallback((text: string, tone: Notice['tone'] = 'info') => {
    setNotices(current => [{ time: timestamp(), text, tone }, ...current].slice(0, 30));
  }, []);

  useEffect(() => {
    invoke<Subnet[]>('detect_subnets').then(found => {
      setSubnets(current => mergeNetworks(current, found));
      const first = found.find(s => s.source === 'interface' && s.hostCount <= 4096) || found.find(s => s.hostCount <= 4096);
      if (first) setCidr(first.cidr);
    }).catch(e => setError(`Não foi possível detectar as redes: ${responseError(e)}`));
    const unlisten = listen<Progress>('scan-progress', event => {
      const { done, total, host } = event.payload;
      setProgress({ done, total });
      if (host) setHosts(current => current.some(item => item.ip === host.ip) ? current : [...current, host].sort((a, b) => ipOrder(a.ip) - ipOrder(b.ip)));
    });
    return () => { unlisten.then(fn => fn()); };
  }, []);

  useEffect(() => { localStorage.setItem(NETWORKS_KEY, JSON.stringify(subnets)); }, [subnets]);

  useEffect(() => {
    const unlisten = listen<DeepProgress>('deep-scan-progress', event => {
      const update = event.payload;
      setDeepProgress(update);
      if (update.finding) setDeepFindings(current => ({ ...current, [update.ip]: [...(current[update.ip] || []), update.finding!] }));
    });
    return () => { unlisten.then(fn => fn()); };
  }, []);

  useEffect(() => { setNameDraft(inventory.find(item => item.ip === selectedIp)?.displayName || ''); }, [selectedIp]);

  useEffect(() => {
    const unlisten = listen<DeviceProbe>('device-probe', event => {
      const sample = event.payload;
      const previous = lastProbe.current[sample.ip];
      if (previous && previous.online !== sample.online) {
        const label = inventoryRef.current.find(item => item.ip === sample.ip);
        addNotice(`${label ? deviceLabel(label) : sample.ip} ${sample.online ? 'voltou a responder' : 'parou de responder'}`, sample.online ? 'success' : 'warning');
      }
      lastProbe.current[sample.ip] = sample;
      setMonitorSamples(current => ({ ...current, [sample.ip]: [...(current[sample.ip] || []), sample].slice(-120) }));
    });
    return () => { unlisten.then(fn => fn()); };
  }, [addNotice]);

  async function startMonitor(ip: string, intervalSec: number) {
    const device = inventory.find(item => item.ip === ip);
    if (!device) { setError('Dispositivo não encontrado no inventário. Faça uma varredura primeiro.'); return; }
    try {
      if (!monitored[ip]) {
        delete lastProbe.current[ip];
        setMonitorSamples(current => ({ ...current, [ip]: [] }));
      }
      await invoke('start_device_monitor', { ip, intervalSec, ports: device.ports.map(port => port.port) });
      setMonitored(current => ({ ...current, [ip]: intervalSec }));
      setError('');
    } catch (e) { setError(responseError(e)); }
  }

  async function stopMonitor(ip: string) {
    try { await invoke('stop_device_monitor', { ip }); setMonitored(current => { const next = { ...current }; delete next[ip]; return next; }); }
    catch (e) { setError(responseError(e)); }
  }

  async function stopAllMonitors() {
    try { await invoke('stop_all_device_monitors'); setMonitored({}); }
    catch (e) { setError(responseError(e)); }
  }

  function saveDisplayName() {
    if (!selectedIp) return;
    const name = nameDraft.trim().slice(0, 60);
    const next = inventory.map(item => item.ip === selectedIp ? { ...item, displayName: name || undefined } : item);
    setInventory(next);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    setNameDraft(name);
    addNotice(name ? `Nome salvo: ${name}` : `Nome personalizado removido de ${selectedIp}`, 'success');
  }

  const runScan = useCallback(async () => {
    if (scanningRef.current) return;
    const target = customCidr.trim() || cidr;
    if (!target) { setError('Escolha uma sub-rede ou informe um CIDR.'); return; }
    const ports = [...new Set(portText.split(/[\s,;]+/).map(Number).filter(n => Number.isInteger(n) && n > 0 && n <= 65535))].slice(0, 100);
    if (!ports.length) { setError('Informe ao menos uma porta válida.'); return; }
    scanningRef.current = true;
    setScanning(true); setProgress({ done: 0, total: 0 }); setHosts([]); setError('');
    try {
      const outcome = await invoke<ScanOutcome>('scan_network', { cidr: target, ports });
      const found = outcome.hosts;
      setHosts(found);
      if (outcome.cancelled) { addNotice('Varredura interrompida. O inventário anterior foi preservado.', 'warning'); return; }
      const currentTime = new Date().toISOString();
      const previous = readInventory();
      const previousMap = new Map(previous.map(item => [item.ip, item]));
      const foundMap = new Map(found.map(item => [item.ip, item]));
      const next: InventoryItem[] = previous.map(item => {
        const match = foundMap.get(item.ip);
        if (match) return { ...item, ...match, online: true, lastSeen: currentTime };
        const inTarget = belongsToCidr(item.ip, target);
        if (inTarget && item.online) addNotice(`${item.hostname || item.ip} ficou indisponível`, 'warning');
        return inTarget ? { ...item, online: false } : item;
      });
      for (const host of found) {
        const before = previousMap.get(host.ip);
        if (!before) {
          next.push({ ...host, online: true, firstSeen: currentTime, lastSeen: currentTime });
          addNotice(`Novo dispositivo: ${host.hostname || host.ip}`, 'success');
        } else if (!before.online) addNotice(`${host.hostname || host.ip} voltou a responder`, 'success');
      }
      next.sort((a, b) => ipOrder(a.ip) - ipOrder(b.ip));
      setInventory(next);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      setLastScan(timestamp());
      addNotice(`Varredura concluída: ${found.length} dispositivos encontrados`, 'info');
      if (found.length && !selectedIp) setSelectedIp(found[0].ip);
    } catch (e) { setError(responseError(e)); }
    finally { scanningRef.current = false; setScanning(false); }
  }, [cidr, customCidr, portText, addNotice, selectedIp]);

  useEffect(() => {
    if (!autoMonitor) return;
    const timer = window.setInterval(runScan, intervalSec * 1000);
    return () => window.clearInterval(timer);
  }, [autoMonitor, intervalSec, runScan]);

  useEffect(() => {
    if (!autoMonitor || !fortiIp || !fortiToken) return;
    const timer = window.setInterval(() => {
      invoke<unknown>('fortigate_query', { ip: fortiIp, token: fortiToken, endpoint: 'sessions' })
        .then(setFortiSessions)
        .catch(e => setError(`Monitoramento do FortiGate: ${responseError(e)}`));
    }, Math.max(intervalSec, 60) * 1000);
    return () => window.clearInterval(timer);
  }, [autoMonitor, fortiIp, fortiToken, intervalSec]);

  const liveInventory = useMemo(() => inventory.map(item => {
    if (!monitored[item.ip]) return item;
    const history = monitorSamples[item.ip];
    const sample = history?.[history.length - 1];
    return sample ? { ...item, online: sample.online, responseMs: sample.latencyMs == null ? null : Math.ceil(sample.latencyMs) } : item;
  }), [inventory, monitorSamples, monitored]);

  const displayed = useMemo(() => {
    const q = search.toLocaleLowerCase();
    return liveInventory.filter(item => {
      if (!showOffline && !item.online) return false;
      if (q && !`${item.ip} ${item.displayName || ''} ${item.hostname || ''} ${item.mac || ''} ${item.ports.map(p => p.service).join(' ')}`.toLocaleLowerCase().includes(q)) return false;
      return true;
    }).sort((a, b) => Number(b.online) - Number(a.online) || ipOrder(a.ip) - ipOrder(b.ip));
  }, [liveInventory, search, showOffline]);
  const selected = liveInventory.find(item => item.ip === selectedIp) || null;
  const onlineCount = liveInventory.filter(item => item.online).length;
  const offlineCount = liveInventory.length - onlineCount;
  const openPorts = liveInventory.filter(item => item.online).reduce((n, item) => n + item.ports.length, 0);
  const sessions = resultRows(fortiSessions);
  const selectedSessions = selectedIp ? sessions.filter(row => JSON.stringify(row).includes(selectedIp)) : [];
  const sessionSources = useMemo(() => {
    const totals = new Map<string, { count: number; sent: number; received: number; hasBytes: boolean }>();
    for (const row of sessions) {
      const source = String(row.srcip ?? row.src_ip ?? row.src ?? row.source ?? '');
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(source)) continue;
      const item = totals.get(source) || { count: 0, sent: 0, received: 0, hasBytes: false };
      item.count++;
      const sent = firstNumber(row, ['sentbyte', 'sent_bytes', 'tx_bytes', 'sent_bytes_total']);
      const received = firstNumber(row, ['rcvdbyte', 'rcvd_bytes', 'received_bytes', 'rx_bytes']);
      if (sent != null || received != null) item.hasBytes = true;
      item.sent += sent || 0;
      item.received += received || 0;
      totals.set(source, item);
    }
    return [...totals.entries()].sort((a, b) => (b[1].sent + b[1].received) - (a[1].sent + a[1].received)).slice(0, 20);
  }, [fortiSessions]);

  async function cancel() { await invoke('cancel_scan'); addNotice('Cancelamento solicitado'); }
  async function detailScan(mode: string, customPorts: string, timeoutMs: number) {
    if (!selected) return;
    const ip = selected.ip;
    setDeepScanning(true);
    setDeepScanIp(ip);
    setDeepProgress(null);
    setDeepFindings(current => ({ ...current, [ip]: [] }));
    setDeepOutcomes(current => { const next = { ...current }; delete next[ip]; return next; });
    setError('');
    try {
      const outcome = await invoke<DeepOutcome>('deep_scan_device', { ip, mode, customPorts, timeoutMs });
      setDeepOutcomes(current => ({ ...current, [ip]: outcome }));
      setDeepFindings(current => ({ ...current, [ip]: outcome.findings }));
      setDeepProgress({ ip, done: outcome.scanned, total: outcome.total, finding: null });
      addNotice(`${outcome.cancelled ? 'Análise interrompida' : 'Análise concluída'} em ${ip}: ${outcome.findings.length} porta(s) aberta(s)`, outcome.cancelled ? 'warning' : 'success');
    } catch (e) { setError(responseError(e)); }
    finally { setDeepScanning(false); setDeepScanIp(null); }
  }
  async function cancelDetailScan() {
    try { await invoke('cancel_deep_scan'); }
    catch (e) { setError(responseError(e)); }
  }
  async function open(action: string) {
    if (!selected) return;
    try { await invoke('open_target', { ip: selected.ip, action, username: sshUser || null }); }
    catch (e) { setError(responseError(e)); }
  }
  async function wol() {
    if (!selected?.mac) return;
    try { await invoke('wake_on_lan', { mac: selected.mac }); addNotice(`Pacote Wake-on-LAN enviado para ${selected.ip}`, 'success'); }
    catch (e) { setError(responseError(e)); }
  }
  async function runRemote(command = remoteInput) {
    if (!selected) return;
    setRemoteBusy(true); setRemoteOutput('Executando via SSH...');
    try { setRemoteOutput(await invoke<string>('remote_command', { ip: selected.ip, username: sshUser, command })); }
    catch (e) { setRemoteOutput(responseError(e)); }
    finally { setRemoteBusy(false); }
  }
  async function exportInventory() {
    const path = await save({ defaultPath: 'firaw-network-inventario.csv', filters: [{ name: 'CSV', extensions: ['csv'] }] });
    if (!path) return;
    try { await invoke('export_csv', { path, hosts: inventory }); addNotice('Inventário exportado com sucesso', 'success'); }
    catch (e) { setError(responseError(e)); }
  }
  async function queryForti(endpoint: 'resources' | 'sessions' | 'interfaces') {
    setFortiBusy(true); setError('');
    try {
      const data = await invoke<unknown>('fortigate_query', { ip: fortiIp, token: fortiToken, endpoint });
      if (endpoint === 'resources') setFortiResources(data);
      else if (endpoint === 'sessions') setFortiSessions(data);
      else {
        const networks = fortiNetworks(data);
        setSubnets(current => mergeNetworks(current, networks));
        addNotice(`${networks.length} sub-redes encontradas nas interfaces do FortiGate`, 'success');
        return;
      }
      addNotice(`Consulta ao FortiGate concluída: ${endpoint === 'resources' ? 'recursos' : 'sessões'}`, 'success');
    } catch (e) { setError(responseError(e)); }
    finally { setFortiBusy(false); }
  }

  const navigation: { id: Section; label: string; icon: typeof Activity }[] = [
    { id: 'painel', label: 'Visão geral', icon: ChartNoAxesCombined },
    { id: 'dispositivos', label: 'Dispositivos', icon: Monitor },
    { id: 'monitoramento', label: 'Monitoramento', icon: Activity },
    { id: 'fortigate', label: 'FortiGate', icon: Shield },
    { id: 'configuracoes', label: 'Configurações', icon: Command },
  ];

  return <div className="app">
    <aside className="sidebar">
      <div className="brand"><img width="38" height="38" src={appLogo} alt=""/><div><strong>FIRAW<span>NETWORK</span></strong><small>NETWORK INTELLIGENCE</small></div></div>
      <div className="sidebar-label">WORKSPACE</div>
      <nav>{navigation.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${section === id ? 'active' : ''}`} onClick={() => setSection(id)}><Icon size={18}/><span>{label}</span>{id === 'dispositivos' && <em>{inventory.length}</em>}</button>)}</nav>
      <div className="sidebar-label top-gap">SUB-REDES DETECTADAS</div>
      <div className="network-list">{subnets.length ? subnets.map(net => <button key={net.cidr} className={`network-item ${cidr === net.cidr && !customCidr ? 'selected' : ''}`} onClick={() => { setCidr(net.cidr); setCustomCidr(''); setSection('dispositivos'); }}><span className="network-dot"/><span><strong>{net.cidr}</strong><small>{net.label} · {net.source === 'interface' ? 'local' : net.source === 'route' ? 'rota' : 'firewall'}</small></span></button>) : <p className="sidebar-empty">Nenhuma rede detectada</p>}</div>
      <div className="sidebar-foot"><span className="status-dot"/><div><strong>Scanner pronto</strong><small>{lastScan ? `Última varredura ${lastScan}` : 'Aguardando primeira varredura'}</small></div></div>
    </aside>

    <main className="main">
      <header className="topbar"><div className="crumb"><span>FIRAWYNIX</span><b>/</b>{navigation.find(n => n.id === section)?.label}</div><div className="top-actions"><span className="pill"><span className="live-dot"/> Monitor {Object.keys(monitored).length ? `${Object.keys(monitored).length} dispositivo(s)` : autoMonitor ? 'de rede ativo' : 'pausado'}</span><button className="icon-button" title="Atualizar redes" onClick={() => invoke<Subnet[]>('detect_subnets').then(found => setSubnets(current => mergeNetworks(current, found))).catch(e => setError(responseError(e)))}><RefreshCw size={17}/></button></div></header>
      <div className="content">
        {error && <div className="error-banner"><CircleHelp size={17}/><span>{error}</span><button onClick={() => setError('')}>×</button></div>}

        {section === 'painel' && <>
          <div className="page-heading"><div><span className="eyebrow">CENTRO DE OPERAÇÕES</span><h1>Visão geral da rede</h1><p>Descoberta, estado dos dispositivos e mudanças em um só lugar.</p></div><button className="primary-button" onClick={runScan} disabled={scanning}><Radar size={18}/>{scanning ? 'Varrendo...' : 'Nova varredura'}</button></div>
          <div className="stat-grid"><Stat icon={Monitor} title="Dispositivos ativos" value={onlineCount} sub="respondendo na última varredura" tone="cyan"/><Stat icon={Power} title="Indisponíveis" value={offlineCount} sub="vistos anteriormente" tone="rose"/><Stat icon={Network} title="Sub-redes" value={subnets.length} sub="interfaces e rotas conhecidas" tone="violet"/><Stat icon={Zap} title="Portas abertas" value={openPorts} sub="serviços detectados" tone="green"/></div>
          <div className="dashboard-grid"><section className="panel"><div className="panel-heading"><div><h2>Varredura de rede</h2><p>Escolha uma sub-rede detectada ou informe uma faixa CIDR.</p></div><Radar size={19}/></div><div className="scan-controls"><label>Sub-rede<select value={cidr} onChange={e => { setCidr(e.target.value); setCustomCidr(''); }}>{subnets.map(net => <option key={net.cidr} value={net.cidr}>{net.cidr} · {net.label}</option>)}</select></label><label>Faixa manual<input placeholder="Ex.: 192.168.10.0/24" value={customCidr} onChange={e => setCustomCidr(e.target.value)}/></label></div><div className="scan-bottom"><span>{scanning ? `${progress.done} / ${progress.total} endereços` : lastScan ? `Última execução: ${lastScan}` : 'Nenhuma varredura realizada'}</span>{scanning ? <button className="outline-button" onClick={cancel}><Square size={15}/> Parar</button> : <button className="outline-button" onClick={runScan}><Play size={15}/> Iniciar</button>}</div><div className="progress-track"><div style={{ width: progress.total ? `${progress.done / progress.total * 100}%` : '0%' }}/></div></section>
          <section className="panel"><div className="panel-heading"><div><h2>Atividade recente</h2><p>Entradas, saídas e varreduras concluídas.</p></div><Activity size={19}/></div><div className="activity-list">{notices.length ? notices.slice(0, 5).map((notice, i) => <div className="activity-item" key={`${notice.time}-${i}`}><span className={`activity-bullet ${notice.tone}`}/><div><strong>{notice.text}</strong><small>{notice.time}</small></div></div>) : <div className="empty-small">As mudanças aparecerão aqui após a primeira varredura.</div>}</div></section></div>
          <section className="panel"><div className="panel-heading"><div><h2>Dispositivos recentes</h2><p>Abra um equipamento para ver serviços e ações disponíveis.</p></div><button className="text-button" onClick={() => setSection('dispositivos')}>Ver todos <ArrowUpRight size={15}/></button></div><DeviceTable items={displayed.slice(0, 7)} selectedIp={selectedIp} onSelect={ip => { setSelectedIp(ip); setSection('dispositivos'); }}/></section>
        </>}

        {section === 'dispositivos' && <>
          <div className="page-heading"><div><span className="eyebrow">INVENTÁRIO E DIAGNÓSTICO</span><h1>Dispositivos</h1><p>Hosts ativos, portas, serviços e acesso remoto.</p></div><div className="heading-actions"><button className="outline-button" onClick={exportInventory}><Download size={17}/> Exportar CSV</button><button className="primary-button" onClick={runScan} disabled={scanning}><Radar size={18}/>{scanning ? 'Varrendo...' : 'Varrer rede'}</button></div></div>
          <div className="device-layout"><section className="panel device-list-panel"><div className="device-toolbar"><div className="searchbox"><Search size={17}/><input placeholder="Buscar IP, nome, MAC ou serviço" value={search} onChange={e => setSearch(e.target.value)}/></div><label className="switch-line"><input type="checkbox" checked={showOffline} onChange={e => setShowOffline(e.target.checked)}/> Offline</label></div><DeviceTable items={displayed} selectedIp={selectedIp} onSelect={setSelectedIp}/></section>
          <section className="panel detail-panel">{selected ? <><div className="detail-head"><div className="device-avatar"><Server size={25}/></div><div><span className={`state-chip ${selected.online ? 'online' : 'offline'}`}>{selected.online ? 'ONLINE' : 'OFFLINE'}</span><h2>{deviceLabel(selected)}</h2><p>{selected.ip}</p></div></div><div className="device-rename"><label htmlFor="device-name">Nome personalizado</label><div><input id="device-name" value={nameDraft} maxLength={60} placeholder="Ex.: Servidor principal" onChange={e => setNameDraft(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') saveDisplayName(); }}/><button className="outline-button" onClick={saveDisplayName}>Salvar nome</button></div><small>Fica salvo neste computador e aparece no inventário.</small></div><div className="detail-meta"><div><span>ENDEREÇO MAC</span><strong>{selected.mac || 'Não identificado'}</strong></div><div><span>SONDAGEM</span><strong>{selected.responseMs == null ? '—' : `${selected.responseMs} ms`}</strong></div><div><span>VISTO POR ÚLTIMO</span><strong>{new Date(selected.lastSeen).toLocaleString('pt-BR')}</strong></div></div>
          <div className="detail-section device-monitor-shortcut"><div className="section-heading"><h3>Monitor individual</h3><span>{monitored[selected.ip] ? 'Rodando' : 'Pausado'}</span></div><p className="muted-copy">Acompanhe latência, falhas e mudanças de disponibilidade enquanto o app estiver aberto.</p><div className="monitor-shortcut-actions"><button className="primary-button" onClick={() => { if (!monitored[selected.ip]) void startMonitor(selected.ip, 5); setSection('monitoramento'); }}><Activity size={15}/>{monitored[selected.ip] ? 'Ver monitor' : 'Deixar rodando'}</button>{monitored[selected.ip] && <button className="outline-button" onClick={() => void stopMonitor(selected.ip)}><Square size={14}/> Parar</button>}</div></div><div className="detail-section"><div className="section-heading"><h3>Portas e serviços</h3><span>{selected.ports.length}</span></div><div className="port-list">{selected.ports.length ? selected.ports.map(port => <div className="port-item" key={port.port}><span className="port-indicator"/><strong>{port.port}</strong><span>{port.service}</span><small>TCP</small></div>) : <div className="empty-small">Nenhuma das portas configuradas respondeu.</div>}</div></div><DeepScanPanel key={selected.ip} ip={selected.ip} scanning={deepScanning} scanningIp={deepScanIp} progress={deepProgress} findings={deepFindings[selected.ip] || []} outcome={deepOutcomes[selected.ip] || null} onStart={detailScan} onCancel={cancelDetailScan}/>
          <div className="detail-section"><div className="section-heading"><h3>Acesso e controle</h3></div><div className="action-grid"><button onClick={() => open('http')}><Globe2 size={17}/> HTTP</button><button onClick={() => open('https')}><LockKeyhole size={17}/> HTTPS</button><button onClick={() => open('rdp')}><Monitor size={17}/> RDP</button><button onClick={() => open('ssh')}><Terminal size={17}/> SSH</button><button onClick={wol} disabled={!selected.mac}><Power size={17}/> Wake-on-LAN</button></div></div>
          <div className="detail-section"><div className="section-heading"><h3>Processos e comandos</h3></div><p className="muted-copy">Acesso via SSH com chave ou autenticação já configurada no sistema. Para Windows, o OpenSSH Server precisa estar ativo.</p><input className="full-input" placeholder="Usuário SSH" value={sshUser} onChange={e => setSshUser(e.target.value)}/><div className="quick-actions"><button onClick={() => runRemote('ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -n 25')} disabled={!sshUser || remoteBusy}>Processos Linux</button><button onClick={() => runRemote('powershell -NoProfile -Command "Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 Id,ProcessName,CPU,WorkingSet | Format-Table -AutoSize"')} disabled={!sshUser || remoteBusy}>Processos Windows</button><button onClick={() => runRemote('uptime; free -h; df -h')} disabled={!sshUser || remoteBusy}>Recursos Linux</button><button onClick={() => runRemote('powershell -NoProfile -Command "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory,LastBootUpTime; Get-PSDrive C"')} disabled={!sshUser || remoteBusy}>Recursos Windows</button></div><div className="command-row"><input placeholder="Comando remoto" value={remoteInput} onChange={e => setRemoteInput(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') runRemote(); }}/><button onClick={() => runRemote()} disabled={!sshUser || !remoteInput.trim() || remoteBusy}><Play size={16}/></button></div>{remoteOutput && <pre className="output">{remoteOutput}</pre>}</div>
          {selectedSessions.length > 0 && <div className="detail-section"><div className="section-heading"><h3>Sessões no FortiGate</h3><span>{selectedSessions.length}</span></div><pre className="output">{JSON.stringify(selectedSessions.slice(0, 10), null, 2)}</pre></div>}
          </> : <div className="detail-empty"><Monitor size={38}/><h2>Selecione um dispositivo</h2><p>Os detalhes, serviços e controles aparecerão aqui.</p></div>}</section></div>
        </>}

        {section === 'monitoramento' && <MonitorPanel devices={inventory} active={monitored} samples={monitorSamples} onStart={startMonitor} onStop={stopMonitor} onStopAll={stopAllMonitors} onOpenDevice={ip => { setSelectedIp(ip); setSection('dispositivos'); }}/>}

        {section === 'fortigate' && <><div className="page-heading"><div><span className="eyebrow">INTEGRAÇÃO DE REDE</span><h1>FortiGate</h1><p>Consulte recursos e sessões diretamente pela API de leitura do firewall.</p></div><span className="forti-badge"><Shield size={16}/> FortiOS REST API</span></div><section className="panel forti-config"><div className="panel-heading"><div><h2>Conexão</h2><p>O token permanece somente nesta sessão do aplicativo.</p></div><LockKeyhole size={19}/></div><div className="forti-form"><label>IP de gerenciamento<input placeholder="Ex.: 192.168.1.1" value={fortiIp} onChange={e => setFortiIp(e.target.value)}/></label><label>Token da API<input type="password" placeholder="Token de administrador somente leitura" value={fortiToken} onChange={e => setFortiToken(e.target.value)} autoComplete="off"/></label></div><div className="forti-actions"><button className="primary-button" disabled={fortiBusy || !fortiIp || !fortiToken} onClick={() => queryForti('resources')}><Activity size={16}/> Consultar recursos</button><button className="outline-button" disabled={fortiBusy || !fortiIp || !fortiToken} onClick={() => queryForti('sessions')}><Network size={16}/> Consultar sessões</button><button className="outline-button" disabled={fortiBusy || !fortiIp || !fortiToken} onClick={() => queryForti('interfaces')}><Network size={16}/> Encontrar sub-redes</button></div><p className="muted-copy">Use HTTPS com certificado confiável, usuário REST API com permissão de leitura e Trusted Hosts configurado no FortiGate.</p></section><FortiSshPanel key={fortiIp} ip={fortiIp} onNetworks={(networks: FoundSubnet[]) => setSubnets(current => mergeNetworks(current, networks))} onNotice={(message) => addNotice(message, 'success')} onError={setError}/><div className="forti-grid"><section className="panel"><div className="panel-heading"><div><h2>Recursos do firewall</h2><p>CPU, memória e sessões retornados pelo equipamento.</p></div><Activity size={19}/></div>{fortiResources ? <pre className="output forti-output">{JSON.stringify((fortiResources as Record<string, unknown>).results ?? fortiResources, null, 2)}</pre> : <div className="empty-small">Conecte o FortiGate para carregar indicadores.</div>}</section><section className="panel"><div className="panel-heading"><div><h2>Sessões observadas</h2><p>Fluxos de rede que atravessam o FortiGate.</p></div><ArrowDownToLine size={19}/></div>{fortiSessions ? <><div className="forti-count">{sessions.length}<small>registros retornados</small></div><div className="session-list">{sessions.slice(0, 15).map((row, i) => <div className="session-row" key={i}><span>{String(row.srcip ?? row.src ?? row.source ?? 'Origem')}</span><ArrowUpRight size={14}/><span>{String(row.dstip ?? row.dst ?? row.destination ?? 'Destino')}</span><small>{sizeOf(firstNumber(row, ['sentbyte', 'sent_bytes', 'tx_bytes']))} ↑</small></div>)}</div>{!sessions.length && <pre className="output">{JSON.stringify(fortiSessions, null, 2)}</pre>}</> : <div className="empty-small">Consulte as sessões para ver o tráfego conhecido pelo firewall.</div>}</section></div>{sessionSources.length > 0 && <section className="panel"><div className="panel-heading"><div><h2>Tráfego por IP de origem</h2><p>Bytes acumulados nas sessões retornadas pela API; não representam velocidade em tempo real.</p></div><ArrowDownToLine size={19}/></div><div className="source-traffic"><div className="source-traffic-head"><span>IP</span><span>SESSÕES</span><span>ENVIADO</span><span>RECEBIDO</span></div>{sessionSources.map(([ip, item]) => <div className="source-traffic-row" key={ip}><strong>{ip}</strong><span>{item.count}</span><span>{item.hasBytes ? sizeOf(item.sent) : '—'}</span><span>{item.hasBytes ? sizeOf(item.received) : '—'}</span></div>)}</div></section>}</>}

        {section === 'configuracoes' && <><div className="page-heading"><div><span className="eyebrow">AJUSTES</span><h1>Configurações</h1><p>Controle a frequência e a profundidade da descoberta.</p></div></div><section className="panel settings-panel"><div className="setting-row"><div><h3>Monitoramento periódico</h3><p>Repete a varredura da faixa selecionada e registra entradas e saídas.</p></div><label className="toggle"><input type="checkbox" checked={autoMonitor} onChange={e => setAutoMonitor(e.target.checked)}/><span/></label></div><div className="setting-row"><div><h3>Intervalo entre varreduras</h3><p>Intervalos curtos aumentam o tráfego na rede.</p></div><select value={intervalSec} onChange={e => setIntervalSec(Number(e.target.value))}><option value={30}>30 segundos</option><option value={60}>1 minuto</option><option value={300}>5 minutos</option><option value={900}>15 minutos</option></select></div><div className="setting-row vertical"><div><h3>Portas TCP consultadas</h3><p>Até 100 portas separadas por vírgulas para a descoberta da rede. No dispositivo, a análise detalhada permite escolher portas comuns, 1 a 1024, 1 a 65535 ou uma faixa personalizada.</p></div><textarea rows={3} value={portText} onChange={e => { setPortText(e.target.value); localStorage.setItem(PORTS_KEY, e.target.value); }}/></div><div className="setting-row"><div><h3>Dados do inventário</h3><p>Histórico local de dispositivos encontrados e última presença.</p></div><button className="outline-button" onClick={exportInventory}><Download size={16}/> Exportar</button></div></section><section className="panel explain-panel"><h2>Fontes de informação</h2><div className="source-grid"><div><Wifi size={20}/><strong>Scanner local</strong><p>IP, resposta, portas, nome DNS e MAC quando visível na rede local.</p></div><div><Shield size={20}/><strong>FortiGate</strong><p>Sessões e indicadores disponibilizados pela API configurada no equipamento.</p></div><div><HardDrive size={20}/><strong>Acesso ao host</strong><p>Processos e comandos remotos por SSH. Uso por processo exige coleta no próprio dispositivo.</p></div></div></section></>}
      </div>
    </main>
  </div>;
}

function belongsToCidr(ip: string, cidr: string): boolean {
  const match = /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(cidr);
  if (!match || Number(match[2]) > 32) return false;
  const mask = Number(match[2]) === 0 ? 0 : (0xffffffff << (32 - Number(match[2]))) >>> 0;
  return ((ipOrder(ip) >>> 0) & mask) === ((ipOrder(match[1]) >>> 0) & mask);
}

function Stat({ icon: Icon, title, value, sub, tone }: { icon: typeof Activity; title: string; value: number; sub: string; tone: string }) {
  return <div className={`stat-card ${tone}`}><div className="stat-icon"><Icon size={20}/></div><div className="stat-copy"><span>{title}</span><strong>{value}</strong><small>{sub}</small></div></div>;
}

function DeviceTable({ items, selectedIp, onSelect }: { items: InventoryItem[]; selectedIp: string | null; onSelect: (ip: string) => void }) {
  return <div className="table-wrap"><div className="table-head"><span>DISPOSITIVO</span><span>IP</span><span>PORTAS</span><span>STATUS</span></div>{items.length ? items.map(item => <button className={`table-row ${selectedIp === item.ip ? 'chosen' : ''}`} key={item.ip} onClick={() => onSelect(item.ip)}><span className="table-name"><span className="host-icon"><Monitor size={16}/></span><span><strong>{item.displayName || item.hostname || 'Dispositivo sem nome'}</strong><small>{item.mac || 'MAC não identificado'}</small></span></span><span className="ip-cell">{item.ip}</span><span>{item.ports.length ? item.ports.slice(0, 3).map(p => p.port).join(', ') : '—'}</span><span><em className={`table-state ${item.online ? 'online' : 'offline'}`}>{item.online ? 'Online' : 'Offline'}</em></span></button>) : <div className="table-empty"><Radar size={28}/><strong>Nenhum dispositivo nesta lista</strong><small>Inicie uma varredura para montar o inventário.</small></div>}</div>;
}

export default App;
