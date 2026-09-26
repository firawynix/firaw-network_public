import { useState } from 'react';
import { Activity, Monitor, Play, Square } from 'lucide-react';

export type DeviceProbe = {
  ip: string;
  checkedAt: number;
  online: boolean;
  latencyMs: number | null;
  method: 'ICMP' | 'TCP' | null;
  error: string | null;
};

export type MonitorDevice = {
  ip: string;
  displayName?: string;
  hostname: string | null;
  ports: { port: number; service: string }[];
};

type Props = {
  devices: MonitorDevice[];
  active: Record<string, number>;
  samples: Record<string, DeviceProbe[]>;
  onStart: (ip: string, intervalSec: number) => Promise<void>;
  onStop: (ip: string) => Promise<void>;
  onStopAll: () => Promise<void>;
  onOpenDevice: (ip: string) => void;
};

export function deviceLabel(device: MonitorDevice): string {
  return device.displayName || device.hostname || device.ip;
}

function ms(value: number | null): string {
  return value == null ? '—' : `${value < 10 ? value.toFixed(1) : Math.round(value)} ms`;
}

function cardStats(history: DeviceProbe[]) {
  const recent = history.slice(-60);
  const values = recent.filter(sample => sample.online && sample.latencyMs != null).map(sample => sample.latencyMs!);
  const changes = values.slice(1).map((value, i) => Math.abs(value - values[i]));
  return {
    failures: recent.length ? (recent.filter(sample => !sample.online).length / recent.length * 100) : 0,
    average: values.length ? values.reduce((a, b) => a + b, 0) / values.length : null,
    jitter: changes.length ? changes.reduce((a, b) => a + b, 0) / changes.length : null,
    min: values.length ? Math.min(...values) : null,
    max: values.length ? Math.max(...values) : null,
  };
}

function MonitorCard({ device, intervalSec, history, onStart, onStop, onOpenDevice }: {
  device: MonitorDevice;
  intervalSec: number;
  history: DeviceProbe[];
  onStart: Props['onStart'];
  onStop: Props['onStop'];
  onOpenDevice: Props['onOpenDevice'];
}) {
  const last = history[history.length - 1];
  const stats = cardStats(history);
  const scale = Math.max(10, ...history.slice(-48).map(sample => sample.latencyMs || 0));
  return <section className="panel monitor-card">
    <div className="monitor-card-head">
      <div className="monitor-title"><span className={`monitor-state-dot ${last?.online ? 'up' : last ? 'down' : 'waiting'}`}/><div><button onClick={() => onOpenDevice(device.ip)}>{deviceLabel(device)}</button><small>{device.ip} · {last ? (last.online ? 'Respondendo' : 'Sem resposta') : 'Aguardando primeira leitura'}</small></div></div>
      <div className="monitor-card-actions"><select aria-label={`Intervalo de ${device.ip}`} value={intervalSec} onChange={event => void onStart(device.ip, Number(event.target.value))}><option value={2}>2 s</option><option value={5}>5 s</option><option value={10}>10 s</option><option value={30}>30 s</option><option value={60}>1 min</option></select><button className="outline-button" onClick={() => void onStop(device.ip)}><Square size={14}/> Parar</button></div>
    </div>
    <div className="monitor-metrics"><div className="monitor-current"><span>LATÊNCIA AGORA</span><strong>{ms(last?.latencyMs ?? null)}</strong><small>{last?.method || 'Aguardando'} · leitura contínua</small></div><div><span>FALHAS</span><strong>{stats.failures.toFixed(0)}%</strong><small>últimas {Math.min(history.length, 60)} leituras</small></div><div><span>MÉDIA</span><strong>{ms(stats.average)}</strong><small>somente respostas</small></div><div><span>VARIAÇÃO</span><strong>{ms(stats.jitter)}</strong><small>entre respostas</small></div></div>
    <div className="monitor-history"><div className="monitor-history-title"><span>Histórico de latência</span><small>Mín {ms(stats.min)} · Máx {ms(stats.max)}</small></div>{history.length ? <div className="monitor-bars" role="img" aria-label={`Histórico de ${history.length} leituras para ${device.ip}`}>{history.slice(-48).map((sample, index) => <span key={`${sample.checkedAt}-${index}`} className={sample.online ? 'up' : 'down'} style={{ height: sample.online ? `${Math.max(10, (sample.latencyMs || 0) / scale * 100)}%` : '12%' }} title={`${new Date(sample.checkedAt).toLocaleTimeString('pt-BR')} · ${sample.online ? ms(sample.latencyMs) : sample.error || 'Sem resposta'}`}/>)}</div> : <div className="monitor-wait">A primeira leitura aparecerá em instantes.</div>}<div className="monitor-history-foot"><span>Última leitura: {last ? new Date(last.checkedAt).toLocaleTimeString('pt-BR') : '—'}</span><span>{last?.error || `${device.ports.length} porta(s) conhecida(s)`}</span></div></div>
  </section>;
}

export default function MonitorPanel({ devices, active, samples, onStart, onStop, onStopAll, onOpenDevice }: Props) {
  const [selected, setSelected] = useState('');
  const [intervalSec, setIntervalSec] = useState(5);
  const activeIps = Object.keys(active).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  const chosen = selected || devices[0]?.ip || '';
  return <>
    <div className="page-heading"><div><span className="eyebrow">ACOMPANHAMENTO AO VIVO</span><h1>Monitoramento</h1><p>Latência e disponibilidade de cada dispositivo, mesmo ao navegar pelas outras telas.</p></div><span className="forti-badge"><Activity size={16}/>{activeIps.length} em execução</span></div>
    <section className="panel monitor-setup"><div className="panel-heading"><div><h2>Adicionar dispositivo</h2><p>O monitor continua rodando enquanto o aplicativo estiver aberto, inclusive minimizado.</p></div><Monitor size={19}/></div><div className="monitor-setup-controls"><label>Dispositivo<select value={chosen} onChange={event => setSelected(event.target.value)}>{devices.map(device => <option key={device.ip} value={device.ip}>{deviceLabel(device)} · {device.ip}</option>)}</select></label><label>Intervalo<select value={intervalSec} onChange={event => setIntervalSec(Number(event.target.value))}><option value={2}>A cada 2 segundos</option><option value={5}>A cada 5 segundos</option><option value={10}>A cada 10 segundos</option><option value={30}>A cada 30 segundos</option><option value={60}>A cada 1 minuto</option></select></label><button className="primary-button" disabled={!chosen} onClick={() => void onStart(chosen, intervalSec)}><Play size={15}/>{active[chosen] ? 'Atualizar intervalo' : 'Deixar rodando'}</button>{activeIps.length > 0 && <button className="outline-button" onClick={() => void onStopAll()}><Square size={15}/> Parar todos</button>}</div><p className="muted-copy monitor-note">A resposta usa ICMP (ping). Se o dispositivo bloquear ping, o app testa até cinco portas TCP já conhecidas e identifica o método usado. Falhas e variação consideram as últimas 60 leituras.</p></section>
    {activeIps.length ? <div className="monitor-grid">{activeIps.map(ip => {
      const device = devices.find(item => item.ip === ip) || { ip, hostname: null, ports: [] };
      return <MonitorCard key={ip} device={device} intervalSec={active[ip]} history={samples[ip] || []} onStart={onStart} onStop={onStop} onOpenDevice={onOpenDevice}/>;
    })}</div> : <section className="panel monitor-empty"><Activity size={31}/><h2>Nenhum dispositivo em monitoramento</h2><p>Escolha um dispositivo encontrado na varredura e clique em “Deixar rodando”.</p></section>}
  </>;
}
