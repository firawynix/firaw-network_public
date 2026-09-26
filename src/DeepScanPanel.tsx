import { useState } from 'react';
import { Play, Radar, Square } from 'lucide-react';

export type DeepFinding = {
  port: number;
  service: string;
  evidence: string | null;
  connectMs: number;
};

export type DeepProgress = { ip: string; done: number; total: number; finding: DeepFinding | null };
export type DeepOutcome = { ip: string; findings: DeepFinding[]; cancelled: boolean; scanned: number; total: number; elapsedMs: number };

type Props = {
  ip: string;
  scanning: boolean;
  scanningIp: string | null;
  progress: DeepProgress | null;
  findings: DeepFinding[];
  outcome: DeepOutcome | null;
  onStart: (mode: string, customPorts: string, timeoutMs: number) => void;
  onCancel: () => void;
};

export default function DeepScanPanel({ ip, scanning, scanningIp, progress, findings, outcome, onStart, onCancel }: Props) {
  const [mode, setMode] = useState('quick');
  const [customPorts, setCustomPorts] = useState('22, 80, 443, 8000-8100');
  const [timeoutMs, setTimeoutMs] = useState(400);
  const isThisScan = scanning && scanningIp === ip;
  const shownProgress = progress?.ip === ip ? progress : null;
  const percent = shownProgress?.total ? Math.min(100, shownProgress.done / shownProgress.total * 100) : 0;
  const sorted = [...findings].sort((a, b) => a.port - b.port);

  return <div className="detail-section deep-scan-section">
    <div className="section-heading"><h3>Análise detalhada Firaw</h3><span>{sorted.length} aberta(s)</span></div>
    <p className="muted-copy">Varredura TCP própria. Identifica serviços por resposta do protocolo e mostra versões quando o equipamento as informa.</p>
    <div className="deep-controls">
      <label>Alcance<select value={mode} disabled={scanning} onChange={event => setMode(event.target.value)}><option value="quick">Rápida · portas comuns</option><option value="standard">Padrão · 1 a 1024</option><option value="full">Completa · 1 a 65535</option><option value="custom">Faixa personalizada</option></select></label>
      <label>Espera por porta<select value={timeoutMs} disabled={scanning} onChange={event => setTimeoutMs(Number(event.target.value))}><option value={250}>250 ms</option><option value={400}>400 ms</option><option value={800}>800 ms</option><option value={1500}>1.500 ms</option></select></label>
    </div>
    {mode === 'custom' && <label className="deep-custom">Portas e faixas<input value={customPorts} disabled={scanning} onChange={event => setCustomPorts(event.target.value)} placeholder="Ex.: 22, 80, 443, 8000-8100"/></label>}
    {mode === 'full' && <p className="deep-note">A análise completa pode levar vários minutos. Use “Parar” para interromper a qualquer momento.</p>}
    <div className="deep-actions">{isThisScan ? <button className="outline-button" onClick={onCancel}><Square size={15}/> Parar análise</button> : <button className="wide-outline" disabled={scanning} onClick={() => onStart(mode, customPorts, timeoutMs)}><Play size={15}/> Iniciar análise</button>}{scanning && !isThisScan && <small>Análise em andamento em {scanningIp}</small>}</div>
    {shownProgress && <><div className="deep-progress-text"><span>{isThisScan ? 'Analisando' : outcome?.cancelled ? 'Interrompida' : 'Concluída'}</span><strong>{shownProgress.done.toLocaleString('pt-BR')} / {shownProgress.total.toLocaleString('pt-BR')}</strong></div><div className="deep-progress-track"><div style={{ width: `${percent}%` }}/></div></>}
    {outcome && <p className="deep-summary">{outcome.cancelled ? 'Análise interrompida' : 'Análise concluída'} · {outcome.findings.length} porta(s) aberta(s) · {(outcome.elapsedMs / 1000).toFixed(1)} s</p>}
    {sorted.length > 0 && <div className="deep-results"><div className="deep-result-head"><span>PORTA</span><span>SERVIÇO</span><span>RESPOSTA / VERSÃO</span><span>CONEXÃO</span></div>{sorted.map(item => <div className="deep-result" key={item.port}><strong>{item.port}/tcp</strong><span>{item.service}</span><span className="deep-evidence" title={item.evidence || ''}>{item.evidence || 'Versão não anunciada'}</span><span>{item.connectMs.toFixed(0)} ms</span></div>)}</div>}
    {outcome && !sorted.length && <div className="empty-small">Nenhuma porta respondeu dentro do alcance e do tempo escolhidos.</div>}
  </div>;
}
