import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Fingerprint, Network, ShieldCheck } from 'lucide-react';

export type FoundSubnet = { cidr: string; label: string; source: 'fortigate'; hostCount: number };

type Props = {
  ip: string;
  onNetworks: (networks: FoundSubnet[]) => void;
  onNotice: (message: string) => void;
  onError: (message: string) => void;
};

export default function FortiSshPanel({ ip, onNetworks, onNotice, onError }: Props) {
  const [port, setPort] = useState('22');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [fingerprint, setFingerprint] = useState('');
  const [checked, setChecked] = useState(false);
  const [busy, setBusy] = useState(false);

  async function readFingerprint() {
    setBusy(true);
    setFingerprint('');
    setChecked(false);
    onError('');
    try {
      const value = await invoke<string>('fortigate_ssh_fingerprint', { ip, port: Number(port) });
      setFingerprint(value);
      onNotice('Chave SSH recebida. Confira a impressão digital antes de buscar redes.');
    } catch (error) { onError(String(error)); }
    finally { setBusy(false); }
  }

  async function discover() {
    setBusy(true);
    onError('');
    try {
      const networks = await invoke<FoundSubnet[]>('fortigate_ssh_networks', {
        ip, port: Number(port), username, password: password || null, fingerprint,
      });
      onNetworks(networks);
      onNotice(`${networks.length} redes encontradas pelas interfaces e rotas do FortiGate.`);
    } catch (error) { onError(String(error)); }
    finally { setBusy(false); }
  }

  return <section className="panel forti-ssh-panel">
    <div className="panel-heading"><div><h2>Conexão SSH ao FortiGate</h2><p>Descubra redes conectadas e rotas além da faixa deste computador.</p></div><Network size={19}/></div>
    <div className="forti-form ssh-form">
      <label>Porta SSH<input type="number" min="1" max="65535" value={port} onChange={e => { setPort(e.target.value); setFingerprint(''); setChecked(false); }}/></label>
      <label>Usuário administrador<input placeholder="Usuário com leitura das rotas" value={username} onChange={e => setUsername(e.target.value)} autoComplete="username"/></label>
      <label>Senha SSH (opcional com agente de chaves)<input type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="off" placeholder="Mantida apenas nesta sessão"/></label>
    </div>
    <div className="forti-actions"><button className="outline-button" disabled={busy || !ip || !Number(port)} onClick={readFingerprint}><Fingerprint size={16}/> Ler chave SSH</button></div>
    {fingerprint && <div className="ssh-verify"><strong>Impressão digital SHA-256</strong><code>{fingerprint.match(/.{1,2}/g)?.join(':')}</code><label><input type="checkbox" checked={checked} onChange={e => setChecked(e.target.checked)}/> Conferi que esta chave pertence ao meu FortiGate</label><button className="primary-button" disabled={busy || !checked || !username} onClick={discover}><ShieldCheck size={16}/> Buscar redes via SSH</button></div>}
    <p className="muted-copy ssh-help">O SSH consulta interfaces e tabela de rotas com permissão de leitura. Precisa de acesso SSH habilitado e de uma conta autorizada. As redes descobertas entram na lista lateral para varredura individual, desde que este computador consiga alcançá-las. Para sessões e uso de recursos, use a API acima.</p>
  </section>;
}
