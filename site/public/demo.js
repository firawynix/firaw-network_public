(() => {
  const names = ['FortiGate','Servidor de arquivos','Estação Design','Estação Financeiro','Impressora'];
  const ports = ['22, 443','135, 445, 3389','135, 445','22, 80','80, 631'];
  let subnet = '192.168.10', selected = 1, monitoring = true, busy = false;
  const latency = [1,2,3,2,7];
  const rows = document.querySelector('#demo-rows');
  const render = () => {
    rows.replaceChildren();
    names.forEach((name,i) => {
      const row = document.createElement('tr');
      if (i === selected) row.className = 'selected';
      const first = document.createElement('td');
      const button = document.createElement('button'); button.className='device-name'; button.textContent=name; button.onclick=()=>{selected=i;render();}; first.append(button); row.append(first);
      [`${subnet}.${i+1}`,ports[i],`${latency[i]} ms`,'Online'].forEach((value,j)=>{const cell=document.createElement('td');cell.textContent=value;if(j===3)cell.className='online';row.append(cell);});
      rows.append(row);
    });
    const detail = document.querySelector('#device-detail');detail.replaceChildren();
    const title = document.createElement('strong'); title.textContent=`${names[selected]} · ${subnet}.${selected+1}`;
    const text = document.createElement('p');text.textContent=`Portas TCP: ${ports[selected]} · Resposta simulada: ${latency[selected]} ms`;
    const evidence = document.createElement('span');evidence.textContent= selected===0 ? 'HTTPS · HTTP 200 · versão não anunciada' : selected===1 ? 'SMB · RDP · Serviço estimado pela porta' : selected===3 ? 'SSH · SSH-2.0-OpenSSH_9.6 (exemplo)' : 'Dispositivo de exemplo · Sem coleta real';
    detail.append(title,text,evidence);
  };
  document.querySelectorAll('.subnet').forEach(button=>button.onclick=()=>{if(busy)return;subnet=button.dataset.subnet;document.querySelectorAll('.subnet').forEach(item=>item.classList.toggle('active',item===button));document.querySelector('#range-label').textContent=`${subnet}.0/24`;render();});
  document.querySelector('#monitor-toggle').onclick=()=>{monitoring=!monitoring;document.querySelector('#monitor-state').textContent=monitoring?'Ativo':'Pausado';document.querySelector('#monitor-toggle').textContent=monitoring?'Pausar monitor':'Retomar monitor';document.querySelector('#scan-status').textContent=monitoring?'Dados simulados · Monitor demonstrativo em execução':'Dados simulados · Monitor pausado';};
  document.querySelector('#scan-demo').onclick=async()=>{if(busy)return;busy=true;const button=document.querySelector('#scan-demo');button.disabled=true;document.querySelector('#scan-status').textContent='Simulando descoberta de dispositivos...';for(let i=0;i<=5;i++){document.querySelector('#device-count').textContent=i;await new Promise(resolve=>setTimeout(resolve,180));}document.querySelector('#scan-status').textContent='Simulação concluída · 5 dispositivos fictícios';button.disabled=false;busy=false;render();};
  setInterval(()=>{if(!monitoring)return;latency.forEach((_,i)=>latency[i]=1+((i*3+Math.floor(Date.now()/2000))%9));render();},2000);
  render();
})();
