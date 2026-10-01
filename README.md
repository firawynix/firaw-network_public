# Firaw Network

Aplicativo Windows para descoberta, inventário e análise de dispositivos em redes administradas pelo usuário. A interface usa o tema escuro e ciano dos aplicativos Firawynix.

[Site e demonstração](https://ipscan.firawynix.com.br/) ·
[Instalador online](https://ipscan.firawynix.com.br/downloads/Firaw-Network-Instalador-Online.exe) ·
[Código público](https://github.com/firawynix/firaw-network_public)

## Instalar

Baixe o instalador online para Windows 10/11 de 64 bits. Ele verifica o tamanho,
o SHA-256 e a identidade da assinatura do pacote antes de instalar. O certificado
público `FirawNetwork.cer` acompanha o aplicativo. Confiar no certificado no
usuário atual é uma opção da instalação, desmarcada por padrão.

O certificado é próprio da Firawynix. A assinatura não garante reputação no
SmartScreen. O WebView2 precisa estar instalado; o instalador pode baixá-lo dos
servidores Microsoft se estiver ausente. A ferramenta também está em **Projetos**
no Firawynix Center.

## Funcionalidades desta versão

- Detecta sub-redes IPv4 das interfaces locais e rotas conhecidas do Windows. Com acesso de leitura ao FortiGate, também importa redes das interfaces e VLANs retornadas pela API ou por SSH.
- Varre faixas CIDR até 4.096 endereços usando ICMP e conexões TCP, com cancelamento e progresso.
- Mostra nome resolvido, MAC quando visível na rede local, latência ICMP em milissegundos e portas TCP configuradas.
- Permite dar um nome personalizado a cada dispositivo; guarda esse nome no inventário local e o inclui no CSV.
- Monitora até 32 dispositivos separadamente enquanto o aplicativo está aberto, inclusive minimizado. Mostra disponibilidade, latência em tempo real, média, variação, falhas e histórico das últimas leituras, com intervalo ajustável e botões para parar cada monitor ou todos.
- Guarda inventário e última presença localmente, detecta entradas e saídas e exporta CSV.
- Abre HTTP, HTTPS, RDP e SSH; envia Wake-on-LAN quando há MAC.
- Executa comandos via SSH previamente autenticado e oferece consultas rápidas de processos e recursos para Windows e Linux.
- Faz análise TCP individual com mecanismo próprio: portas comuns, 1 a 1.024, 1 a 65.535 ou faixas personalizadas. Mostra progresso, permite cancelar e identifica serviços por respostas SSH e HTTP/HTTPS e mensagens iniciais de outros protocolos. Exibe versões quando o serviço as anuncia.
- Consulta recursos, sessões e interfaces do FortiGate pela API REST com token fornecido na sessão. Com o monitor ligado, atualiza as sessões periodicamente. Resume bytes por IP quando a resposta contém contadores reconhecíveis.
- Alternativamente, conecta ao FortiGate por SSH com senha ou agente de chaves para importar redes conectadas e rotas. Confirme a impressão digital SSH antes de autenticar. As redes importadas ficam disponíveis após reiniciar o aplicativo.

## Executar

Requisitos: Windows 10/11, Node.js, Rust e WebView2. Na pasta do projeto:

```powershell
npm install
npm run tauri:dev
```

Para criar o instalador NSIS:

```powershell
npm run tauri:build
```

O pacote publicado usa a assinatura Firawynix configurada em
`src-tauri/tauri.conf.json`. Para um build local sem essa identidade:

```powershell
npm run tauri:build -- --no-sign
```

Para criar o instalador online a partir do pacote completo assinado:

```powershell
powershell -NoProfile -File tools/build-online.ps1
node tools/prepare-catalog.mjs
```

O script gera o manifesto com tamanho e SHA-256 do pacote completo, compila o
instalador NSIS, assina os executáveis e prepara os downloads do site. Ele usa
o certificado no armazenamento do Windows e nunca exporta a chave privada.
`FIRAW_SIGNING_THUMBPRINT` e `FIRAW_SIGNTOOL` permitem escolher a identidade e o
assinador no script. Para outra identidade, ajuste também o certificado público,
o pin no instalador e a configuração de assinatura do Tauri.

## Site e ícone

`site/public` contém a página responsiva, a demonstração com dados fictícios e a
barra inferior fixa. A demonstração não faz consultas à rede do visitante.
`assets/logo.svg` é a marca original; `tools/make-icon.py` gera PNGs e um `.ico`
com múltiplos tamanhos. Os arquivos do site podem ser servidos como arquivos
estáticos. A configuração Docker usa uma rede externa existente no servidor.

`packaging/firaw-network-project.json` registra os artefatos do Center com seus
hashes reais. `site/catalog.sql` atualiza o catálogo e o portfólio; sua aplicação
deve ocorrer no ambiente Firawynix, após os downloads estarem disponíveis.

## Pacote para a Microsoft Store

A identidade reservada é `Firawynix.FirawNetwork` e o ID é `9N38CQ340VZX`.
O aplicativo está publicado na [Microsoft Store](https://apps.microsoft.com/detail/9N38CQ340VZX).
O pacote da Store é `0.2.2.0` e contém o aplicativo `0.2.1`.
Os dados de publicação e as imagens sem inventário privado ficam em
`packaging/store`. Para gerar o MSIX x64 com o executável já compilado:

```powershell
powershell -NoProfile -File tools/build-msix.ps1 -Config packaging/store/msix.json -Channel Store -Publisher CN=1FDE3668-C222-4506-AFE6-E2E425EAECD8 -OutputDirectory release/store
```

O pacote usa a identidade do Partner Center. A Microsoft assina o pacote
distribuído pela Store; o certificado do instalador do site não é usado para
assinar esse MSIX. A distribuição depende da certificação da Microsoft.
O Microsoft Edge WebView2 Runtime deve estar instalado.

## FortiGate

Crie no FortiOS um administrador REST API com permissão somente leitura e restrinja os Trusted Hosts ao IP da estação. A aplicação exige HTTPS com certificado confiável e envia o token no cabeçalho `Authorization: Bearer`; o token não é gravado no inventário nem no armazenamento local. Os campos e endpoints podem variar conforme a versão do FortiOS. Consulte o modelo e a versão antes de ajustar a integração para uso contínuo.

Para usar SSH como alternativa, habilite SSH na interface de administração do FortiGate e use uma conta com permissão de leitura. O app lê a tabela de rotas com `get router info routing-table all` e as interfaces com `show system interface`. A senha e a impressão digital confirmada permanecem apenas na sessão atual. SSH permite listar sub-redes fora da rede do computador, mas não fornece as mesmas estatísticas estruturadas de sessões e recursos da API.

## Limites dos dados

- MAC é confiável apenas quando o equipamento aparece na tabela de vizinhos da rede local. Um host que não responde ao ICMP nem às portas de detecção rápida pode não aparecer.
- A descoberta de rede usa as portas configuradas; a análise individual usa o alcance selecionado. O analisador é original e não requer outro programa. Ele consulta portas TCP; não faz varredura UDP, identificação de sistema operacional nem scripts de inspeção. A identificação de versões depende das informações anunciadas pelos serviços.
- A latência do monitor usa o tempo de resposta ICMP. Quando o dispositivo bloqueia ping, o app mede o tempo de conexão TCP nas portas conhecidas e identifica esse método. O histórico de amostras existe somente enquanto o app permanece aberto.
- As sessões do FortiGate mostram apenas o tráfego que passa pelo firewall e que sua API devolve. Bytes de sessão são acumulados, não taxa de banda em tempo real.
- Processos e recursos requerem acesso SSH ao próprio dispositivo. Para execução rápida sem interação, configure uma chave SSH. O aplicativo não instala agentes automaticamente.
- A descoberta de todas as VLANs depende de acesso às rotas, interfaces ou informações dos equipamentos de rede; não é possível inferir todas só a partir da estação.
