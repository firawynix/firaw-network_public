from pathlib import Path
from datetime import datetime, timezone
import shutil
config = Path('/etc/cloudflared/config.yml')
text = config.read_text(encoding='utf-8')
entry = '  - hostname: ipscan.firawynix.com.br\n    service: http://127.0.0.1:26014\n'
anchor = '  - service: http://localhost:8099\n'
if entry in text:
    print('IPScan já configurado')
else:
    if 'hostname: ipscan.firawynix.com.br' in text or text.count(anchor) != 1:
        raise SystemExit('Configuração inesperada; túnel não alterado')
    backup = config.with_name('config.yml.before-ipscan-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    shutil.copy2(config, backup)
    config.write_text(text.replace(anchor, entry + anchor), encoding='utf-8')
    print('IPScan configurado; backup:', backup)
