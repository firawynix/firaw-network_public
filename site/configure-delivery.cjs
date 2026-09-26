// Configure delivery for this static host using the existing server connection.
const fs=require('node:fs');
const envPath='/home/ksdev/firawynix-portfolio/.env';
const settings={};
for(const line of fs.readFileSync(envPath,'utf8').split(/\r?\n/)) {
  const match=line.match(/^([A-Z_]+)=(.*)$/);if(!match)continue;
  let value=match[2].trim();if((value.startsWith('"')&&value.endsWith('"'))||(value.startsWith("'")&&value.endsWith("'")))value=value.slice(1,-1);
  settings[match[1]]=value;
}
const token=settings.CLOUDFLARE_API_TOKEN;
if(!token)throw new Error('Conexão Cloudflare ausente');
async function api(method,path,body){const response=await fetch('https://api.cloudflare.com/client/v4'+path,{method,headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:body&&JSON.stringify(body)});const data=await response.json();if(!data.success)throw new Error(JSON.stringify(data.errors));return data.result;}
(async()=>{
  const zone=settings.CLOUDFLARE_ZONE_ID || (await api('GET','/zones?name=firawynix.com.br'))[0]?.id;
  const ruleset=await api('GET',`/zones/${zone}/rulesets/phases/http_request_firewall_custom/entrypoint`);
  if(process.argv.includes('--inspect')){console.log(JSON.stringify(ruleset.rules.map(({id,description,action,expression,action_parameters})=>({id,description,action,expression,action_parameters})),null,2));return;}
  const description='ipscan: entrega publica estatica GET e HEAD';
  if(ruleset.rules.some(rule=>rule.description===description)){console.log('Entrega IPScan já configurada');return;}
  const rule={description,action:'skip',expression:'(http.host eq "ipscan.firawynix.com.br" and http.request.method in {"GET" "HEAD"})',enabled:true,action_parameters:{ruleset:'current',products:['bic','securityLevel']}};
  if(ruleset.rules.length>=5){
    // Preserve both existing delivery exceptions in one equivalent rule.
    const remote=ruleset.rules.find(r=>r.description==='firaw-remote: site downloads e atualizador sem desafio');
    const merge=ruleset.rules.find(r=>r.description==='firawmerge: site downloads e atualizador sem desafio');
    if(!remote||!merge||remote.action!==merge.action||JSON.stringify(remote.action_parameters)!==JSON.stringify(merge.action_parameters)||remote.enabled!==merge.enabled)throw new Error('Não há duas regras equivalentes para consolidar');
    fs.writeFileSync('/home/ksdev/ipscan-site/cloudflare-before-ipscan-'+Date.now()+'.json',JSON.stringify(ruleset,null,2));
    const allowed=['id','action','action_parameters','expression','description','enabled','logging','ref'];
    const rules=ruleset.rules.filter(r=>r.id!==merge.id).map(r=>Object.fromEntries(Object.entries(r).filter(([key])=>allowed.includes(key))));
    const consolidated=rules.find(r=>r.id===remote.id);
    consolidated.expression=`(${remote.expression}) or (${merge.expression})`;
    consolidated.description='firaw-remote e firawmerge: site downloads e atualizador sem desafio';
    rules.unshift(rule);
    await api('PUT',`/zones/${zone}/rulesets/${ruleset.id}`,{rules});
  }else{
    await api('POST',`/zones/${zone}/rulesets/${ruleset.id}/rules`,{...rule,position:{before:ruleset.rules[0].id}});
  }
  console.log('Entrega pública GET/HEAD configurada apenas para ipscan; WAF gerenciado e limites mantidos.');
})().catch(error=>{console.error(error.message);process.exitCode=1;});
