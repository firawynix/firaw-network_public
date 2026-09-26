// Execute inside the portfolio backend; use its existing Cloudflare connection.
const token = process.env.CLOUDFLARE_API_TOKEN;
if (!token) throw new Error('Cloudflare não configurada');
async function cf(method, url, body) {
  const response = await fetch('https://api.cloudflare.com/client/v4'+url,{method,headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:body&&JSON.stringify(body)});
  const data=await response.json();if(!data.success)throw new Error(JSON.stringify(data.errors));return data.result;
}
(async()=>{
  const zone=(await cf('GET','/zones?name=firawynix.com.br'))[0];if(!zone)throw new Error('Zona ausente');
  const prefix=`/zones/${zone.id}/dns_records`;
  const existing=(await cf('GET',`${prefix}?name=ipscan.firawynix.com.br`))[0];
  const reference=(await cf('GET',`${prefix}?name=firawmerge.firawynix.com.br`))[0];
  if(!reference||reference.type!=='CNAME')throw new Error('Referência do túnel ausente');
  if(existing){if(existing.type!=='CNAME'||existing.content!==reference.content)throw new Error('DNS já existe com destino diferente; não alterado');console.log('DNS IPScan já configurado');return;}
  await cf('POST',prefix,{type:'CNAME',name:'ipscan.firawynix.com.br',content:reference.content,ttl:1,proxied:true});
  console.log('DNS IPScan criado no túnel existente');
})().catch(error=>{console.error(error.message);process.exitCode=1;});
