'use strict';
// Project inventory UI. Existing scan/import/evidence workflows remain shared.
const searchLink=(q='',mode='auto')=>'#explore?'+new URLSearchParams({q,mode});
const hostLink=id=>'#host?id='+id;
const coverageLabel=x=>({scanned:'Scanned',active:'Active evidence',passive:'Passive only',unscanned:'Not scanned'}[x]||x);
let hidePassive=localStorage.getItem('vandal-hide-passive')==='1';
const unfilteredApi=api;
api=async function(path,options={}){
 if(hidePassive&&(!options.method||options.method==='GET')&&/^\/api\/e\/\d+\/(inventory(?:\/\d+)?|findings)(?:\?|$)/.test(path)){
  const url=new URL(path,location.origin);url.searchParams.set('hide_passive','1');path=url.pathname+url.search;
 }
 return unfilteredApi(path,options);
};
const passiveToggle=document.createElement('button');passiveToggle.type='button';passiveToggle.id='hide-passive';passiveToggle.title='Explore, Domains, host details and Vulnerabilities. Confirmed findings remain visible.';
function updatePassiveToggle(){passiveToggle.textContent='Hide passive: '+(hidePassive?'ON':'OFF');passiveToggle.setAttribute('aria-pressed',String(hidePassive));passiveToggle.className=hidePassive?'primary':'secondary'}
$('.page-heading').insertBefore(passiveToggle,$('#page-actions'));updatePassiveToggle();
passiveToggle.addEventListener('click',async()=>{
 hidePassive=!hidePassive;updatePassiveToggle();localStorage.setItem('vandal-hide-passive',hidePassive?'1':'0');selected.clear();closeDrawer();closeHostPane();navigate(page,{...params,page:1});await route();
});
const originalFindingDrawer=findingDrawer;
findingDrawer=async function(...args){
 await originalFindingDrawer(...args);
 const form=$('#finding-form');if(!form)return;
 const field=form.elements.asset_ids,chosen=new Map(field.value.split(',').filter(Boolean).map(id=>[Number(id),{id:Number(id),value:'Asset #'+id}]));
 const picker=document.createElement('section');picker.className='asset-picker';
 picker.innerHTML='<label>ASSETS — IP, HOSTNAME OR ID<input type="search" class="asset-search" placeholder="Search project assets…" autocomplete="off"></label><div class="asset-selected"></div><div class="asset-options" aria-live="polite"></div>';
 field.type='hidden';field.parentElement.replaceWith(picker);picker.append(field);
 const input=picker.querySelector('input[type=search]'),selectedBox=picker.querySelector('.asset-selected'),results=picker.querySelector('.asset-options');
 const draw=()=>{field.value=[...chosen.keys()].join(',');selectedBox.innerHTML=[...chosen.values()].map(a=>`<button type="button" class="tag" data-remove-asset="${a.id}" aria-label="Remove ${esc(a.value)}">${esc(a.value)} · #${a.id} ×</button>`).join('')};
 draw();
 if(chosen.size){try{const assets=await api(endpoint('asset-options?'+new URLSearchParams({ids:[...chosen.keys()].join(',')})));if(!form.isConnected)return;for(const a of assets)chosen.set(a.id,a);draw()}catch(e){results.textContent=e.message}}
 let version=0,timer;
 input.addEventListener('input',()=>{clearTimeout(timer);const ticket=++version,q=input.value.trim();results.textContent='';if(!q)return;
  timer=setTimeout(async()=>{try{const assets=await api(endpoint('asset-options?'+new URLSearchParams({q})));if(ticket!==version||!form.isConnected)return;
   results.innerHTML=assets.map(a=>`<button type="button" class="facet-value" data-pick-asset="${a.id}"><span>${esc(a.value)}</span><small>${esc(a.kind)} · #${a.id}${chosen.has(a.id)?' · selected':''}</small></button>`).join('')||'<p class="muted">No matching assets.</p>';
   if(assets.length===200)results.insertAdjacentHTML('beforeend','<p class="micro">Showing 200 matches. Refine your search.</p>');
   results.querySelectorAll('[data-pick-asset]').forEach(button=>button.onclick=()=>{const a=assets.find(a=>a.id===Number(button.dataset.pickAsset));chosen.set(a.id,a);draw();results.innerHTML='';input.value='';input.focus()});
  }catch(e){if(ticket===version&&form.isConnected)results.textContent=e.message}},200);
 });
 selectedBox.onclick=e=>{const button=e.target.closest('[data-remove-asset]');if(button){chosen.delete(Number(button.dataset.removeAsset));draw()}};
};
function servicePill(s){return `<a class="service-pill" href="#" data-port-owner="${s.owner_id}" data-port="${s.port}" data-protocol="${esc(s.protocol)}" title="${esc(s.owner)} · ${esc(s.evidence)} · ${esc(stamp(s.observed_at))}">${s.port}/${esc(s.protocol)} <span>${esc(s.service||s.state)}</span>${s.evidence==='passive'?' <small>passive</small>':''}</a>`}
function compactServices(a){
 const groups=new Map();for(const s of a.services.filter(s=>s.state==='open')){const key=s.protocol+'/'+s.port;if(!groups.has(key))groups.set(key,[]);groups.get(key).push(s)}
 return [...groups.values()].slice(0,8).map(g=>g.length===1?servicePill(g[0]):`<a class="service-pill" href="#host?id=${a.id}&tab=services&port=${g[0].port}">${g[0].port}/${esc(g[0].protocol)} <small>${g.length} owners</small></a>`).join('');
}
function searchText(){if(params.q)return params.q;const pairs={domain:'hostname',port:'port',service:'service',evidence:'source'};return Object.entries(pairs).filter(([k])=>params[k]).map(([k,v])=>v+':'+params[k]).join(' ')}
async function inventoryPage(token){
 const mode=page==='domains'?'hostname':params.mode||(params.primary==='ip'?'ip':'auto');
 const q=searchText();let data,error='';try{data=await api(endpoint('inventory?'+new URLSearchParams({q,mode,sort:params.sort||'address',page:params.page||1})))}catch(e){error=e.message;data={items:[],facets:{},tokens:[],total:0,page:1,size:25}}
 const facetNames={org:'Organization',cve:'CVE',country:'Country',domain:'Domain',coverage:'Coverage',scope:'Scope',port:'Port',service:'Service',source:'Source'};
 const facets=Object.entries(data.facets).map(([key,values])=>{
  const buttons=rows=>rows.map(([value,n])=>`<button class="facet-value" data-search-add="${esc((key==='domain'?'hostname':key)+':'+JSON.stringify(String(value)))}"><span>${esc(value)}${key==='cve'?`<br><small>${data.cve_scores?.[value]>=0?'CVSS '+data.cve_scores[value]:'Unscored'}</small>`:''}</span><b>${fmt(n)}</b></button>`).join('');
  return `<details class="facet" ${['coverage','port','domain'].includes(key)?'open':''}><summary>${facetNames[key]}</summary>${buttons(values.slice(0,8))||'<p class="muted">No values</p>'}${values.length>8?`<details class="facet"><summary>Show all ${fmt(values.length)} ${key==='domain'?'domains':'values'}</summary>${buttons(values.slice(8))}</details>`:''}${key==='domain'?`<a class="text-link" href="#domains?${new URLSearchParams({q})}">Search by domain →</a>`:''}</details>`;
 }).join('');
 const cards=data.items.map(a=>{
  let related=[...a.associated];const domainTerm=data.tokens.find(t=>t.key==='hostname'&&!t.negative)?.value;
  if(domainTerm)related.sort((x,y)=>Number(y.value.endsWith(domainTerm))-Number(x.value.endsWith(domainTerm)));
  const names=related.filter(r=>r.kind===(a.kind==='ip'?'hostname':'ip'));
  const open=a.services.filter(s=>s.state==='open');
  return `<article class="host-result"><div class="result-header"><input type="checkbox" data-select="${a.id}" data-value="${esc(a.value)}" ${selected.has(a.id)?'checked':''} aria-label="Select ${esc(a.value)}"><h2><a href="${hostLink(a.id)}">${esc(a.value)}</a></h2><span class="coverage ${a.coverage}">${coverageLabel(a.coverage)}</span></div>
   <div class="result-names">${names.slice(0,2).map(r=>`<a href="${hostLink(r.id)}">${esc(r.value)}</a>`).join(' · ')||'<span class="muted">No associated '+(a.kind==='ip'?'hostnames':'IPs')+'</span>'}${names.length>2?` <a href="${hostLink(a.id)}">+${names.length-2} more</a>`:''}</div>
   <div class="result-meta">${esc(a.provider||'Organization unknown')} · ${esc(a.country)} · ${esc(a.scope)}<span>Last checked: ${esc(stamp(a.last_scan))}</span></div>
   <div class="service-strip">${compactServices(a)||'<span class="muted">'+(a.coverage==='scanned'?'No open ports in retained observations':'No open-port evidence')+'</span>'}${open.length>8?`<a href="${hostLink(a.id)}">+${open.length-8} endpoints</a>`:''}</div>
   <div class="result-footer"><a href="${hostLink(a.id)}">Open ${a.kind==='ip'?'host':'hostname'} →</a><span>${a.potential?`${a.potential} potential CVEs · `:''}${a.confirmed?`${a.confirmed} confirmed · `:''}${a.sources.length} sources</span>${a.kind==='ip'?`<button class="quiet" data-quick-scan="${a.id}">Scope + Nmap</button>`:'<button class="quiet" data-host-scan="'+a.id+'" data-host-value="'+esc(a.value)+'">Scan hostname</button>'}</div></article>`;
 }).join('');
 put(`<div class="view-toggle"><a class="tag active" href="#explore">Inventory</a><a class="tag" href="#domains">Search by domain</a><a class="tag" href="#web">Web</a><button class="quiet" data-web-scan>Web capture</button></div><form id="inventory-search" class="toolbar"><input name="q" class="search" aria-label="Search inventory" placeholder='hostname:example.com port:443 product:nginx' value="${esc(q)}"><input type="hidden" name="mode" value="${mode}"><button class="primary">Search</button></form>
 ${error?`<p class="notice" role="alert">${esc(error)}</p>`:''}<details class="search-help"><summary>Search syntax</summary><p>Terms are ANDed. Use quotes for spaces and - to exclude. Port, service and product terms must match the same observation.</p><code>hostname:example.com · ip:192.0.2.1 · net:192.0.2.0/24 · port:443 · product:nginx · service:https · country:"United States" · org:Kohler · asn:AS123 · source:shodan · has:vuln · has:ports · scanned:false · scope:included · coverage:passive · cve:CVE-2024-12345</code></details>
 <div class="query-chips">${data.tokens.map((t,i)=>`<button class="quiet" data-search-remove="${i}">${esc(t.text)} ×</button>`).join('')}</div>
 <div class="toolbar inventory-controls"><span>${fmt(data.total)} ${mode==='hostname'?'hostnames':mode==='ip'?'hosts':'results'}</span>${page!=='domains'?`<label>Results<select id="inventory-mode"><option value="ip" ${mode==='ip'?'selected':''}>IP first</option><option value="auto" ${mode==='auto'?'selected':''}>Hostname first (IP fallback)</option><option value="hostname" ${mode==='hostname'?'selected':''}>Hostnames only</option></select></label>`:''}<label>Sort<select id="inventory-sort">${[['address','Address / domain'],['hostname','Hostname'],['recent','Latest observation'],['vulns','Vulnerability count'],['open_ports','Most open ports']].map(([v,l])=>`<option value="${v}" ${params.sort===v?'selected':''}>${l}</option>`).join('')}</select></label><span id="selection-count">${selected.size} selected</span><button class="quiet" data-action="new-job">Scan selection</button><button class="quiet" data-action="save-view">Save view</button><button class="quiet" data-load-views>Saved views</button></div>
 <div class="inventory-layout"><aside class="facet-panel">${facets}</aside><div>${cards||empty('No matching results','Change the query or import scan data.')}${pagination(data)}</div></div>`,token);
 inventoryPage.tokens=data.tokens;
}
renderers.explore=inventoryPage;
renderers.domains=async function(token){
 const q=searchText();
 const data=await api(endpoint('inventory?'+new URLSearchParams({mode:'hostname',q,domain_summary:'1'})));
 if(!put(`<div class="view-toggle"><a class="tag" href="#explore">Inventory</a><a class="tag active" href="#domains">Search by domain</a><a class="tag" href="#web">Web</a></div>
 ${q?`<p class="query-chips">Inventory filter: ${esc(q)} <a class="text-link" href="#domains">Clear</a></p>`:''}
 <div class="toolbar"><label>DOMAIN<input id="domain-filter" class="search" type="search" placeholder="Filter domains…"></label><label>SORT<select id="domain-sort"><option value="domain">Domain A–Z</option><option value="hostnames">Hostname count</option><option value="ips">IP count</option><option value="unscanned">Not scanned</option></select></label><span id="domain-count"></span></div>
 <p class="micro">Grouped by root domain. Coverage counts hostnames; IP addresses are unique within each domain.</p><div id="domain-table"></div>`,token))return;
 const draw=()=>{
  const filter=$('#domain-filter').value.trim().toLowerCase(),sort=$('#domain-sort').value;
  const groups=data.domain_groups.filter(g=>g.domain.toLowerCase().includes(filter)).sort((a,b)=>sort==='domain'?a.domain.localeCompare(b.domain):b[sort]-a[sort]||a.domain.localeCompare(b.domain));
  $('#domain-count').textContent=`${fmt(groups.length)} / ${fmt(data.domain_groups.length)} domains`;
  $('#domain-table').innerHTML=groups.length?table(['DOMAIN','HOSTNAMES','IPs','WITH OPEN PORTS','SCANNED','ACTIVE EVIDENCE','PASSIVE ONLY','NOT SCANNED'],groups.map(g=>{
   const query=[q,'hostname:'+JSON.stringify(g.domain)].filter(Boolean).join(' ');
   const link=(n,extra='')=>`<a class="text-link" href="${esc(searchLink(query+extra,'hostname'))}">${fmt(n)}</a>`;
   return `<tr><td><a class="text-link" href="${esc(searchLink(query,'hostname'))}">${esc(g.domain)}</a></td><td>${link(g.hostnames)}</td><td>${fmt(g.ips)}</td><td>${link(g.with_ports,' has:ports')}</td><td>${link(g.scanned,' coverage:scanned')}</td><td>${link(g.active,' coverage:active')}</td><td>${link(g.passive,' coverage:passive')}</td><td>${link(g.unscanned,' coverage:unscanned')}</td></tr>`;
  }).join('')):empty('No matching domains','Change the domain filter or import hostname data.');
 };
 $('#domain-filter').addEventListener('input',draw);$('#domain-sort').addEventListener('change',draw);draw();
};
renderers.host=async function(token){
 const a=await api(endpoint('inventory/'+Number(params.id)));const tab=params.tab||'services';
 $('#page-title').textContent=a.value;
 $('#page-actions').innerHTML=a.kind==='ip'?`<button class="primary" data-quick-scan="${a.id}">Scope + Nmap</button>`:`<button class="primary" data-host-scan="${a.id}" data-host-value="${esc(a.value)}">New scan for hostname</button>`;
 const tabs=['services','vulnerabilities','relationships','history','notes'];
 const nav=tabs.map(t=>`<a class="${tab===t?'active':''}" href="#host?${new URLSearchParams({id:a.id,tab:t})}">${t[0].toUpperCase()+t.slice(1)}</a>`).join('');
 let body='';
 if(tab==='services')body=a.services.filter(s=>!params.port||s.port===Number(params.port)).map(s=>`<section class="panel"><div class="panel-head"><h3>${s.port}/${esc(s.protocol)} · ${esc(s.service||'Service unknown')}</h3>${badge(s.state)}</div><div class="panel-body"><p>${esc(s.product||'No product identified')}</p><p class="service-context">${esc(s.owner)} · ${esc(s.evidence)} · ${esc(stamp(s.observed_at))}${s.conflict?' · States differ across observations':''}</p><a class="text-link" href="#" data-record="${s.record_id}">Latest summary evidence →</a> <button class="quiet" data-port-owner="${s.owner_id}" data-port="${s.port}" data-protocol="${esc(s.protocol)}">${s.count} observations</button><details class="banner"><summary>Source output</summary><pre>${esc(s.banner||'No source output retained.')}</pre></details></div></section>`).join('')||empty('No service observations','DNS discovery alone does not establish an open service.');
 if(tab==='vulnerabilities')body=findingTable(a.findings);
 if(tab==='relationships')body=table(['RELATED ASSET','RELATIONSHIP','OBSERVED','SOURCE'],a.detail.relationships.map(r=>`<tr><td><a class="text-link" href="${hostLink(r.id)}">${esc(r.value)}</a></td><td>${esc(r.kind)}</td><td>${esc(stamp(r.observed_at))}</td><td><a class="text-link" href="#" data-record="${r.record_id}">${esc(r.filename)}</a></td></tr>`).join(''));
 if(tab==='history')body=`<h2>Scan jobs</h2>${jobRows(a.jobs)}<h2>Source records</h2>${table(['RECORD','TYPE','OBSERVED'],a.detail.records.map(r=>`<tr><td><a href="#" class="text-link" data-record="${r.id}">${esc(r.title)}</a></td><td>${esc(r.kind)}</td><td>${esc(stamp(r.observed_at))}</td></tr>`).join(''))}<a href="#records?asset_id=${a.id}">Browse all records →</a>`;
 if(tab==='notes')body=`<form id="asset-form" data-id="${a.id}"><label>TAGS<input name="tags" value="${esc(a.tags)}"></label><label>NOTES<textarea name="notes">${esc(a.notes)}</textarea></label><button class="primary">Save</button></form><button class="quiet" data-interest-asset="${a.id}">Add item of interest</button>`;
 put(`<div class="host-summary"><span class="coverage ${a.coverage}">${coverageLabel(a.coverage)}</span> ${badge(a.scope)}<p>${esc(a.provider||'Organization unknown')} · ${esc(a.country)} ${esc(a.city)}</p><p>Last scan: ${esc(stamp(a.last_scan))} · Last observation: ${esc(stamp(a.last_seen))}</p><div>${a.associated.slice(0,4).map(r=>`<a class="tag" href="${hostLink(r.id)}">${esc(r.value)}</a>`).join('')}${a.associated.length>4?`<a href="#host?id=${a.id}&tab=relationships">+${a.associated.length-4} relationships</a>`:''}</div></div><nav class="host-tabs">${nav}</nav>${body}`,token);
 if(token===epoch)confirmedHostPanel($('#content .host-summary'),a);
};
function confirmedHostPanel(header,a){
 if(!header)return;
 const findings=(a.confirmed_findings||a.findings||[]).filter(f=>f.confirmed&&f.status!=='dismissed');
 const row=document.createElement('div');row.className='host-top-row';header.before(row);row.append(header);
 row.insertAdjacentHTML('beforeend',`<aside class="host-confirmed" aria-label="Confirmed vulnerabilities"><h3>Confirmed vulnerabilities <span>${findings.length}</span></h3>${findings.length?findings.map(f=>`<article><a class="text-link" href="#" data-finding="${f.id}">${esc(f.title)}</a><p class="micro">${esc(f.priority)} priority${f.affected_assets?.length?' · '+f.affected_assets.map(x=>esc(x.value)).join(', '):''}</p>${f.notes?`<p class="confirmed-note">${esc(f.notes)}</p>`:''}</article>`).join(''):'<p class="muted">None confirmed.</p>'}</aside>`);
}
function findingTable(items){return items.length?table(['ITEM / CVE','CATEGORY','STATE','EVIDENCE'],items.map(f=>`<tr><td><a href="#" class="text-link" data-finding="${f.id}">${esc(f.title)}</a></td><td>${esc(f.category)}</td><td>${badge(f.confirmed?'confirmed':f.status)}</td><td>${parse(f.evidence).length} records</td></tr>`).join('')):empty('No items','No matching vulnerability or review items.')}
renderers.findings=async function(token){
 const all=await api(endpoint('findings'));const state=params.state||'potential';
 const items=all.filter(f=>state==='all'||state==='confirmed'&&f.confirmed||state==='potential'&&!f.confirmed&&f.category==='potential CVE'||state==='interests'&&!f.confirmed&&f.category!=='potential CVE').filter(f=>!params.status||f.status===params.status).filter(f=>!params.q||[f.title,f.notes].join(' ').toLowerCase().includes(params.q.toLowerCase()));
 $('#page-actions').innerHTML='<button class="primary" data-action="new-finding">+ Item of interest</button>';
 put(`<form id="review-search" class="toolbar"><input class="search" name="q" placeholder="Search CVE, host or notes" value="${esc(params.q||'')}"><select name="status"><option value="">All review states</option>${['new','reviewing','parked','dismissed'].map(v=>`<option ${params.status===v?'selected':''}>${v}</option>`).join('')}</select><button class="primary">Filter</button></form><div class="view-toggle review-tabs">${[['potential','Potential CVEs'],['confirmed','Confirmed'],['interests','Items of interest'],['all','All']].map(([v,l])=>`<a class="tag ${v===state?'active':''}" href="#findings?state=${v}">${l} (${all.filter(f=>v==='all'||v==='confirmed'&&f.confirmed||v==='potential'&&!f.confirmed&&f.category==='potential CVE'||v==='interests'&&!f.confirmed&&f.category!=='potential CVE').length})</a>`).join('')}</div>${findingTable(items)}`,token);
};
function jobTargetSummary(j){const targets=parse(j.targets),first=targets[0]||'No targets';return targets.length>1?`<details class="target-summary"><summary>${esc(first)} <span>+${targets.length-1}</span></summary><div>${targets.map(t=>`<code>${esc(t)}</code>`).join('')}</div></details>`:`<code>${esc(first)}</code>`}
function jobRows(jobs){return jobs.length?table(['JOB','PROFILE / TARGET','STATE','CREATED'],jobs.map(j=>`<tr><td><a href="#" class="text-link" data-job="${j.id}">#${j.id}</a></td><td>${esc(j.profile)}${jobTargetSummary(j)}</td><td>${badge(j.status)}</td><td>${esc(stamp(j.created_at))}</td></tr>`).join('')):empty('No scans','Use New scan to start a job.')}
// Patch live dashboard content without detaching the WebGL canvas or clearing
// the enrichment row between polls (both caused resize/scroll jumps).
function putOverview(html,token){
 if(token!==epoch)return;
 if(!$('#overview-map')){put(html,token);return}
 function patch(current,fresh){
  if(current.nodeType!==fresh.nodeType||current.nodeName!==fresh.nodeName){current.replaceWith(fresh.cloneNode(true));return}
  if(current.nodeType===Node.TEXT_NODE){if(current.data!==fresh.data)current.data=fresh.data;return}
  if(current.nodeType===Node.ELEMENT_NODE){
   if(['overview-map','enrichment-progress'].includes(current.id))return;
   for(const attr of [...current.attributes])if(!fresh.hasAttribute(attr.name))current.removeAttribute(attr.name);
   for(const attr of fresh.attributes)if(current.getAttribute(attr.name)!==attr.value)current.setAttribute(attr.name,attr.value);
  }
  const old=[...current.childNodes],updated=[...fresh.childNodes];
  for(let i=0;i<Math.max(old.length,updated.length);i++){
   if(!updated[i])old[i].remove();else if(!old[i])current.append(updated[i].cloneNode(true));else patch(old[i],updated[i]);
  }
 }
 const fresh=document.createElement('div');fresh.id='content';fresh.innerHTML=html;patch($('#content'),fresh);
}
renderers.overview=async function(token){
 const d=await api(endpoint('dashboard'));if(token!==epoch)return;
 const stats=[['Hosts',d.hosts,searchLink()],['IP addresses',d.addresses,searchLink('','ip')],['Current open services',d.services,searchLink('has:ports')],['Potential host/CVE pairs',d.potential,'#findings?state=potential']];
 putOverview(`<div class="overview-status"><span id="enrichment-progress" class="micro"></span>${d.active_jobs.length?`<a class="running-jobs" href="#jobs">${d.active_jobs.length} ACTIVE SCAN${d.active_jobs.length===1?'':'S'}</a>`:'<span class="micro">SCAN QUEUE IDLE</span>'}</div>
 <section class="overview-transmission"><div class="transmission-mark"><b>SURFACE</b><span>INDEX // ${fmt(d.hosts)}</span></div><pre><span>hosts</span> ${fmt(d.hosts)}   <span>addresses</span> ${fmt(d.addresses)}   <span>open.service</span> ${fmt(d.services)}   <span>review.queue</span> ${fmt(d.review)}\n<em>projection current</em> :: evidence retained :: analyst decisions preserved</pre></section>
 <div class="stats overview-register">${stats.map(([label,n,url])=>`<a class="stat" href="${url}"><span class="stat-label">${label}</span><strong>${fmt(n)}</strong></a>`).join('')}</div>
 <div class="overview-primary"><section class="map-register"><div class="console-heading"><div><span class="micro">INFRASTRUCTURE POSITION</span><h2>IP locations</h2></div><span class="micro">${fmt(d.locations.length)} RECORDS</span></div><div id="overview-map" class="host-globe"></div></section><section class="coverage-register"><div class="console-heading"><div><span class="micro">CURRENT PROJECTION</span><h2>Coverage</h2></div></div><div class="coverage-list">${['unscanned','passive','active','scanned'].map(c=>`<a href="${searchLink('coverage:'+c)}"><span>${coverageLabel(c)}</span><strong>${fmt(d.coverage[c])}</strong></a>`).join('')}<a href="#findings?state=confirmed"><span>Confirmed vulnerabilities</span><strong class="risk-confirmed">${d.confirmed}</strong></a><a href="#findings?state=all"><span>Awaiting review</span><strong>${d.review}</strong></a></div></section></div>
 ${d.active_jobs.length?`<section class="overview-section"><div class="console-heading"><h2>Active scans</h2><button class="primary" data-action="new-job">New scan</button></div>${jobRows(d.active_jobs)}</section>`:''}
 <div class="overview-grid"><section class="overview-section"><div class="console-heading"><span class="micro">LATEST COMMANDS</span><h2>Recent scans</h2></div>${jobRows(d.jobs)}</section><section class="overview-section"><div class="console-heading"><span class="micro">RECENTLY RESOLVED</span><h2>New hosts</h2></div>${table(['HOST','FIRST IMPORTED'],d.new_hosts.map(a=>`<tr><td><a class="text-link" href="${hostLink(a.id)}">${esc(a.value)}</a></td><td>${esc(stamp(a.first_seen))}</td></tr>`).join(''))}</section><section class="overview-section"><div class="console-heading"><span class="micro">OPEN SERVICE DELTA</span><h2>New endpoints</h2></div>${table(['HOST','ENDPOINT'],d.new_services.map(s=>`<tr><td><a class="text-link" href="${hostLink(s.id)}">${esc(s.value)}</a></td><td>${s.port}/${esc(s.protocol)}</td></tr>`).join(''))}</section><section class="overview-section"><div class="console-heading"><span class="micro">SOURCE INTAKE</span><h2>Recent imports</h2></div>${table(['FILE','STATUS','RECORDS'],d.imports.map(i=>`<tr><td><a class="text-link" href="#records?import_id=${i.id}">${esc(i.filename)}</a></td><td>${badge(i.status)}</td><td>${fmt(i.record_count)}</td></tr>`).join(''))}</section>${d.new_findings.length?`<section class="overview-section"><div class="console-heading"><span class="micro">ANALYST QUEUE</span><h2>Latest review items</h2></div>${findingTable(d.new_findings)}</section>`:''}</div>`,token);if(token===epoch){await VandalMap.render($('#overview-map'),d.locations);}await refreshEnrichment();
};
// Search controls carry the query through pagination and saved views.
document.addEventListener('submit',e=>{if(e.target.id==='review-search'){e.preventDefault();navigate('findings',{...params,...Object.fromEntries(new FormData(e.target))});return}if(e.target.id!=='inventory-search')return;e.preventDefault();const v=Object.fromEntries(new FormData(e.target));navigate(page,{...v,sort:params.sort||'address'})});
document.addEventListener('change',e=>{if(e.target.id==='inventory-mode'){navigate('explore',{...params,q:searchText(),mode:e.target.value,sort:params.sort||'address',page:1})}if(e.target.id==='inventory-sort')navigate(page,{...params,q:searchText(),sort:e.target.value,page:1})});
document.addEventListener('click',async e=>{const t=e.target.closest('button,a');if(!t)return;try{
 if(t.dataset.searchAdd){navigate(page,{...params,q:[searchText(),t.dataset.searchAdd].filter(Boolean).join(' '),page:1})}
 if(t.dataset.searchRemove!==undefined){const tokens=inventoryPage.tokens.filter((_,i)=>i!==Number(t.dataset.searchRemove));navigate(page,{...params,q:tokens.map(t=>t.negative?'-':'').map((_,i)=>{const t=tokens[i];return (t.negative?'-':'')+(t.key==='text'?'':t.key+':')+JSON.stringify(t.value)}).join(' '),page:1})}
 if(t.dataset.hostScan){selected.clear();selected.set(Number(t.dataset.hostScan),t.dataset.hostValue);await jobComposer()}
 if(t.hasAttribute('data-load-views')){const views=await api(endpoint('views'));drawer('<h2>Saved views</h2>'+views.map(v=>`<p><a class="tag" href="#explore?${esc(new URLSearchParams(parse(v.filters)))}" data-action="close-drawer">${esc(v.name)}</a></p>`).join(''))}
}catch(err){toast(err.message)}});


let hostPaneEpoch=0,hostPaneFocus=null;
function closeHostPane(){hostPaneEpoch++;$('#host-pane').hidden=true;$('#host-pane-shade').hidden=true;document.body.style.overflow='';hostPaneFocus?.focus()}
$('#host-pane-close').onclick=closeHostPane;$('#host-pane-shade').onclick=closeHostPane;
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!$('#host-pane').hidden&&$('#drawer').hidden)closeHostPane()});
function cveHtml(cve,entry){
 const result=parse(entry.result||'{}');
 if(!result.id)return `<section class="cve-detail"><h3>${esc(cve)}</h3><p>${esc(entry.status==='failed'?'Lookup failed; background retry scheduled':entry.status==='running'?'Fetching CVE record…':'CVE details queued…')}</p></section>`;
 return `<section class="cve-detail"><div class="row-between"><h3>${esc(cve)}</h3>${badge(result.state)}</div>${result.title?`<p>${esc(result.title)}</p>`:''}<p>${esc(result.description||'No description provided')}</p><div>${(result.scores||[]).map(s=>badge('CVSS '+s.version+' / '+s.baseScore+' / '+(s.baseSeverity||s.source))).join('')}</div><p class="micro">${esc(result.source)} · Updated ${esc(result.modified)} · Retrieved ${esc(entry.updated_at)}</p><details><summary>Affected products and versions</summary><pre>${esc(JSON.stringify(result.affected,null,2))}</pre></details><details><summary>References</summary>${(result.references||[]).filter(u=>/^https?:\/\//.test(u)).map(u=>`<p><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a></p>`).join('')}</details></section>`;
}
function updateCveSlot(slot,entry){
 slot.innerHTML=cveHtml(slot.dataset.cveEntry,entry);slot.dataset.status=entry.status;
 const row=slot.closest('details.inline-cve');if(!row)return;
 const result=parse(entry.result||'{}');
 const scores=(result.scores||[]).map(s=>s.baseScore==null?-1:Number(s.baseScore)).filter(s=>Number.isFinite(s)&&s>=0&&s<=10);
 const score=scores.length?Math.max(...scores):-1;row.dataset.score=score;
 row.querySelector(':scope > summary').textContent=slot.dataset.cveEntry+' · '+(score<0?'Unscored':'CVSS '+score)+(result.title?' · '+result.title:'');
 const parent=row.parentElement;
 [...parent.querySelectorAll(':scope > details.inline-cve')].sort((a,b)=>Number(b.dataset.score)-Number(a.dataset.score)||a.dataset.cve.localeCompare(b.dataset.cve)).forEach(r=>parent.append(r));
}
async function loadCves(selector,findings){
 const node=$(selector);if(!node)return;
 const cves=[...new Set(findings.flatMap(f=>f.title.match(/CVE-\d{4}-\d{4,}/g)||[]))];
 if(!cves.length)return;
 node.innerHTML='<div class="subheading">CVEs · Highest CVSS first</div><div class="form-actions"><button type="button" data-cve-expand>Expand all</button><button type="button" data-cve-collapse>Collapse all</button></div>'+cves.map(c=>`<details class="inline-cve" data-score="-1" data-cve="${esc(c)}"><summary>${esc(c)} · Loading</summary><section data-cve-entry="${esc(c)}">${esc(c)} · loading</section>${selector==='#host-cves'?findings.filter(f=>f.title.includes(c)).map(f=>`<p>${badge(f.confirmed?'confirmed':'potential')} ${esc(f.status)} · <a class="text-link" href="#" data-finding="${f.id}">Review finding</a></p>`).join(''):''}</details>`).join('');
 node.querySelector('[data-cve-expand]').onclick=()=>node.querySelectorAll(':scope > details.inline-cve').forEach(r=>r.open=true);
 node.querySelector('[data-cve-collapse]').onclick=()=>node.querySelectorAll(':scope > details.inline-cve').forEach(r=>r.open=false);
 await Promise.all(cves.map(async c=>{try{const d=await api(endpoint('cves/'+c));if(node.isConnected){const slot=node.querySelector(`[data-cve-entry="${c}"]`);if(slot)updateCveSlot(slot,d)}}catch(e){if(node.isConnected){const slot=node.querySelector(`[data-cve-entry="${c}"]`);if(slot){slot.textContent=c+' · '+e.message;slot.closest('details').querySelector('summary').textContent=c+' · Lookup unavailable'}}}}));
}
async function openHostPane(id){
 const token=++hostPaneEpoch;if($('#host-pane').hidden)hostPaneFocus=document.activeElement;
 $('#host-pane').hidden=false;$('#host-pane-shade').hidden=false;document.body.style.overflow='hidden';$('#host-pane-close').focus();
 $('#host-pane-content').innerHTML='<p class="loading">Loading host…</p>';
 try{
 const a=await api(endpoint('inventory/'+id));if(token!==hostPaneEpoch)return;
 a.services.sort((x,y)=>Number(y.state==='open')-Number(x.state==='open')||x.port-y.port);const names=a.associated.filter(r=>r.kind==='hostname'),ips=a.associated.filter(r=>r.kind==='ip');
 const links=list=>list.map(r=>`<a href="${hostLink(r.id)}">${esc(r.value)}</a>`).join('<br>')||'—';
 $('#host-pane-content').innerHTML=`<header class="host-pane-header"><div class="eyebrow">${esc(a.kind)} / ${esc(a.scope)}</div><h2>${esc(a.value)}</h2><p>${coverageLabel(a.coverage)} · Last observation ${esc(stamp(a.last_seen))}</p><div class="form-actions">${a.kind==='ip'?`<button class="primary" data-quick-scan="${a.id}">Scope + Nmap</button>`:`<button class="primary" data-host-scan="${a.id}" data-host-value="${esc(a.value)}">New scan</button>`}<button class="quiet" data-interest-asset="${a.id}">Add review item</button></div></header>
 <div class="host-pane-grid"><div class="host-facts"><section class="panel"><div class="panel-head"><h3>General information</h3></div><dl class="pane-facts"><dt>Hostnames</dt><dd>${a.kind==='hostname'?esc(a.value)+(names.length?'<br>'+links(names):''):links(names)}</dd><dt>IP addresses</dt><dd>${a.kind==='ip'?esc(a.value):links(ips)}</dd><dt>Domain</dt><dd>${esc(a.domain)||'—'}</dd><dt>Organization</dt><dd>${esc(a.provider)||'Unknown'}</dd><dt>ASN</dt><dd>${esc(a.asn)||'Unknown'}</dd><dt>Country / city</dt><dd>${esc(a.country)} / ${esc(a.city)||'—'}</dd><dt>Coordinates</dt><dd>${a.latitude??'—'}, ${a.longitude??'—'}</dd><dt>Location source</dt><dd>${esc(a.geo_source)||(a.kind==='hostname'?'See associated IPs':'Pending geolocation')}</dd><dt>Last scan</dt><dd>${esc(stamp(a.last_scan))}</dd><dt>Sources</dt><dd>${a.sources.map(esc).join(', ')}</dd></dl></section>
 <section class="panel"><div class="panel-head"><h3>Vulnerabilities / review</h3></div><div class="panel-body"><div id="host-cves"></div>${a.findings.filter(f=>! /CVE-\d{4}-\d{4,}/.test(f.title)).map(f=>`<p><a class="text-link" href="#" data-finding="${f.id}">${esc(f.title)}</a></p>`).join('')}${!a.findings.length?'<p>No claims on this asset.</p>':''}</div></section>
 <details><summary>Notes and tags</summary><form id="asset-form" data-id="${a.id}"><label>Tags<input name="tags" value="${esc(a.tags)}"></label><label>Notes<textarea name="notes">${esc(a.notes)}</textarea></label><button class="primary">Save</button></form></details></div>
 <div class="host-services"><section class="panel"><div class="panel-head"><h3>Observed ports</h3></div><div class="panel-body service-strip">${a.services.map(s=>`<button class="quiet" data-pane-endpoint="ep-${s.owner_id}-${s.protocol}-${s.port}">${s.port}/${esc(s.protocol)} ${esc(s.state)}</button>`).join('')||'No port observations'}</div></section>
 ${a.services.map(s=>`<section class="panel" id="ep-${s.owner_id}-${s.protocol}-${s.port}"><div class="panel-head"><h3>${s.port}/${esc(s.protocol)} · ${esc(s.service||'Unknown service')}</h3>${badge(s.state)}</div><div class="panel-body"><div class="row-between"><span>${esc(s.owner)}</span><span>${esc(s.evidence)} · ${esc(stamp(s.observed_at))}</span></div><h3>${esc(s.product)}</h3><pre class="host-banner">${esc(s.banner||'No source output')}</pre><a class="text-link" href="#" data-record="${s.record_id}">Source record</a> <button class="quiet" data-port-owner="${s.owner_id}" data-port="${s.port}" data-protocol="${esc(s.protocol)}">${s.count} observations${s.conflict?' · states differ':''}</button></div></section>`).join('')}
 <details><summary>Scan history (${a.jobs.length})</summary>${jobRows(a.jobs)}<a href="#records?asset_id=${a.id}" data-leave-host>All source records →</a></details></div></div>`;
 confirmedHostPanel($('#host-pane-content .host-pane-header'),a);
 $('#host-pane').scrollTop=0;loadCves('#host-cves',a.findings);
 }catch(e){if(token===hostPaneEpoch)$('#host-pane-content').innerHTML=empty('Could not load host',e.message)}
}
document.addEventListener('click',e=>{const a=e.target.closest('a,button');if(!a)return;
 if(a.hasAttribute('data-leave-host'))closeHostPane();
 if(a.dataset.paneEndpoint){document.getElementById(a.dataset.paneEndpoint)?.scrollIntoView({behavior:'smooth',block:'start'});return}
 if(a.tagName==='A'&&a.getAttribute('href')?.startsWith('#host?')){e.preventDefault();e.stopImmediatePropagation();const id=Number(new URLSearchParams(a.getAttribute('href').split('?')[1]).get('id'));closeDrawer();openHostPane(id)}
},true);
async function refreshEnrichment(){const node=$('#enrichment-progress');if(!node)return;try{const stats=await api(endpoint('enrichment'));if(node.isConnected)node.textContent='Background metadata · '+stats.map(s=>`${s.kind==='geo'?'Location':'CVE'} ${s.status}: ${s.count}`).join(' · ')}catch{}}
setInterval(async()=>{if(!session||document.hidden)return;refreshEnrichment();for(const slot of document.querySelectorAll('[data-cve-entry]')){if(slot.dataset.status==='completed')continue;try{const d=await api(endpoint('cves/'+slot.dataset.cveEntry));if(slot.isConnected)updateCveSlot(slot,d)}catch{}}},10000);
renderers.scope=async function(token){
 const rules=await api(endpoint('scope'));
 put(`<section class="panel dark-panel"><div class="panel-head"><h3>Scope rules</h3></div><form id="bulk-scope-form" class="panel-body"><label>ACTION<select name="action"><option value="exclude">Exclude and hide</option><option value="include">Include</option></select></label><label>TARGETS<textarea name="targets" required placeholder="example.com&#10;192.0.2.0/24&#10;192.0.2.10-192.0.2.40"></textarea></label><label>LOAD TEXT FILE<input type="file" id="scope-list-file" accept=".txt,.csv,text/plain,text/csv"></label><p class="micro">One entry per line, or separated by commas. Domains include subdomains. Exclusions hide matching assets and linked evidence; removing a rule restores visibility.</p><label>REASON<input name="reason" placeholder="EPT coverage"></label><button class="primary">Preview rules</button><div id="scope-preview"></div></form></section>${table(['ACTION','TARGET','REASON',''],rules.map(r=>`<tr><td>${badge(r.action)}</td><td>${esc(r.target)}</td><td>${esc(r.reason)}</td><td><button class="quiet" data-remove-scope="${r.id}">Remove</button></td></tr>`).join(''))}`,token);
 const form=$('#bulk-scope-form');if(!form)return;
 form.oninput=()=>{$('#scope-preview').innerHTML=''};
 $('#scope-list-file').onchange=async e=>{try{const file=e.target.files[0];if(!file)return;if(file.size>1024*1024)throw Error('File exceeds 1 MiB');form.elements.targets.value=[form.elements.targets.value,await file.text()].filter(Boolean).join('\n');$('#scope-preview').innerHTML=''}catch(err){toast(err.message)}};
 form.onsubmit=async e=>{e.preventDefault();try{
  const body=Object.fromEntries(new FormData(form));const preview=await api(endpoint('scope'),{method:'POST',body:{...body,preview:true}});
  $('#scope-preview').innerHTML=`<p>${preview.targets.length} rules · ${preview.matched_assets} matching assets</p><details><summary>Normalized rules</summary><pre>${esc(preview.targets.join('\n'))}</pre></details><button type="button" class="primary" id="apply-scope">Apply ${esc(body.action)} rules</button>`;
  $('#apply-scope').onclick=async e=>{e.target.disabled=true;try{const r=await api(endpoint('scope'),{method:'POST',body});selected.clear();closeHostPane();closeDrawer();toast(`${r.added} rules added`);await route()}catch(err){e.target.disabled=false;toast(err.message)}};
 }catch(err){toast(err.message)}};
};
// host-workspace.js mounts the shared browsing workspace before starting.
