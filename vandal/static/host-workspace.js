'use strict';
// Browsing-only current-state API. Scan composers and source-record editors keep
// their existing APIs and stable IDs.
const evidenceApi=api;
api=async function(path,options={}){
 if(!options.method||options.method==='GET'){
  path=path.replace(/(\/api\/e\/\d+)\/inventory(?=\/|\?|$)/,'$1/hosts');
  if(/^\/api\/e\/\d+\/(hosts(?:\/\d+)?|host-vulnerabilities|dashboard)(?:\?|$)/.test(path)){
   const url=new URL(path,location.origin);
   if(hidePassive)url.searchParams.set('hide_passive','1');
   if(url.pathname.endsWith('/dashboard'))url.searchParams.set('view','current');
   path=url.pathname+url.search;
  }
 }
 return evidenceApi(path,options);
};

const workspaceViews=new Set(['explore','domains','web','findings']);
const originalRoute=route,originalPut=put;
let workspaceRoot=null,workspaceEid=null;
const viewState=new Map();
function workspaceTabs(){return `<div class="workspace-bar"><nav class="workspace-tabs" aria-label="Explore views">${[['explore','Hosts'],['domains','Domains'],['web','Web'],['findings','Vulnerabilities']].map(([v,label])=>`<a href="#${v}" data-workspace-view="${v}">${label}</a>`).join('')}</nav><div class="workspace-preferences" data-workspace-preferences></div></div>`}
put=function(html,token){
 if(workspaceRoot?.isConnected&&workspaceViews.has(page)&&token===epoch){
  const target=workspaceRoot.querySelector(`[data-workspace-body="${page}"]`);if(target){target.innerHTML=html;return true}
 }
 return originalPut(html,token);
};
route=async function(){
 const name=location.hash.slice(1).split('?')[0]||'overview';
 if(workspaceRoot?.isConnected&&viewState.has(page))viewState.get(page).scroll=window.scrollY;
 if(!workspaceViews.has(name)){
  passiveToggle.hidden=true;
  if(workspaceRoot?.isConnected){$('.page-heading').insertBefore(passiveToggle,$('#page-actions'));workspaceRoot.remove();}
  return originalRoute();
 }
 const oldPage=page;
 if(workspaceViews.has(oldPage)&&viewState.has(oldPage))viewState.get(oldPage).scroll=window.scrollY;
 const token=++epoch;page=name;params=Object.fromEntries(new URLSearchParams(location.hash.split('?')[1]||''));
 window.VandalMap?.destroy();
 if(!eid)return originalRoute();
 if(workspaceEid!==eid){workspaceRoot=null;viewState.clear();workspaceEid=eid;selected.clear()}
 if(!workspaceRoot){workspaceRoot=document.createElement('section');workspaceRoot.className='explore-workspace';workspaceRoot.innerHTML=workspaceTabs()+[...workspaceViews].map(v=>`<section data-workspace-body="${v}" class="workspace-view" hidden></section>`).join('')}
 if(!workspaceRoot.isConnected)$('#content').replaceChildren(workspaceRoot);
 passiveToggle.hidden=false;workspaceRoot.querySelector('[data-workspace-preferences]').append(passiveToggle);
 $('#breadcrumb').textContent='WORKSPACE / EXPLORE';$('#page-title').textContent='Explore';$('#page-actions').innerHTML=name==='findings'?'<button class="primary" data-action="new-finding">+ Item of interest</button>':'';
 document.querySelectorAll('.rail nav a').forEach(a=>a.classList.toggle('active',a.dataset.page==='explore'));
 workspaceRoot.querySelectorAll('[data-workspace-view]').forEach(a=>a.classList.toggle('active',a.dataset.workspaceView===name));
 workspaceRoot.querySelectorAll('[data-workspace-body]').forEach(a=>a.hidden=a.dataset.workspaceBody!==name);
 const previous=viewState.get(name),emptyParams=!Object.keys(params).length;
 if(previous&&oldPage!==name&&emptyParams){params={...previous.params};history.replaceState(null,'','#'+name+'?'+new URLSearchParams(params))}
 const key=JSON.stringify({eid,hidePassive,...params});
 if(previous?.key===key&&!params.refresh){if(name==='explore'){hostListQuery=previous.listQuery;hostListData=previous.listData}window.scrollTo(0,previous.scroll||0);return}
 const target=workspaceRoot.querySelector(`[data-workspace-body="${name}"]`);target.setAttribute('aria-busy','true');
 try{await renderers[name](token);if(token===epoch){viewState.set(name,{key,params:{...params},scroll:oldPage===name?window.scrollY:0,listQuery:hostListQuery,listData:hostListData});if(oldPage!==name)window.scrollTo(0,previous?.scroll||0)}}catch(e){if(token===epoch)put(empty('Unable to load',e.message),token)}finally{target.removeAttribute('aria-busy')}
};
function invalidateWorkspace(){viewState.clear()}
// Existing save/toggle flows call route; invalidate cached views after writes.
const projectedApi=api;
api=async function(path,options={}){const result=await projectedApi(path,options);if(options.method&&options.method!=='GET')invalidateWorkspace();return result};

let hostListData=null,hostListQuery=null,hostListVersion=null,listRequest=0;
function groupPort(s){return `<a class="service-pill" href="${hostLink(s.host_id||s.owner_id)}">${s.port}/${esc(s.protocol)} <span>${esc(s.service||s.state)}</span>${s.variants?.length>1?` <small>${s.variants.length} owners</small>`:''}</a>`}
function hostCard(a){
 const view=a.address_view,ports=a.services.filter(s=>s.state==='open');
 const ip=view.primary_ip||'No validated address';
 const risk=[a.confirmed?`<strong class="risk-confirmed">${a.confirmed} confirmed</strong>`:'',a.potential?`${a.potential} potential`:'' ].filter(Boolean).join(' · ')||'<span class="muted">No CVE claims</span>';
 return `<article class="host-result current-host" data-host-row="${a.id}">
 <div class="host-select"><input type="checkbox" data-select="${a.id}" data-value="${esc(a.value)}" ${selected.has(a.id)?'checked':''} aria-label="Select ${esc(a.value)}"></div>
 <div class="host-identity result-header"><h2><a href="${hostLink(a.id)}">${esc(a.value)}</a></h2><div>${esc(ip)}${view.addresses.length>1?` <span class="muted">+${view.addresses.length-1}</span>`:''} <span class="address-state">${esc(view.status)}</span></div><small>${esc(a.provider||'Organization unknown')} · ${esc(a.country||'Unknown')}</small></div>
 <div class="host-service-cell"><div class="service-strip">${ports.slice(0,6).map(s=>groupPort({...s,host_id:a.id})).join('')||'<span class="muted">No open-service evidence</span>'}${ports.length>6?`<a href="${hostLink(a.id)}">+${ports.length-6}</a>`:''}</div></div>
 <div class="host-risk-cell">${risk}<small>${coverageLabel(a.coverage)} · ${esc(stamp(a.last_scan))}</small></div>
 <a class="host-open" href="${hostLink(a.id)}" aria-label="Open ${esc(a.value)}">→</a></article>`;
}
function currentFacets(data){
 const labels={domain:'Domain',country:'Country',coverage:'Coverage',scope:'Scope',org:'Organization',cve:'CVE',port:'Open port',service:'Service',source:'Source'};
 return Object.entries(data.facets).map(([key,values])=>{
  const rows=entries=>entries.map(([value,count])=>`<button class="facet-value" data-search-add="${esc((key==='domain'?'hostname':key)+':'+JSON.stringify(String(value)))}"><span>${esc(value)}${key==='cve'?`<small> · ${data.cve_scores[value]>=0?'CVSS '+data.cve_scores[value]:'Unscored'}</small>`:''}</span><b>${fmt(count)}</b></button>`).join('');
  return `<details class="facet" ${['domain','port','coverage'].includes(key)?'open':''}><summary>${labels[key]}</summary>${rows(values.slice(0,8))||'<p class="muted">No values</p>'}${values.length>8?`<details><summary>Show all ${values.length}</summary>${rows(values.slice(8))}</details>`:''}</details>`;
 }).join('');
}
function listPager(data){return `<div class="pagination"><span>${fmt(data.total)} hosts · Page ${data.page}</span><div><button type="button" data-host-page="${data.page-1}" ${data.page<=1?'disabled':''}>← Previous</button><button type="button" data-host-more ${data.page*data.size>=data.total?'disabled':''}>Load more</button><button type="button" data-host-page="${data.page+1}" ${data.page*data.size>=data.total?'disabled':''}>Next →</button></div></div>`}
renderers.explore=async function(token){
 const q=searchText(),mode=params.mode||'auto',size=Number(params.size)||25;
 const query={q,mode,size,sort:params.sort||'address',page:params.page||1};hostListQuery=query;
 const data=await api(endpoint('hosts?'+new URLSearchParams(query)));if(token!==epoch)return;
 hostListData=data;inventoryPage.tokens=data.tokens;
 const exportUrl=endpoint('hosts-export?'+new URLSearchParams({...query,hide_passive:hidePassive?'1':'0'}));
 put(`<form id="current-host-search" class="toolbar"><input name="q" class="search" aria-label="Search hosts" placeholder="hostname:example.com port:443" value="${esc(q)}"><button class="primary">Search</button><a class="tag" href="${esc(exportUrl)}">Export CSV</a></form>
 <details class="search-help"><summary>Search syntax</summary><p>Search current evidence. Examples: <code>hostname:example.com port:443 has:vuln country:"United States" coverage:scanned</code>. Previous observations are under each host's History.</p></details>
 <div class="query-chips">${data.tokens.map((t,i)=>`<button class="quiet" data-search-remove="${i}">${esc(t.text)} ×</button>`).join('')}</div>
 <div class="toolbar inventory-controls"><span>${fmt(data.total)} hosts</span><label>Identity<select id="inventory-mode">${[['auto','Hostname first'],['ip','IP addresses'],['hostname','Hostnames only']].map(([v,l])=>`<option value="${v}" ${mode===v?'selected':''}>${l}</option>`).join('')}</select></label><label>Sort<select id="inventory-sort">${[['address','Host'],['recent','Latest evidence'],['vulns','Vulnerability count'],['open_ports','Most open ports']].map(([v,l])=>`<option value="${v}" ${query.sort===v?'selected':''}>${l}</option>`).join('')}</select></label><label>Per page<select id="host-page-size">${[25,50,100].map(n=>`<option ${size===n?'selected':''}>${n}</option>`).join('')}</select></label><span id="selection-count">${selected.size} selected</span><button class="quiet" data-action="new-job">Scan selection</button><button class="quiet" data-action="save-view">Save view</button><button class="quiet" data-load-views>Saved views</button></div>
 <button id="host-updates" class="secondary" hidden>New evidence available · Refresh results</button>
 <button id="facet-toggle" class="quiet" type="button" aria-expanded="false">Filters · ${Object.values(data.facets).filter(v=>v.length).length} groups</button>
 <div class="inventory-layout"><aside class="facet-panel" id="facet-panel">${currentFacets(data)}</aside><div><div class="host-ledger-head" aria-hidden="true"><span>Host / current identity</span><span>Open services</span><span>Risk / latest evidence</span></div><div id="current-host-list">${data.items.map(hostCard).join('')||empty('No matching hosts','Adjust the filters or import evidence.')}</div><div id="current-host-pager">${listPager(data)}</div></div></div>`,token);
 try{hostListVersion=(await api(endpoint('projection-version'))).version}catch{}
};
document.addEventListener('submit',e=>{if(e.target.id==='current-host-search'){e.preventDefault();navigate('explore',{...params,q:e.target.elements.q.value,page:1})}});
document.addEventListener('change',e=>{if(e.target.id==='host-page-size')navigate('explore',{...params,size:e.target.value,page:1})});
document.addEventListener('click',async e=>{
 const t=e.target.closest('button,a');if(!t)return;
 if(t.dataset.hostPage){navigate('explore',{...params,page:Number(t.dataset.hostPage)});return}
 if(t.id==='facet-toggle'){const panel=$('#facet-panel'),open=panel.classList.toggle('mobile-open');t.setAttribute('aria-expanded',String(open));t.textContent=(open?'Hide filters':'Filters')+' · '+panel.querySelectorAll(':scope > .facet').length+' groups';return}
 if(t.id==='host-updates'){invalidateWorkspace();await route();return}
 if(t.hasAttribute('data-host-more')){
  const token=epoch,request=++listRequest;t.disabled=true;
  try{const data=await api(endpoint('hosts?'+new URLSearchParams({...hostListQuery,page:hostListData.page+1})));if(token!==epoch||request!==listRequest)return;
   const existing=new Set([...document.querySelectorAll('[data-host-row]')].map(n=>Number(n.dataset.hostRow)));
   $('#current-host-list').insertAdjacentHTML('beforeend',data.items.filter(a=>!existing.has(a.id)).map(hostCard).join(''));hostListData=data;
   $('#current-host-pager').innerHTML=listPager(data);if(viewState.has('explore'))viewState.get('explore').listData=data;
  }catch(err){toast(err.message);if(t.isConnected)t.disabled=false}
 }
});
setInterval(async()=>{
 if(!session||page!=='explore'||document.hidden||!$('#host-updates'))return;
 try{const value=(await api(endpoint('projection-version'))).version;if(hostListVersion&&value!==hostListVersion)$('#host-updates').hidden=false}catch{}
},10000);

function claimLinks(claims){return claims.map(f=>`<article class="claim"><a class="text-link" href="#" data-finding="${f.id}">${esc(f.actor||'Source')} · Review #${f.id}</a> ${badge(f.confirmed?'confirmed':f.status)}${f.notes?`<p>${esc(f.notes)}</p>`:''}<div>${parse(f.evidence).map(id=>`<a class="tag" href="#" data-record="${id}">Evidence #${id}</a>`).join(' ')}</div></article>`).join('')}
function vulnerabilityGroup(g){return `<details class="vulnerability-group ${g.confirmed?'confirmed':''}" data-vulnerability="${esc(g.cve)}"><summary><strong>${esc(g.cve)}</strong> ${badge(g.status)} <span>${g.score==null?'Unscored':'CVSS '+g.score} · ${g.claims.length} source claim${g.claims.length===1?'':'s'}</span></summary>${g.decision_conflict?'<p class="notice">Source items contain differing analyst decisions; review each claim.</p>':''}<section data-cve-entry="${esc(g.cve)}">CVE details load when expanded.</section>${claimLinks(g.claims)}</details>`}
document.addEventListener('toggle',async e=>{const row=e.target;if(!row.matches?.('[data-vulnerability]')||!row.open)return;const slot=row.querySelector('[data-cve-entry]');if(slot.dataset.status)return;slot.dataset.status='loading';try{const result=await api(endpoint('cves/'+row.dataset.vulnerability));if(slot.isConnected)updateCveSlot(slot,result)}catch(err){slot.dataset.status='failed';slot.textContent=err.message}},true);
renderers.findings=async function(token){
 const data=await api(endpoint('host-vulnerabilities?'+new URLSearchParams({q:params.q||'',state:params.state||'all'})));
 if(token!==epoch)return;$('#page-actions').innerHTML='<button class="primary" data-action="new-finding">+ Item of interest</button>';
 put(`<form id="current-vuln-search" class="toolbar"><input class="search" name="q" value="${esc(params.q||'')}" placeholder="Host, CVE or notes"><select name="state">${[['all','All'],['confirmed','Confirmed'],['potential','Potential CVEs'],['interests','Other items'],['dismissed','Dismissed']].map(([v,l])=>`<option value="${v}" ${params.state===v?'selected':''}>${l}</option>`).join('')}</select><button class="primary">Filter</button></form><p class="micro">${data.total} groups · ${data.cve_pairs} host/CVE pairs · Highest CVSS first</p>${data.items.map(a=>`<section class="host-vulnerability-group"><h2>${a.id?`<a href="${hostLink(a.id)}">${esc(a.value)}</a>`:esc(a.value)}</h2>${a.vulnerabilities.map(vulnerabilityGroup).join('')}${a.other_findings.length?`<details><summary>Other analyst items (${a.other_findings.length})</summary>${claimLinks(a.other_findings)}</details>`:''}</section>`).join('')||empty('No matching items','Change the filters.')}`,token);
};
document.addEventListener('submit',e=>{if(e.target.id==='current-vuln-search'){e.preventDefault();navigate('findings',Object.fromEntries(new FormData(e.target)))}});

function serviceGroup(s,hostId){return `<details class="current-service" id="current-service-${s.protocol}-${s.port}"><summary><strong>${s.port}/${esc(s.protocol)}</strong> ${badge(s.state)} <span>${esc(s.service||'Service unknown')} · ${s.variants.length} owner${s.variants.length===1?'':'s'}</span></summary>${s.variants.map(v=>`<section class="service-variant"><h3>${esc(v.owner)} · ${esc(v.service||'Unknown service')}</h3><p>${badge(v.evidence)} · ${esc(stamp(v.observed_at))}</p><p>${esc(v.product)}</p><pre class="host-banner">${esc(v.banner||'No source output')}</pre><a class="text-link" href="#" data-record="${v.record_id}">Current evidence #${v.record_id}</a></section>`).join('')}<p class="micro">${s.count} retained observations. See History for superseded evidence.</p></details>`}
function hostHistory(a){return `<details class="host-history"><summary>History · ${a.service_history.length} service observations · ${a.address_view.history.length} address records</summary><h3>Address history</h3>${table(['WHEN','SOURCE','ADDRESSES','STATUS'],a.address_view.history.map(r=>`<tr><td>${esc(stamp(r.at))}<br>${esc(r.time_basis)}</td><td><a class="text-link" href="#" data-record="${r.record_id}">${esc(r.source)}</a></td><td>${r.ips.map(ip=>esc(ip.value)).join('<br>')||'No addresses'}</td><td>${esc(r.reason)}${r.error?'<br>'+esc(r.error):''}</td></tr>`).join(''))}<h3>Service evidence</h3>${table(['WHEN / OWNER','SERVICE','STATE','WHY'],a.service_history.map(r=>`<tr><td>${esc(stamp(r.observed_at))}<br>${esc(r.owner)}</td><td><a class="text-link" href="#" data-record="${r.record_id}">${r.port}/${esc(r.protocol)} ${esc(r.service)}</a></td><td>${esc(r.state)} · ${esc(r.evidence)}</td><td>${esc(r.reason)}</td></tr>`).join(''))}${a.finding_history.length?`<h3>Archived passive claims</h3>${claimLinks(a.finding_history)}`:''}<a href="#records?asset_id=${a.id}" data-leave-host>All source records →</a></details>`}
openHostPane=async function(id){
 const token=++hostPaneEpoch;if($('#host-pane').hidden)hostPaneFocus=document.activeElement;
 $('#host-pane').hidden=false;$('#host-pane-shade').hidden=false;document.body.style.overflow='hidden';$('#host-pane-close').focus();
 $('#host-pane-content').innerHTML='<p class="loading">Loading current host…</p>';
 try{
  const a=await api(endpoint('hosts/'+id));if(token!==hostPaneEpoch)return;
  const vulnerabilities=[...a.vulnerabilities].sort((x,y)=>Number(y.confirmed)-Number(x.confirmed)||(y.score??-1)-(x.score??-1)||x.cve.localeCompare(y.cve));
  const confirmed=vulnerabilities.filter(g=>g.confirmed),manual=a.other_findings.filter(f=>f.confirmed&&f.status!=='dismissed');
  const confirmedSummary=confirmed.map(g=>`<button class="confirmed-jump" type="button" data-vuln-jump="${esc(g.cve)}"><strong>${esc(g.cve)}</strong><span>${g.score==null?'Unscored':'CVSS '+g.score}</span></button>`).join('')+manual.map(f=>`<button class="confirmed-jump" type="button" data-finding="${f.id}"><strong>${esc(f.title)}</strong><span>${esc(f.priority)} priority</span></button>`).join('');
  $('#host-pane-content').innerHTML=`<div class="host-top-row"><header class="host-pane-header"><div class="eyebrow">HOST #${a.id} · ${esc(a.scope)}</div><h2>${esc(a.value)}</h2><div class="host-register"><span>${coverageLabel(a.coverage)}</span><span>${a.open_port_count} open services</span><span>${esc(a.address_view.primary_ip||'Unresolved')}</span><span>${esc(a.address_view.status)}</span></div><div class="form-actions"><button class="quiet" data-interest-asset="${a.id}">Add item</button><button class="quiet" data-reload-host="${a.id}">Refresh</button>${a.kind==='hostname'?`<button class="quiet" data-sync-dns="${esc(a.value)}">Sync DNS</button>`:''}</div></header><aside class="host-confirmed ${confirmed.length||manual.length?'has-confirmed':''}"><h3>Confirmed vulnerabilities <span>${confirmed.length+manual.length}</span></h3>${confirmedSummary||'<p class="muted">None confirmed.</p>'}</aside></div>
  <div class="host-pane-grid"><div class="host-facts"><section class="panel"><div class="panel-head"><h3>Current identity</h3></div><dl class="pane-facts"><dt>Primary address</dt><dd>${esc(a.address_view.primary_ip||'Unresolved')}</dd><dt>Addresses</dt><dd>${a.address_view.addresses.map(p=>`<a href="${hostLink(p.id)}">${esc(p.value)}</a>`).join('<br>')||'—'}</dd><dt>DNS status</dt><dd>${esc(a.address_view.status)}</dd><dt>Last validated</dt><dd>${esc(stamp(a.address_view.checked_at))}</dd><dt>Organization</dt><dd>${esc(a.provider||'Unknown')}</dd><dt>Location</dt><dd>${esc(a.country||'Unknown')} / ${esc(a.city||'—')}</dd><dt>ASN</dt><dd>${esc(a.asn||'—')}</dd></dl></section><section class="panel host-vulnerability-register"><div class="panel-head"><h3>Vulnerabilities · ${vulnerabilities.length} unique CVEs</h3></div><div class="panel-body">${vulnerabilities.map(vulnerabilityGroup).join('')||'<p class="muted">No current CVE claims.</p>'}${a.other_findings.length?`<details><summary>Other items (${a.other_findings.length})</summary>${claimLinks(a.other_findings)}</details>`:''}</div></section><details><summary>Notes and tags</summary><form id="asset-form" data-id="${a.id}"><label>Tags<input name="tags" value="${esc(a.tags)}"></label><label>Notes<textarea name="notes">${esc(a.notes)}</textarea></label><button class="primary">Save</button></form></details></div>
  <div class="host-services"><section class="panel"><div class="panel-head"><h3>Current services</h3></div><div class="panel-body">${a.services.map(s=>`<a class="tag" href="#" data-current-jump="${s.protocol}-${s.port}">${s.port}/${esc(s.protocol)} · ${esc(s.state)}</a>`).join(' ')||'No current service evidence'}</div></section>${a.services.map(s=>serviceGroup(s,a.id)).join('')}${hostHistory(a)}<details><summary>Scan history (${a.jobs.length})</summary>${jobRows(a.jobs)}</details></div></div>`;
  $('#host-pane').scrollTop=0;
 }catch(e){if(token===hostPaneEpoch)$('#host-pane-content').innerHTML=empty('Could not load host',e.message)}
};
document.addEventListener('click',async e=>{
 const t=e.target.closest('a,button');if(!t)return;
 if(t.dataset.reloadHost){await openHostPane(Number(t.dataset.reloadHost));return}
 if(t.dataset.vulnJump){const row=[...document.querySelectorAll('[data-vulnerability]')].find(node=>node.dataset.vulnerability===t.dataset.vulnJump);if(row){row.open=true;row.scrollIntoView({behavior:'smooth',block:'start'})}return}
 if(t.dataset.currentJump){e.preventDefault();const node=document.getElementById('current-service-'+t.dataset.currentJump);if(node){node.open=true;node.scrollIntoView({behavior:'smooth',block:'start'})}}
},true);
// Direct links land in the workspace, with the host layered over the list.
renderers.host=async function(){const id=Number(params.id);history.replaceState(null,'','#explore');await route();await openHostPane(id)};
start();
