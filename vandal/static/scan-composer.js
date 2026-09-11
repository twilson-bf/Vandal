/* Profile-specific scan controls; all options are validated again by the server. */
jobComposer=async function(preferredProfile,context={}){
 const profiles=await api(endpoint('profiles'));
 const targetQuery=new URLSearchParams(selected.size?{ids:[...selected.keys()].join(',')}:{q:['explore','domains'].includes(page)?searchText():'',mode:page==='domains'?'hostname':params.mode||'auto'});
 if(page==='web'&&!selected.size){targetQuery.set('source','web');targetQuery.set('q',params.q||'');if(params.status)targetQuery.set('status',params.status);if(params.job_id)targetQuery.set('job_id',params.job_id)}
 const targetList=context.targets?{targets:context.targets,count:context.targets.length,source:'selection'}:await api(endpoint('scan-targets?'+targetQuery));
 const select=(name,label,items,value)=>`<label>${label}<select name="${name}">${items.map(([v,l])=>`<option value="${v}" ${v===value?'selected':''}>${l}</option>`).join('')}</select></label>`;
 const num=(name,label,value,min,max)=>`<label>${label}<input name="${name}" type="number" value="${value}" min="${min}" max="${max}" required></label>`;
 const check=(name,label)=>`<label class="checkbox"><input name="${name}" type="checkbox">${label}</label>`;
 drawer(`<div class="composer-heading"><div><span>PROCESS CONTROL // NEW</span><h2>New scan</h2></div><b>JOB / UNCOMMITTED</b></div><section class="composer-aperture"><div class="aperture-code">SCAN<br>CTRL</div><pre><i>target.buffer</i> = ${targetList.count}\n<i>source.mode</i>   = ${targetList.source==='selection'?'SELECTED':'FILTERED_SET'}\n<i>profile.state</i> = AWAITING_INPUT\n<i>execution</i>     = LOCKED_UNTIL_VALIDATED</pre></section><form id="scan-composer"><div class="form-grid">${select('profile','TOOL / PROFILE',profiles.map(p=>[p.id,p.name+(p.installed?'':' · not installed')]),'bbot-passive')}</div><p id="scan-description" class="micro"></p><label>TARGETS<textarea name="targets" required placeholder="Hostnames or IPs, one per line">${esc(targetList.targets.join('\n'))}</textarea></label><p class="micro">${targetList.count} targets from ${targetList.source==='selection'?'your selection':'all matching results, across every page'}. Edit the list to adjust this job.</p>${check('add_scope','Add entered targets to scope')}
 <fieldset data-scan-profile="nmap-services"><legend>Nmap / TCP</legend>
 ${select('preset','PRESET',[['light','Light service discovery'],['services','Detailed service discovery'],['vulns','Vulnerability review'],['custom','Custom']],'light')}
 <div class="form-grid">${select('port_mode','PORT SELECTION',[['custom','Custom ports'],['top','Most common ports'],['all','All TCP ports (1–65535)']],'custom')}<label data-port-mode="custom">PORTS<input name="ports" value="22,80,443,445,3389,8080,8443"></label><div data-port-mode="top">${num('top_ports','NUMBER OF TOP PORTS',1000,1,65535)}</div>
 ${select('service_detection','SERVICE / VERSION DETECTION',[['off','Off'],['light','Light · intensity 2'],['standard','Standard · intensity 7'],['thorough','Thorough · intensity 9']],'light')}
 ${select('host_discovery','HOST DISCOVERY',[['skip','Assume online (-Pn)'],['probe','Probe before port scan']],'skip')}
 ${select('address_family','ADDRESS FAMILY',[['auto','Automatic · IPv4 for hostnames'],['ipv4','IPv4'],['ipv6','IPv6']],'auto')}</div>
 <h3>Service & vulnerability scripts</h3>${check('service_scripts','Service metadata · HTTP, SSH, certificates, SMB')}${check('tls_checks','TLS cipher enumeration')}${check('safe_vulns','Vulnerability checks · Nmap safe/vuln category')}${check('vulners','Vulners · match detected versions to potential CVEs')}
 <p class="micro">Vulners sends software names/versions or CPEs to vulners.com. CVE matches remain unconfirmed. TLS enumeration makes additional handshakes.</p>
 <div class="form-grid">${num('min_cvss','VULNERS MINIMUM CVSS',0,0,10)}${num('script_timeout','SCRIPT TIMEOUT / SECONDS',60,5,600)}</div>
 <details><summary>Timing & limits</summary><div class="form-grid">${select('timing','TIMING TEMPLATE',[['0','T0 · Paranoid'],['1','T1 · Sneaky'],['2','T2 · Polite'],['3','T3 · Normal'],['4','T4 · Aggressive'],['5','T5 · Insane']],'3')}${num('max_rate','MAX PACKETS / SECOND',100,1,10000)}${num('max_retries','MAX RETRIES',2,0,10)}${num('host_timeout','HOST TIMEOUT / SECONDS',180,10,3600)}</div></details>
 <p class="micro">TCP connect scans run without sudo. Drafts preserve entered hostnames without a DNS lookup. Profile validation checks DNS and scope before execution.</p></fieldset>
 <fieldset data-scan-profile="bbot-passive"><legend>Passive discovery</legend>${['crt','hackertarget','rapiddns','shodan_idb'].map(m=>`<label class="checkbox"><input type="checkbox" name="source_${m}" checked>${({crt:'Certificate transparency',hackertarget:'HackerTarget',rapiddns:'RapidDNS',shodan_idb:'Shodan InternetDB · passive ports & CVEs'})[m]}</label>`).join('')}<p>DNS resolution is enabled; port observations come from providers.</p></fieldset>
 <fieldset data-scan-profile="dns-validate"><legend>DNS validation</legend><p>Compare A, AAAA and CNAME answers from Cloudflare and Google. Each resolver’s answers are retained separately.</p></fieldset>
 <fieldset data-scan-profile="httpx-web"><legend>HTTP inventory</legend><div class="form-grid">${num('rate','REQUESTS / SECOND',5,1,100)}${num('threads','CONCURRENT WORKERS',5,1,50)}${num('timeout','REQUEST TIMEOUT / SECONDS',10,1,120)}</div><p class="micro">Retains HTTP metadata and technology hints. Redirect following is disabled.</p></fieldset>
 <fieldset data-scan-profile="gowitness-web"><legend>Web capture</legend><p>Validate HTTP and HTTPS on every observed open TCP port. Capture responding URLs with gowitness, preserving hostnames for virtual hosts.</p><label class="checkbox"><input name="web_defaults" type="checkbox" checked>Also check ports 80 and 443</label>${check('full_page','Capture full-page screenshots')}<div class="form-grid">${num('web_threads','CONCURRENT WORKERS',2,1,10)}${num('probe_timeout','VALIDATION TIMEOUT / SECONDS',5,1,30)}${num('web_timeout','CAPTURE TIMEOUT / SECONDS',30,5,120)}${num('web_delay','RENDER DELAY / SECONDS',2,0,15)}</div><p class="micro">Redirects and page resources stay within this job’s candidate hosts and ports. Off-target resources are blocked. Results appear in Explore → Web.</p></fieldset>
 <button class="primary" type="submit">Generate draft</button><button class="quiet" type="button" data-open-drafts>Saved drafts</button></form><div id="job-preview"></div>`);
 const form=$('#scan-composer'),f=form.elements;
 if(selected.size&&[...selected.values()].every(v=>/^[0-9.]+$/.test(v)||v.includes(':')))f.profile.value='nmap-services';
 if(preferredProfile&&profiles.some(p=>p.id===preferredProfile))f.profile.value=preferredProfile;
 if(context.draft){const saved=context.draft.payload;f.profile.value=saved.profile;f.add_scope.checked=saved.add_scope;f.preset.value='custom';for(const [key,value] of Object.entries(saved.config)){if(key==='modules'){for(const m of ['crt','hackertarget','rapiddns','shodan_idb'])f['source_'+m].checked=Array.isArray(value)&&value.includes(m)}else if(f[key]){if(f[key].type==='checkbox')f[key].checked=value;else f[key].value=value}}}
 const update=()=>{for(const fieldset of form.querySelectorAll('[data-scan-profile]')){fieldset.hidden=fieldset.dataset.scanProfile!==f.profile.value;fieldset.disabled=fieldset.hidden}for(const el of form.querySelectorAll('[data-port-mode]')){el.hidden=el.dataset.portMode!==f.port_mode.value;for(const input of el.querySelectorAll('input'))input.disabled=el.hidden}$('#scan-description').textContent=profiles.find(p=>p.id===f.profile.value)?.description||''};
 update();
 let revision=0;
 const invalidate=()=>{form.captureDraft?.();form.captureDraft=null;revision++;$('#job-preview').innerHTML=''};
 form.oninput=invalidate;
 form.onchange=e=>{invalidate();if(e.target===f.preset&&f.preset.value!=='custom'){
  const preset=f.preset.value;f.port_mode.value=preset==='light'?'custom':'top';f.service_detection.value=preset==='light'?'light':'standard';f.service_scripts.checked=preset!=='light';f.tls_checks.checked=preset==='vulns';f.safe_vulns.checked=preset==='vulns';f.vulners.checked=false;f.host_timeout.value=preset==='light'?180:900;
 }else if(e.target.closest('[data-scan-profile="nmap-services"]'))f.preset.value='custom';update()};
 let resumed=context.draft;
 form.onsubmit=async e=>{e.preventDefault();const token=++revision;$('#job-preview').innerHTML='Preparing draft…';try{
  const values=Object.fromEntries(new FormData(form));const config={};
  for(const [key,value] of Object.entries(values))if(!key.startsWith('source_')&&!['profile','targets','add_scope','preset'].includes(key))config[key]=value;
  if(values.profile==='nmap-services')for(const key of ['service_scripts','tls_checks','safe_vulns','vulners'])config[key]=f[key].checked;
  if(values.profile==='bbot-passive')config.modules=['crt','hackertarget','rapiddns','shodan_idb'].filter(m=>f['source_'+m].checked);
  if(values.profile==='gowitness-web'){config.web_defaults=f.web_defaults.checked;config.full_page=f.full_page.checked;}
  const body={profile:values.profile,targets:values.targets.split(/[\s,;]+/).filter(Boolean),config,add_scope:f.add_scope.checked};
  await showScanDraft(form,body,resumed,()=>token===revision&&form.isConnected);resumed=null;
 }catch(err){if(token===revision&&form.isConnected)$('#job-preview').textContent=err.message}};
 if(context.draft){const token=++revision;await showScanDraft(form,context.draft.payload,resumed,()=>token===revision&&form.isConnected);resumed=null;}
};
