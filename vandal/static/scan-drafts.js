/* Saved review documents are independent of the validated execution profile. */
async function showScanDraft(form,body,saved,current){
 const base=endpoint(''),plan=await api(base+'scan-drafts/preview',{method:'POST',body});if(!current())return;
 const meta=saved||form.draftMeta||{};
 const errorPrefix='Last reported profile validation error: ';
 let did=meta.id||0,revision=meta.revision||0,validationError=meta.validation_error||saved?.warnings.find(w=>w.startsWith(errorPrefix))?.slice(errorPrefix.length)||'';
 $('#job-preview').innerHTML=`<section id="scan-draft-editor"><h3>Command draft</h3><p class="micro">Free-text edits are saved for review. Executable changes use the profile controls above.</p><label>TITLE<input id="draft-title" maxlength="150" value="${esc(meta.title||body.profile+' · '+body.targets[0])}"></label><label>COMMAND<textarea id="draft-command" rows="6" maxlength="20000" spellcheck="false">${esc(saved?saved.command:plan.command)}</textarea></label><details><summary>Draft target file · ${body.targets.length} identifiers</summary><pre>${esc(body.targets.join('\n'))}</pre></details><details><summary>Draft warnings</summary>${(saved?.warnings||plan.warnings).map(w=>`<p>${esc(w)}</p>`).join('')}${plan.excluded.length?`<pre>${esc(JSON.stringify(plan.excluded,null,2))}</pre>`:''}</details><label>NOTES<textarea id="draft-notes" maxlength="20000">${esc(meta.notes||'')}</textarea></label><div class="form-actions"><button class="primary" id="save-scan-draft">Save ${did?'revision':'draft'}</button><button class="quiet" id="reset-draft-command">Reset command to profile</button><button class="quiet" id="download-scan-draft">Export draft</button></div><p id="draft-save-state" class="micro">${did?'Draft #'+did+' · Revision '+revision:'Unsaved draft'}</p><details id="draft-history"><summary>Revision history</summary><div>${saved?.revisions?.map(r=>`<details><summary>Revision ${r.revision} · ${esc(r.actor)} · ${esc(stamp(r.created_at))}</summary><pre>${esc(r.command)}</pre><p>${esc(r.notes)}</p>${r.warnings.map(w=>`<p>${esc(w)}</p>`).join('')}</details>`).join('')||'Save a draft to retain revisions.'}</div></details><h3>Profile readiness</h3><button class="secondary" id="validate-scan-profile">Validate profile</button><p id="draft-edit-state" class="micro"></p><div id="profile-readiness"></div></section>`;
 const editor=$('#scan-draft-editor'),command=editor.querySelector('#draft-command'),status=editor.querySelector('#draft-save-state');
 if(!saved&&meta.edited)command.value=meta.command;
 editor.querySelector('#draft-title').value=editor.querySelector('#draft-title').value.slice(0,150);
 const edited=()=>command.value!==plan.command;
 const explain=()=>{editor.querySelector('#draft-edit-state').textContent=edited()?'Draft text has edits. Run is disabled until you reset it; change profile options above to change the executable command.':'';const run=editor.querySelector('#run-preview');if(run)run.disabled=edited()};
 command.oninput=explain;explain();
 editor.querySelector('#reset-draft-command').onclick=()=>{command.value=plan.command;explain()};
 const values=()=>({title:editor.querySelector('#draft-title').value,payload:body,command:command.value,notes:editor.querySelector('#draft-notes').value,validation_error:validationError,base_revision:revision});
 form.captureDraft=()=>{if(editor.isConnected)form.draftMeta={...values(),id:did,revision,edited:edited()}};
 editor.querySelector('#save-scan-draft').onclick=async e=>{const button=e.target;button.disabled=true;try{
  const data=values(),result=await api(base+'scan-drafts'+(did?'/'+did:''),{method:did?'PUT':'POST',body:data});did=result.id;revision=result.revision;form.draftMeta={id:did,revision,title:data.title,notes:data.notes};
  if(!editor.isConnected)return;status.textContent=`Saved draft #${did} · Revision ${revision}`;button.textContent='Save revision';
  const history=await api(base+'scan-drafts/'+did);if(editor.isConnected)editor.querySelector('#draft-history>div').innerHTML=history.revisions.map(r=>`<details><summary>Revision ${r.revision} · ${esc(r.actor)} · ${esc(stamp(r.created_at))}</summary><pre>${esc(r.command)}</pre><p>${esc(r.notes)}</p>${r.warnings.map(w=>`<p>${esc(w)}</p>`).join('')}</details>`).join('');
 }catch(err){if(editor.isConnected)status.textContent=err.message}finally{button.disabled=false}};
 editor.querySelector('#download-scan-draft').onclick=()=>{const blob=new Blob([JSON.stringify({...values(),warnings:plan.warnings,executable:false},null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='vandal-draft.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)};
 editor.querySelector('#validate-scan-profile').onclick=async e=>{
  const button=e.target;button.disabled=true;const slot=editor.querySelector('#profile-readiness');slot.textContent='Validating profile…';
  try{const checked=await api(base+'jobs/preview',{method:'POST',body});if(!current()||!editor.isConnected)return;validationError='';
   const runBody={...body};if(checked.resolutions)runBody.resolutions=checked.resolutions;if(checked.web_candidates)runBody.web_candidates=checked.web_candidates;
   slot.innerHTML=`<h4>Validated profile command</h4><pre>${esc(checked.command_text||checked.command.join(' '))}</pre>${checked.resolutions?`<details open><summary>DNS snapshot · ${checked.scan_targets.length} addresses</summary><pre>${esc(JSON.stringify(checked.resolutions,null,2))}</pre></details>`:''}${checked.web_candidates?`<details><summary>${checked.web_candidates.length} web candidates</summary><pre>${esc(checked.web_candidates.map(c=>c.url).join('\n'))}</pre></details>`:''}${checked.scope_additions?.length?`<p>Scope additions on run: ${checked.scope_additions.map(esc).join(', ')}</p>`:''}${checked.excluded?.length?`<details><summary>${checked.excluded.length} excluded targets</summary><pre>${esc(JSON.stringify(checked.excluded,null,2))}</pre></details>`:''}<button class="primary" id="run-preview">Run validated profile</button>`;
   explain();slot.querySelector('#run-preview').onclick=async event=>{if(edited())return;event.target.disabled=true;try{const job=await api(base+'jobs',{method:'POST',body:runBody});toast('Profile queued and recorded.');await jobDrawer(job.id)}catch(err){validationError=err.message;status.textContent=err.message;event.target.disabled=false}};
  }catch(err){validationError=err.message;if(editor.isConnected)slot.innerHTML=`<p class="notice">${esc(err.message)}</p><p class="micro">The draft is retained. Correct the profile or save it with this validation error.</p>`}finally{button.disabled=false}
 };
}

async function openScanDraft(id){const item=await api(endpoint('scan-drafts/'+id));await jobComposer(item.profile,{targets:item.payload.targets,draft:item})}
async function showSavedDrafts(){const drafts=await api(endpoint('scan-drafts'));drawer(`<h2>Saved scan drafts</h2>${drafts.length?table(['TITLE','PROFILE','REVISION','UPDATED'],drafts.map(d=>`<tr><td><a class="text-link" href="#" data-scan-draft="${d.id}">${esc(d.title)}</a></td><td>${esc(d.profile)}</td><td>${d.revision}</td><td>${esc(stamp(d.updated_at))}</td></tr>`).join('')):empty('No saved drafts','Generate a draft from New scan, then save it.')}`)}
document.addEventListener('click',async e=>{const t=e.target.closest('a,button');if(!t)return;try{
 if(t.hasAttribute('data-open-drafts')){e.preventDefault();await showSavedDrafts()}
 if(t.dataset.scanDraft){e.preventDefault();await openScanDraft(Number(t.dataset.scanDraft))}
 if(t.dataset.syncDns){e.preventDefault();await jobComposer('dns-validate',{targets:[t.dataset.syncDns]})}
 if(t.dataset.profileDraft){e.preventDefault();await jobComposer(t.dataset.profileDraft)}
}catch(err){toast(err.message)}});
const originalJobsView=renderers.jobs;
renderers.jobs=async function(token){await originalJobsView(token);if(token!==epoch)return;$('#page-actions').insertAdjacentHTML('afterbegin','<button class="quiet" data-open-drafts>Saved drafts</button>');const cards=document.querySelectorAll('#content .stats .stat');const profiles=await api(endpoint('profiles'));if(token!==epoch)return;profiles.forEach((p,i)=>cards[i]?.insertAdjacentHTML('beforeend',`<button class="quiet" data-profile-draft="${esc(p.id)}">Configure ${esc(p.tool)}</button>`))};
