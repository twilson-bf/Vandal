/* Adapted from LotusPetal coverage-globe.js; same local globe.gl renderer. */
window.VandalMap=(()=>{
 let globe=null,container=null,overlay=null,markerNodes=[],resize=null,visible=null,points=[],flat=false,projectionReady=false,epoch=0,clusterFrame=0,clusterKey='';
 // Cluster in screen pixels so separation follows both zoom and viewport size.
 function updateClusters(){
  clusterFrame=0;if(!globe||!overlay||!projectionReady)return;
  const camera=globe.camera(),cam=camera.position,camLength=Math.hypot(cam.x,cam.y,cam.z)||1,clusters=[];
  for(const p of points){
   if(p.latitude==null||p.longitude==null)continue;
   const lat=Number(p.latitude),lng=Number(p.longitude),v=globe.getCoords(lat,lng,0),vLength=Math.hypot(v.x,v.y,v.z)||1;
   const dot=(cam.x*v.x+cam.y*v.y+cam.z*v.z)/(camLength*vLength),side=dot<-.04?'rear':'front';
   const xy=globe.getScreenCoords(lat,lng,0);
   const confirmed=Boolean(p.confirmed),pwned=Boolean(p.pwned),state=pwned?'pwned':confirmed?'confirmed':'host';
   let node=clusters.find(c=>c.state===state&&c.side===side&&Math.hypot(c.x-xy.x,c.y-xy.y)<44);
   if(!node){node={lat,lng,x:xy.x,y:xy.y,dot,side,confirmed,pwned,state,hosts:[]};clusters.push(node)}
   node.hosts.push(p);
  }
  for(const node of clusters)node.offset=clusters.some(c=>c!==node&&c.side===node.side&&c.state!==node.state&&Math.hypot(c.x-node.x,c.y-node.y)<32)?(node.pwned?-20:node.confirmed?0:20):0;
  const key=JSON.stringify(clusters.map(c=>[c.lat,c.lng,c.state,c.side,c.offset,c.hosts.map(p=>[p.id,p.country,p.hostnames,p.confirmed,p.pwned,p.callback_count])]));
  if(key!==clusterKey){clusterKey=key;overlay.replaceChildren();markerNodes=clusters.map(node=>{const el=marker(node);overlay.appendChild(el);return el})}
  clusters.forEach((node,index)=>{
   const el=markerNodes[index];if(!el)return;
   el.style.transform=`translate(${node.x+(node.offset||0)}px,${node.y}px) translate(-50%,-50%)`;
   const front=node.dot>.08,rear=node.dot<-.04;
   el.style.opacity='1';
   el.style.visibility='visible';
   el.style.pointerEvents=front?'auto':'none';
   if(rear){
    const depth=Math.min(1,(-node.dot-.04)*1.4),tile=Math.round(2+depth*8),mask='repeating-conic-gradient(#000 0% 25%,transparent 0% 50%)';
    el.style.filter='brightness(.72)';
    el.style.webkitMaskImage=mask;el.style.maskImage=mask;
    el.style.webkitMaskSize=`${tile}px ${tile}px`;el.style.maskSize=`${tile}px ${tile}px`;
   }else{
    el.style.filter=front?'':'brightness(.82)';
    el.style.webkitMaskImage='none';el.style.maskImage='none';
    el.style.webkitMaskSize='';el.style.maskSize='';
   }
  });
  overlay.classList.add('ready')
 }
 function scheduleClusters(){if(!clusterFrame)clusterFrame=requestAnimationFrame(updateClusters)}
 function graticule(){const lines=[];for(let lat=-75;lat<=75;lat+=15){const pts=[];for(let lng=-180;lng<=180;lng+=3)pts.push([lng,lat]);lines.push({pts})}for(let lng=-180;lng<180;lng+=15){const pts=[];for(let lat=-87;lat<=87;lat+=3)pts.push([lng,lat]);lines.push({pts})}return lines}
 const byName=new Intl.Collator(undefined,{numeric:true,sensitivity:'base'});
 function showGroup(node){
  if(node.hosts.length===1){openHostPane(node.hosts[0].id);return}
  const hosts=node.hosts.map(h=>({...h,hostnames:[...(h.hostnames||[])].sort((a,b)=>byName.compare(a.value,b.value))}));
  hosts.sort((a,b)=>Number(!a.hostnames.length)-Number(!b.hostnames.length)||byName.compare(a.hostnames[0]?.value||'',b.hostnames[0]?.value||'')||byName.compare(a.value,b.value));
  drawer(`<div class="eyebrow">LOCATION GROUP</div><h2>${hosts.length} hosts</h2><p>${esc([...new Set(hosts.map(h=>h.country))].join(' · '))}</p><div class="cluster-hosts">${table(['HOSTNAMES','IP ADDRESS'],hosts.map(h=>`<tr><td>${h.hostnames.map(n=>`<a class="text-link" href="#host?id=${n.id}">${esc(n.value)}</a>`).join('<br>')||'<span class="muted">—</span>'}</td><td><a class="text-link" href="#host?id=${h.id}">${esc(h.value)}</a></td></tr>`).join(''))}</div>`)
 }
 function wheelZoom(event){
  if(!globe||flat)return;
  event.preventDefault();event.stopPropagation();
  const delta=event.deltaY*(event.deltaMode===1?16:event.deltaMode===2?container.clientHeight:1);
  const view=globe.pointOfView();
  globe.pointOfView({...view,altitude:Math.max(.35,Math.min(5,view.altitude*Math.exp(Math.max(-1,Math.min(1,delta*.0015)))))},0);
 }
 function marker(node){const button=document.createElement('button');button.type='button';button.className='globe-marker'+(node.pwned?' pwned':node.confirmed?' confirmed':'');button.textContent=node.hosts.length>1?node.hosts.length:node.pwned?'◆':node.confirmed?'!':'◎';button.title=node.hosts.length+' host(s)'+(node.pwned?' · Mythic beacon observed':node.confirmed?' · Confirmed vulnerabilities':' · No confirmed vulnerabilities')+' · '+[...new Set(node.hosts.map(h=>h.country))].join(' · ');button.setAttribute('aria-label','View '+button.title);button.onclick=e=>{e.stopPropagation();showGroup(node)};return button}
 function stopGlobe(){cancelAnimationFrame(clusterFrame);clusterFrame=0;clusterKey='';projectionReady=false;markerNodes=[];overlay?.remove();overlay=null;if(globe)globe.controls().removeEventListener('change',scheduleClusters);resize?.disconnect();visible?.disconnect();resize=visible=null;if(globe){globe.pauseAnimation();globe._destructor?.();globe=null}}
 function destroy(){epoch++;stopGlobe();container=null}
 async function flatMap(){await world('#vandal-flat-map',points);for(const p of points){const dot=container?.querySelector(`circle[data-asset="${p.id}"]`);if(!dot)continue;if(p.pwned||p.confirmed)dot.setAttribute('fill','#ff4055');if(p.pwned)dot.querySelector('title').textContent+=' · Mythic beacon observed';else if(p.confirmed)dot.querySelector('title').textContent+=' · Confirmed vulnerabilities'}}
 async function mount(){const token=++epoch;stopGlobe();const stage=container.querySelector('.globe-stage');stage.innerHTML='';
  if(flat){stage.innerHTML='<div id="vandal-flat-map" class="map-box" style="height:100%"></div>';await flatMap();return}
  try{
   const topology=await fetch('/static/countries-110m.json').then(r=>r.json());if(token!==epoch||!stage.isConnected)return;
   globe=new Globe(stage).width(stage.clientWidth).height(stage.clientHeight).backgroundColor('#101014').globeImageUrl(null).showAtmosphere(false)
    .polygonsData(topojson.feature(topology,topology.objects.countries).features).polygonCapColor(()=> '#1A5FFF').polygonSideColor(()=> 'rgba(0,0,0,0)').polygonStrokeColor(()=> '#000000').polygonAltitude(.003)
    .pathsData(graticule()).pathPoints('pts').pathPointLat(p=>p[1]).pathPointLng(p=>p[0]).pathColor(()=> '#1A5FFF').pathStroke(.5).pathDashLength(1).pathDashGap(0).pathTransitionDuration(0)
    .onGlobeReady(()=>{if(!globe)return;const material=globe.globeMaterial();material.color.set('#000000');material.specular?.setRGB(0,0,0);material.shininess=0;projectionReady=true;requestAnimationFrame(scheduleClusters)});
   overlay=document.createElement('div');overlay.className='globe-icon-overlay';stage.appendChild(overlay);
   const controls=globe.controls();controls.autoRotate=false;controls.enableDamping=true;controls.enableZoom=false;controls.addEventListener('change',scheduleClusters);
   globe.pointOfView({lat:25,lng:10,altitude:2.2},0);
   resize=new ResizeObserver(()=>{if(globe){globe.width(stage.clientWidth).height(stage.clientHeight);scheduleClusters()}});resize.observe(stage);
   visible=new IntersectionObserver(entries=>{if(globe){if(entries[0].isIntersecting&&!document.hidden)globe.resumeAnimation();else globe.pauseAnimation()}});visible.observe(stage);
   stage.querySelector('canvas')?.setAttribute('aria-label','Interactive host globe. Drag to rotate; scroll to zoom.');
  }catch(e){stopGlobe();if(token!==epoch)return;flat=true;container.querySelector('[data-map-toggle]').textContent='Try 3D';container.querySelector('.globe-status').textContent='3D unavailable · flat map';stage.innerHTML='<div id="vandal-flat-map" class="map-box" style="height:100%"></div>';await flatMap()}
 }
 async function render(element,data){points=data;
  if(container===element){if(globe)scheduleClusters();else if(flat)await flatMap();updateStatus();return}
  destroy();container=element;flat=false;
  container.innerHTML='<div class="globe-controls"><button class="quiet" data-map-toggle>Flat map</button><button class="quiet" data-map-zoom="in" aria-label="Zoom in">+</button><button class="quiet" data-map-zoom="out" aria-label="Zoom out">−</button><button class="quiet" data-map-reset>Reset</button><button class="quiet" data-map-expand>Expand</button></div><div class="globe-stage"></div><div class="globe-status micro"></div>';
  container.querySelector('.globe-stage').addEventListener('wheel',wheelZoom,{passive:false,capture:true});
  container.onclick=e=>{const b=e.target.closest('button');if(!b)return;if(b.hasAttribute('data-map-toggle')){flat=!flat;b.textContent=flat?'3D globe':'Flat map';mount()}if(b.dataset.mapZoom&&globe){const view=globe.pointOfView();globe.pointOfView({...view,altitude:Math.max(.35,Math.min(5,view.altitude*(b.dataset.mapZoom==='in'?.8:1.25)))},250)}if(b.hasAttribute('data-map-reset')&&globe)globe.pointOfView({lat:25,lng:10,altitude:2.2},350);if(b.hasAttribute('data-map-expand')){container.classList.toggle('expanded');b.textContent=container.classList.contains('expanded')?'Collapse':'Expand'}};
  updateStatus();await mount();
 }
 function updateStatus(){if(!container)return;const known=points.filter(p=>p.latitude!=null&&p.longitude!=null).length;container.querySelector('.globe-status').textContent=`${known} located · ${points.length-known} unknown · Red: pwned or confirmed vulnerability · Orange: other hosts · Scroll to zoom`}
 document.addEventListener('visibilitychange',()=>{if(globe){if(document.hidden)globe.pauseAnimation();else globe.resumeAnimation()}});
 return {render,destroy};
})();
