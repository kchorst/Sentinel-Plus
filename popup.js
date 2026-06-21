const $ = id => document.getElementById(id);
const ids = [
  'modeLine','siteLine','statusDot','refreshNotice','refreshPage','gearBtn','moreBtn','gearPanel','hideGear','styleSelect','approvedBox','approvedCount','clearApproved','trustedLocalBox',
  'morePanel','hideMore','detectedItems','checkIntegrations','integrationMsg','enableProfileTools',
  'profilePanel','hideProfile','importProfile','profileFile','exportProfile','editProfile','customSitesBtn','devDiag','profileEditor','editorActions','applyProfile','cancelEdit','profileMsg',
  'customSitesPanel','hideCustomSites','customSitesBox','testSelectors','customSiteMsg',
  'diagPanel','hideDiag','exportAuditJson','exportAuditCsv','rawDebug','diagBox','protectedTermsBox','protectedTermsCount','manageProtectedTerms','protectedTermsEditorPanel','protectedTermsEditor','saveProtectedTerms','clearProtectedTerms','hideProtectedTerms','hideProtectedTermsTop','protectedTermsMsg','regexHelp'
];
const els = ids.reduce((a,id)=>(a[id]=$(id),a),{});
let state = null;
let pendingProfile = null;

document.addEventListener('DOMContentLoaded', init);

async function init(){ bind(); await refresh(); }

function bind(){
  els.gearBtn.onclick = () => togglePanel(els.gearPanel);
  els.hideGear.onclick = () => { hidePanel(els.gearPanel); hidePanel(els.protectedTermsEditorPanel); };
  els.moreBtn.onclick = () => toggleMore();
  els.hideMore.onclick = () => hideMoreTree();
  els.styleSelect.onchange = () => send({type:'SET_PROTECTION_STYLE', style:els.styleSelect.value}).then(refresh);
  els.clearApproved.onclick = async () => { await send({ type:'CLEAR_APPROVED_SESSION' }); await refresh(); };
  els.manageProtectedTerms.onclick = () => toggleProtectedTermsEditor();
  els.hideProtectedTerms.onclick = () => hideProtectedTermsEditor();
  els.hideProtectedTermsTop.onclick = () => hideProtectedTermsEditor();
  els.saveProtectedTerms.onclick = saveProtectedTerms;
  els.clearProtectedTerms.onclick = async () => { els.protectedTermsEditor.value = ''; await saveProtectedTerms(); };
  els.regexHelp.onclick = () => chrome.tabs.create({ url:'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions' });
  els.refreshPage.onclick = async () => {
    const result = await send({ type:'REFRESH_ACTIVE_TAB' });
    if(!result.ok) els.siteLine.textContent = result.error || 'Could not refresh this page.';
  };
  els.checkIntegrations.onclick = async () => {
    const result = await send({type:'CHECK_INTEGRATIONS'});
    els.integrationMsg.textContent = result.message || (result.integrations?.length ? 'Status refreshed.' : 'Checked: no integrations detected.');
    await refresh();
  };
  els.enableProfileTools.onclick = () => togglePanel(els.profilePanel);
  els.hideProfile.onclick = () => { hidePanel(els.profilePanel); hidePanel(els.profileEditor); hidePanel(els.editorActions); };
  els.importProfile.onclick = () => els.profileFile.click();
  els.profileFile.onchange = importProfileFile;
  els.exportProfile.onclick = exportProfile;
  els.editProfile.onclick = editProfile;
  els.cancelEdit.onclick = () => { hidePanel(els.profileEditor); hidePanel(els.editorActions); };
  els.applyProfile.onclick = applyEditorProfile;
  els.customSitesBtn.onclick = () => { togglePanel(els.customSitesPanel); renderCustomSites(); };
  els.hideCustomSites.onclick = () => hidePanel(els.customSitesPanel);
  els.testSelectors.onclick = testSelectors;
  els.devDiag.onclick = showDiagnostics;
  els.hideDiag.onclick = () => hidePanel(els.diagPanel);
  els.exportAuditJson.onclick = () => exportAudit('json');
  els.exportAuditCsv.onclick = () => exportAudit('csv');
  els.rawDebug.onclick = toggleRawDebug;
}

function togglePanel(el){ el.classList.toggle('hidden'); updateMoreButton(); }
function hidePanel(el){ el.classList.add('hidden'); updateMoreButton(); }
function showPanel(el){ el.classList.remove('hidden'); updateMoreButton(); }
function toggleMore(){ if(els.morePanel.classList.contains('hidden')) showPanel(els.morePanel); else hideMoreTree(); }
function hideMoreTree(){ [els.morePanel, els.profilePanel, els.customSitesPanel, els.diagPanel, els.profileEditor, els.editorActions].forEach(hidePanel); }
function updateMoreButton(){ els.moreBtn.textContent = els.morePanel.classList.contains('hidden') ? 'More' : 'Hide'; }

function toggleProtectedTermsEditor(){
  if(els.protectedTermsEditorPanel.classList.contains('hidden')) showProtectedTermsEditor();
  else hideProtectedTermsEditor();
}
function showProtectedTermsEditor(){
  showPanel(els.protectedTermsEditorPanel);
  els.manageProtectedTerms.textContent = 'Hide';
}
function hideProtectedTermsEditor(){
  hidePanel(els.protectedTermsEditorPanel);
  els.manageProtectedTerms.textContent = 'Manage';
}

async function refresh(){ state = await send({type:'GET_POPUP_STATE'}); render(); }

function render(){
  const style = state.protectionStyle || 'balanced';
  els.styleSelect.value = style;
  els.modeLine.textContent = `${state.userMode || 'Basic'} · ${capitalize(style)}`;
  updateMoreButton();
  const ready = Boolean(state.protectionReady);
  if(state.supported && state.siteName){
    if(ready) els.siteLine.textContent = `Active on ${state.siteName}`;
    else if(state.supportedButInactive) els.siteLine.textContent = `${state.siteName} active — chat box not detected yet`;
    else els.siteLine.textContent = `${state.siteName} needs refresh to activate protection`;
    els.siteLine.classList.remove('hidden');
  } else if(state.unsupported && state.unsupportedSiteName === 'Copilot') {
    els.siteLine.textContent = 'Copilot is not supported in this beta.';
    els.siteLine.classList.remove('hidden');
  } else {
    els.siteLine.textContent = 'Not active on this site.';
    els.siteLine.classList.remove('hidden');
  }
  if(els.statusDot){
    els.statusDot.classList.toggle('warn', Boolean(state.supported && !ready));
    els.statusDot.classList.toggle('bad', Boolean(!state.supported));
    els.statusDot.title = ready ? 'Protection active' : (state.unsupported ? 'Unsupported site' : (state.supported ? 'Supported site, protection not confirmed' : 'Not active on this site'));
  }
  // Only show the refresh prompt when no content-script heartbeat is attached.
  // If Sentinel+ is already active on Gemini/ChatGPT/etc., do not nag users to refresh.
  els.refreshNotice.classList.toggle('hidden', !state.needsRefresh);
  els.approvedBox.classList.toggle('hidden', !state.approvedCount);
  els.approvedCount.textContent = String(state.approvedCount || 0);
  renderDetected();
  renderCustomSites();
  renderProtectedTerms();
  els.manageProtectedTerms.textContent = els.protectedTermsEditorPanel.classList.contains('hidden') ? 'Manage' : 'Hide';
}

function renderDetected(){
  clear(els.detectedItems);
  let count = 0;
  if(state.lastMetrics){ addRow(els.detectedItems, 'TPS', state.lastMetrics.tps ?? '—'); addRow(els.detectedItems, 'TTFT', state.lastMetrics.ttftMs != null ? `${state.lastMetrics.ttftMs}ms` : '—'); count += 2; }
  for(const item of state.integrations || []){
    if(!item) continue;
    const value = item.status === 'connected' ? 'Connected' : 'Refresh';
    addRow(els.detectedItems, item.label, value, item.status === 'connected' ? 'ok' : 'warn');
    count++;
    if(item.vram){ addRow(els.detectedItems, 'VRAM', formatVram(item.vram)); count++; }
  }
  if(count === 0) addNote(els.detectedItems, 'No integrations shown unless detected or previously used.');
}

function renderCustomSites(){
  if(!els.customSitesBox) return;
  const sites = state?.customSites || [];
  clear(els.customSitesBox);
  if(!sites.length){ els.customSitesBox.textContent = 'No custom sites loaded.'; return; }
  sites.forEach(site => addRow(els.customSitesBox, site.name || site.friendlyName || site.domain || 'Custom site', site.domain || site.urlPattern || ''));
}


function renderProtectedTerms(){
  const terms = state?.protectedTerms || [];
  if(els.protectedTermsCount) els.protectedTermsCount.textContent = `${terms.length} saved`;
  if(!els.protectedTermsEditor) return;
  if(document.activeElement === els.protectedTermsEditor) return;
  els.protectedTermsEditor.value = terms.map(t => t.phrase || '').filter(Boolean).join('\n');
}
async function saveProtectedTerms(){
  const raw = els.protectedTermsEditor.value || '';
  const result = await send({ type:'SET_PROTECTED_TERMS', terms: raw });
  els.protectedTermsMsg.textContent = result.ok ? `Saved ${result.count || 0} protected term(s).` : `Save failed: ${result.error || 'unknown error'}`;
  await refresh();
}

async function importProfileFile(){
  const file = els.profileFile.files?.[0];
  if(!file) return;
  try{
    const profile = JSON.parse(await file.text());
    const preview = await send({type:'PREVIEW_PROFILE', profile});
    if(!preview.ok){ els.profileMsg.textContent = `Import failed: ${preview.error}`; return; }
    const summary = preview.summary || {};
    const warnings = (preview.warnings || []).join('\n');
    const text = [
      `Import profile: ${summary.profileName || 'Profile'}`,
      `Rules: ${summary.ruleCount || 0}`,
      `Locked rules: ${summary.lockedRuleCount || 0}`,
      `Custom sites: ${summary.customSiteCount || 0}`,
      warnings ? `\nWarnings:\n${warnings}` : '',
      '\nContinue import?'
    ].join('\n');
    if(!window.confirm(text)){ els.profileMsg.textContent = 'Import cancelled.'; return; }
    const origins = profileOrigins(preview.profile || profile);
    if(origins.length && chrome.permissions?.request){
      await requestOrigins(origins);
    }
    const result = await send({type:'IMPORT_PROFILE_CONFIRMED', profile: preview.profile || profile});
    els.profileMsg.textContent = result.ok ? `Imported ${result.summary.profileName} (${result.summary.ruleCount} rules)` : `Import failed: ${result.error}`;
    await refresh();
  }catch(e){ els.profileMsg.textContent = `Import failed: ${e.message}`; }
}

async function exportProfile(){ const profile = await send({type:'EXPORT_PROFILE'}); download('sentinel-profile.json', JSON.stringify(profile,null,2), 'application/json'); }
async function editProfile(){ const profile = await send({type:'EXPORT_PROFILE'}); els.profileEditor.value = JSON.stringify(profile,null,2); showPanel(els.profileEditor); showPanel(els.editorActions); }
async function applyEditorProfile(){
  try{
    const profile = JSON.parse(els.profileEditor.value);
    const preview = await send({type:'PREVIEW_PROFILE', profile});
    if(!preview.ok){ els.profileMsg.textContent = `Apply failed: ${preview.error}`; return; }
    const summary = preview.summary || {};
    if(!window.confirm(`Apply profile ${summary.profileName || 'Profile'} with ${summary.ruleCount || 0} rule(s)?`)){ els.profileMsg.textContent = 'Apply cancelled.'; return; }
    const origins = profileOrigins(preview.profile || profile);
    if(origins.length && chrome.permissions?.request){ await requestOrigins(origins); }
    const result = await send({type:'IMPORT_PROFILE_CONFIRMED', profile: preview.profile || profile});
    els.profileMsg.textContent = result.ok ? `Applied ${result.summary.profileName}` : `Apply failed: ${result.error}`;
    await refresh();
  }catch(e){ els.profileMsg.textContent = `Invalid JSON: ${e.message}`; }
}

async function testSelectors(){
  els.customSiteMsg.textContent = 'Testing current page selectors...';
  const result = await send({ type:'TEST_CUSTOM_SELECTORS' });
  if(result.ok) els.customSiteMsg.textContent = `Editor: ${result.editorFound ? 'found' : 'not found'} · Send button: ${result.sendButtonFound ? 'found' : 'not found'}`;
  else els.customSiteMsg.textContent = `Test failed: ${result.error || 'Content script not active on this page.'}`;
}

async function showDiagnostics(){
  showPanel(els.diagPanel);
  const audit = await send({type:'GET_AUDIT'});
  const safe = { version:state.version, supported:state.supported, siteName:state.siteName, integrations:state.integrations, metricsPresent:Boolean(state.lastMetrics), approvedCount:state.approvedCount || 0, protectedTermCount:(state.protectedTerms || []).length, auditCount:audit.auditLog?.length || 0, rawDebug:state.rawDebug };
  els.diagBox.textContent = JSON.stringify(safe,null,2);
}
async function exportAudit(type){ const res = await send({type:'GET_AUDIT'}); const rows = res.auditLog || []; if(type==='json') download('sentinel-audit.json', JSON.stringify(rows,null,2), 'application/json'); else download('sentinel-audit.csv', toCsv(rows), 'text/csv'); }
async function toggleRawDebug(){ const now = Date.now(); const on = !(state.rawDebug?.enabled && state.rawDebug.expiresAt > now); const r = await send({type:'SET_RAW_DEBUG', enabled:on}); els.rawDebug.textContent = on ? 'Raw debug logging is on for 30 minutes.' : 'Raw debug logging: Off'; await refresh(); }

function profileOrigins(profile){
  const sites = profile?.customSites || [];
  return sites.map(site => {
    if(site.urlPattern) return site.urlPattern;
    const domain = String(site.domain || '').replace(/^https?:\/\//,'').replace(/\/.*$/,'');
    return domain ? `https://${domain}/*` : '';
  }).filter(Boolean);
}
function requestOrigins(origins){ return new Promise(resolve => chrome.permissions.request({ origins }, granted => resolve(Boolean(granted)))); }
function toCsv(rows){ const cols=['time','site','ruleId','category','risk','action','userMode']; return [cols.join(',')].concat(rows.map(r=>cols.map(c=>`"${String(c==='time'?new Date(r[c]).toISOString():r[c]??'').replace(/"/g,'""')}"`).join(','))).join('\n'); }
function download(name,text,type){ const url=URL.createObjectURL(new Blob([text],{type})); const a=document.createElement('a'); a.href=url; a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(url),1000); }
function send(msg){ return new Promise(resolve => chrome.runtime.sendMessage(msg, res => resolve(res || {}))); }
function clear(el){ while(el.firstChild) el.removeChild(el.firstChild); }
function addNote(parent,text){ const div=document.createElement('div'); div.className='note'; div.textContent=text; parent.appendChild(div); }
function addRow(parent,label,value,cls=''){
  const row=document.createElement('div'); row.className='row';
  const l=document.createElement('span'); l.textContent=label;
  const v=document.createElement('strong'); v.textContent=String(value ?? ''); if(cls) v.className=cls;
  row.append(l,v); parent.appendChild(row);
}
function capitalize(s){ return String(s || '').charAt(0).toUpperCase() + String(s || '').slice(1); }
function formatVram(v){ if(typeof v==='string') return v; try{return JSON.stringify(v);}catch{return String(v);} }
