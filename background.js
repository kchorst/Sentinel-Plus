// background.js — Sentinel+ v2.2.4 beta candidate build
// State-driven, no clipboard, no raw prompt/response persistence by default.
// P0 invariant: never silently block a send.

const TESTER_ID = 'njggbbcnjobebgflkngifbpnanlgfekc';
const PARAMETIZER_BASE = 'http://127.0.0.1:9820';
const VERSION = '2.2.4';
const AUDIT_RETENTION_DAYS = 7;
const APPROVAL_TTL_MS = 6 * 60 * 60 * 1000;
const ACTIVE_CONTENT_TTL_MS = 30 * 1000;
// Per-frame heartbeat state. dynamic SPA surfaces may put the usable
// composer in a child frame while the top frame is only a shell. Never let a
// non-ready top-frame heartbeat overwrite a ready child-frame heartbeat.
const activeContentByTab = new Map();

const DEFAULT_PATTERNS = [
  { id: 'email', label: 'Email Address', category: 'PII', risk: 'medium', action: 'advise', redactionLabel: '[EMAIL REDACTED]', regex: String.raw`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`, flags: 'g' },
  { id: 'phone_us', label: 'Phone Number', category: 'PII', risk: 'medium', action: 'advise', redactionLabel: '[PHONE REDACTED]', regex: String.raw`(?:\+?1[\s.-]*)?\(?\d{3}\)?[\s.-]*\d{3}[\s.-]*\d{4}\b`, flags: 'g' },
  { id: 'phone_international', label: 'Possible International Phone Number', category: 'PII', risk: 'medium', action: 'advise', redactionLabel: '[PHONE REDACTED]', regex: String.raw`(?<![\w])\+[1-9]\d{0,2}(?:[\s().-]*\d){6,14}(?![\w])`, flags: 'g' },
  { id: 'iban', label: 'Possible IBAN Bank Account', category: 'Financial', risk: 'high', action: 'gate', redactionLabel: '[IBAN REDACTED]', regex: String.raw`\b[A-Z]{2}\d{2}[\s-]?(?:[A-Z0-9][\s-]?){11,30}\b`, flags: 'gi' },
  { id: 'swift_bic', label: 'Possible SWIFT/BIC Code', category: 'Financial', risk: 'medium', action: 'advise', redactionLabel: '[SWIFT/BIC REDACTED]', regex: String.raw`\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b`, flags: 'g' },
  { id: 'passport_labeled', label: 'Labeled Passport Number', category: 'PII', risk: 'high', action: 'gate', redactionLabel: '[PASSPORT REDACTED]', regex: String.raw`\b(?:passport(?:\s+(?:no\.?|number|#))?|travel\s+document(?:\s+(?:no\.?|number|#))?)\s*[:#-]?\s*[A-Z0-9]{6,12}\b`, flags: 'gi' },
  { id: 'tax_id_labeled', label: 'Labeled Tax/VAT/TIN Number', category: 'PII', risk: 'high', action: 'gate', redactionLabel: '[TAX ID REDACTED]', regex: String.raw`\b(?:VAT|TIN|tax\s+ID|tax\s+identification\s+number|national\s+tax\s+number)\s*[:#-]?\s*[A-Z0-9][A-Z0-9\s.-]{5,24}\b`, flags: 'gi' },
  { id: 'ip_address', label: 'IP Address', category: 'Network', risk: 'low', action: 'advise', redactionLabel: '[IP REDACTED]', regex: String.raw`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`, flags: 'g' },
  { id: 'ssn', label: 'Social Security Number', category: 'PII', risk: 'high', action: 'gate', redactionLabel: '[SSN REDACTED]', regex: String.raw`\b\d{3}[-.\s]*\d{2}[-.\s]*\d{4}\b`, flags: 'g' },
  { id: 'credit_card_like', label: 'Credit Card-like Number', category: 'Financial', risk: 'high', action: 'gate', redactionLabel: '[CARD REDACTED]', luhn: true, regex: String.raw`\b(?:\d[\s-]*){12,18}\d\b`, flags: 'g' },
  { id: 'api_key', label: 'API Key or Token', category: 'Credentials', risk: 'critical', action: 'gate', redactionLabel: '[API KEY REDACTED]', regex: String.raw`(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ey[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_=-]{10,}\.?[A-Za-z0-9_.+/=-]*)`, flags: 'g' },
  { id: 'password_assignment', label: 'Password or Secret', category: 'Credentials', risk: 'critical', action: 'gate', redactionLabel: '[SECRET REDACTED]', regex: String.raw`\b(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*[:=]\s*\S+`, flags: 'gi' },
  { id: 'private_key_block', label: 'Private Key Block', category: 'Credentials', risk: 'critical', action: 'gate', redactionLabel: '[PRIVATE KEY REDACTED]', regex: String.raw`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`, flags: 'g' }
];

const RISK_RANK = { low: 1, medium: 2, high: 3, critical: 4 };
const ACTION_RANK = { none: 0, advise: 1, gate: 2, block: 2 };

chrome.runtime.onInstalled.addListener(() => initialize());
chrome.runtime.onStartup.addListener(() => initialize());
initialize();

function initialize() {
  chrome.storage.local.get(['protectionStyle', 'activeProfile', 'auditLog', 'protectedTerms'], async (data) => {
    const defaults = {};
    if (!data.protectionStyle) defaults.protectionStyle = 'balanced';
    if (!Array.isArray(data.auditLog)) defaults.auditLog = [];
    if (!Array.isArray(data.protectedTerms)) defaults.protectedTerms = [];
    if (Object.keys(defaults).length) chrome.storage.local.set(defaults);
    await registerCustomSites(data.activeProfile?.customSites || data.customSites || []);
  });
  chrome.action.setBadgeText({ text: '' });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg !== 'object') return false;

  if (msg.type === 'PAGE_ACTIVE') {
    const tabId = sender.tab?.id;
    if (tabId) {
      const frameStatus = {
        siteName: msg.siteName || 'AI site',
        url: sender.tab?.url || msg.siteUrl || '',
        frameUrl: sender.url || msg.frameUrl || msg.siteUrl || '',
        frameId: sender.frameId ?? 0,
        editorFound: Boolean(msg.editorFound),
        sendButtonFound: Boolean(msg.sendButtonFound),
        protectionReady: Boolean(msg.protectionReady || msg.editorFound),
        lastSeen: Date.now()
      };
      const best = rememberContentFrame(tabId, frameStatus);
      const ready = Boolean(best.protectionReady || best.editorFound);
      chrome.action.setBadgeText({ tabId, text: ready ? '•' : '!' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: ready ? '#22c55e' : '#f59e0b' });
      chrome.storage.local.set({
        activeSiteName: best.siteName || frameStatus.siteName,
        activeSiteUrl: best.url || frameStatus.url,
        contentScriptActive: true,
        contentScriptProtectionReady: ready
      });
    }
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'PROCESS_INPUT') {
    processInput(msg.text || '', msg.siteName || 'AI site', msg.siteUrl || sender.tab?.url || '', sender.tab?.id || 0).then(sendResponse);
    return true;
  }

  if (msg.type === 'APPROVE_MATCHES') {
    approveMatchSignatures(msg.scopeKey, msg.signatures || []).then(sendResponse);
    return true;
  }

  if (msg.type === 'RECORD_ACTION') {
    writeAudit({ site: msg.site || 'AI site', ruleId: msg.ruleId || 'multiple', category: msg.category || 'Mixed', risk: msg.risk || 'unknown', action: msg.action || 'unknown', userMode: msg.userMode || 'basic' });
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'GET_POPUP_STATE') {
    getPopupState().then(sendResponse);
    return true;
  }

  if (msg.type === 'SET_PROTECTION_STYLE') {
    const style = ['gentle', 'balanced', 'strict'].includes(msg.style) ? msg.style : 'balanced';
    chrome.storage.local.set({ protectionStyle: style }, () => sendResponse({ ok: true, style }));
    return true;
  }


  if (msg.type === 'SET_PROTECTED_TERMS') {
    setProtectedTerms(msg.terms || '').then(sendResponse);
    return true;
  }

  if (msg.type === 'GET_PROTECTED_TERMS') {
    chrome.storage.local.get(['protectedTerms'], (d) => sendResponse({ ok: true, terms: d.protectedTerms || [] }));
    return true;
  }

  if (msg.type === 'PREVIEW_PROFILE') {
    previewProfile(msg.profile).then(sendResponse);
    return true;
  }

  if (msg.type === 'IMPORT_PROFILE_CONFIRMED') {
    importProfile(msg.profile).then(sendResponse);
    return true;
  }

  if (msg.type === 'IMPORT_PROFILE') {
    // Backward compatible path: preview only; popup should then confirm and call IMPORT_PROFILE_CONFIRMED.
    previewProfile(msg.profile).then(sendResponse);
    return true;
  }

  if (msg.type === 'EXPORT_PROFILE') {
    chrome.storage.local.get(['activeProfile', 'customSites', 'protectedTerms'], (d) => sendResponse(buildExportProfile(d.activeProfile, d.customSites || [], d.protectedTerms || [])));
    return true;
  }

  if (msg.type === 'GET_SITE_CONFIG') {
    getSiteConfigForUrl(msg.url || sender.tab?.url || '').then(sendResponse);
    return true;
  }

  if (msg.type === 'CHECK_INTEGRATIONS') {
    checkIntegrations().then(sendResponse);
    return true;
  }

  if (msg.type === 'REFRESH_ACTIVE_TAB') {
    refreshActiveTab().then(sendResponse);
    return true;
  }

  if (msg.type === 'TEST_CUSTOM_SELECTORS') {
    testCustomSelectors(sender.tab?.id).then(sendResponse);
    return true;
  }

  if (msg.type === 'GET_AUDIT') {
    chrome.storage.local.get(['auditLog'], (d) => sendResponse({ ok: true, auditLog: pruneAudit(d.auditLog || []) }));
    return true;
  }

  if (msg.type === 'SET_RAW_DEBUG') {
    const enabled = Boolean(msg.enabled);
    const expiresAt = enabled ? Date.now() + 30 * 60 * 1000 : 0;
    chrome.storage.local.set({ rawDebug: { enabled, expiresAt } }, () => sendResponse({ ok: true, enabled, expiresAt }));
    return true;
  }

  if (msg.type === 'CLEAR_APPROVED_SESSION') {
    clearApprovedSession().then(sendResponse);
    return true;
  }

  return false;
});

chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  if (sender.id !== TESTER_ID) return false;
  const action = message.action || message.type;
  const payload = message.payload || message;

  if (action === 'PING') {
    sendResponse({ ok: true, product: 'Sentinel+', version: VERSION });
    return false;
  }

  if (action === 'LLM_TESTER_RUN_COMPLETE' || action === 'INFERENCE_END') {
    const metrics = normalizeMetrics(payload);
    const safeUpdate = {
      llmTester: { present: true, working: true, lastSeen: Date.now() },
      lastMetrics: metrics,
      metricsVisible: Boolean(metrics && (metrics.tps !== null || metrics.ttftMs !== null)),
      integrationsKnown: true
    };
    chrome.storage.local.set(safeUpdate, () => {
      writeAudit({ site: 'LLM Tester', ruleId: 'telemetry', category: 'Integration', risk: 'low', action: 'metrics_received', userMode: 'advanced' });
      sendResponse({ ok: true, received: true });
    });
    return true;
  }

  if (action === 'TESTER_STATUS_UPDATE') {
    chrome.storage.local.set({ llmTester: { present: true, working: true, lastSeen: Date.now() }, integrationsKnown: true }, () => sendResponse({ ok: true }));
    return true;
  }

  return false;
});

async function processInput(text, siteName, siteUrl, tabId) {
  let raw = String(text || '');
  if (!raw.trim()) return { ok: true, decision: 'none', matches: [], redactedText: raw };

  const data = await storageGet(['protectionStyle', 'activeProfile', 'protectedTerms']);
  const style = data.protectionStyle || 'balanced';
  const rules = buildRules(data.activeProfile, data.protectedTerms || []);
  const scopeKey = makeScopeKey(tabId, siteName, siteUrl);
  const approved = await getApprovedSignatures(scopeKey);
  const scan = await scanText(raw, rules, scopeKey, approved);

  if (scan.matches.length === 0) {
    raw = null;
    return { ok: true, decision: 'none', matches: [], redactedText: text };
  }

  const highest = scan.highestRisk;
  let decision = decisionForStyle(style, highest);
  const forced = resolveForcedAction(scan.matches);
  if (forced && ACTION_RANK[forced] > ACTION_RANK[decision]) decision = forced === 'block' ? 'gate' : forced;
  if (scan.lockedNoOverride) decision = 'gate';

  const summary = scan.matches.map(m => ({
    id: m.id,
    label: m.label,
    category: m.category,
    risk: m.risk,
    count: m.count,
    locked: Boolean(m.locked),
    action: m.action || '',
    customMessage: m.customMessage || ''
  }));

  raw = null;
  return {
    ok: true,
    decision,
    highestRisk: highest,
    matches: summary,
    redactedText: scan.redactedText,
    message: buildMessage(decision, highest, summary),
    approvalSignatures: scan.approvalSignatures,
    scopeKey
  };
}

function decisionForStyle(style, highestRisk) {
  if (style === 'strict') return 'gate';
  if (style === 'gentle') return 'advise';
  return RISK_RANK[highestRisk] >= RISK_RANK.high ? 'gate' : 'advise';
}

function resolveForcedAction(matches) {
  let best = '';
  let bestRank = 0;
  for (const match of matches) {
    const action = String(match.action || '').toLowerCase();
    const normalized = action === 'block' ? 'gate' : action;
    const rank = ACTION_RANK[normalized] || 0;
    if (rank > bestRank) {
      best = normalized;
      bestRank = rank;
    }
  }
  return best;
}

function buildRules(profile, protectedTerms = []) {
  const builtins = DEFAULT_PATTERNS.map(r => ({ ...r, source: 'default', enabled: true }));

  const protectedRules = buildProtectedTermRules(protectedTerms);
  if (!profile || typeof profile !== 'object') return builtins.concat(protectedRules);
  const custom = Array.isArray(profile.rules) ? profile.rules : Array.isArray(profile.patterns) ? profile.patterns : [];
  const valid = custom.filter(r => r && r.enabled !== false && r.regex).map((r, idx) => ({
    id: String(r.id || `custom_${idx}`),
    label: String(r.label || r.id || `Custom Rule ${idx + 1}`),
    category: String(r.category || 'Custom'),
    risk: normalizeRisk(r.risk || 'medium'),
    action: normalizeRuleAction(r.action || ''),
    customMessage: r.message || r.customMessage || '',
    redactionLabel: r.redactionLabel || `[${String(r.category || 'CUSTOM').toUpperCase()} REDACTED]`,
    regex: String(r.regex),
    flags: String(r.flags || 'g'),
    enabled: r.enabled !== false,
    locked: Boolean(r.locked),
    noOverride: Boolean(r.noOverride),
    source: 'profile'
  }));
  return builtins.concat(protectedRules, valid);
}


function buildProtectedTermRules(protectedTerms) {
  const terms = Array.isArray(protectedTerms) ? protectedTerms : [];
  return terms
    .filter(t => t && t.enabled !== false && String(t.phrase || '').trim().length >= 2)
    .slice(0, 200)
    .map((t, idx) => {
      const phrase = String(t.phrase || '').trim();
      return {
        id: `protected_term_${stableHash(phrase.toLowerCase())}_${idx}`,
        label: 'Protected Term',
        category: 'Confidential Business',
        risk: 'high',
        action: 'gate',
        customMessage: 'Sentinel+ noticed a protected term you added. This may include client, case, project, or confidential business information.',
        redactionLabel: t.redactionLabel || '[PROTECTED TERM REDACTED]',
        regex: protectedTermRegex(phrase),
        flags: 'gi',
        enabled: true,
        source: 'protectedTerms'
      };
    });
}

function protectedTermRegex(phrase) {
  const escaped = escapeRegexLiteral(phrase).replace(/\s+/g, String.raw`\s+`);
  const startsWord = /^[A-Za-z0-9]/.test(phrase);
  const endsWord = /[A-Za-z0-9]$/.test(phrase);
  return `${startsWord ? String.raw`\b` : ''}${escaped}${endsWord ? String.raw`\b` : ''}`;
}

function escapeRegexLiteral(s) {
  return String(s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function stableHash(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(36);
}

async function setProtectedTerms(rawTerms) {
  const raw = Array.isArray(rawTerms) ? rawTerms.map(t => t?.phrase || t).join('\n') : String(rawTerms || '');
  const seen = new Set();
  const terms = raw.split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .filter(line => {
      const key = line.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, 200)
    .map((phrase, idx) => ({ id: `term_${idx}_${stableHash(phrase.toLowerCase())}`, phrase, enabled: true, redactionLabel: '[PROTECTED TERM REDACTED]' }));
  await storageSet({ protectedTerms: terms });
  return { ok: true, count: terms.length, terms };
}

function normalizeRuleAction(action) {
  const a = String(action || '').toLowerCase();
  if (['advise', 'gate', 'block'].includes(a)) return a;
  return '';
}

async function scanText(text, rules, scopeKey, approvedSet) {
  let redacted = text;
  const matches = [];
  let highestRisk = 'low';
  let lockedNoOverride = false;
  const approvalSignatures = [];

  for (const rule of rules) {
    let re;
    try { re = new RegExp(rule.regex, rule.flags || 'g'); } catch { continue; }
    if (!re.global) re = new RegExp(rule.regex, `${rule.flags || ''}g`);

    const found = [];
    let m;
    while ((m = re.exec(text)) !== null) {
      const value = m[0];
      if (!value) break;
      if (rule.id === 'credit_card_like') {
        const digits = value.replace(/\D/g, '');
        if (digits.length < 13 || digits.length > 19) continue;
      }
      if (rule.id === 'phone_international') {
        const digits = value.replace(/\D/g, '');
        if (!String(value).trim().startsWith('+')) continue;
        if (digits.length < 8 || digits.length > 15) continue;
      }

      if (rule.id === 'iban') {
        if (!isLikelyIban(value)) continue;
      }
      if (rule.id === 'swift_bic') {
        const compact = String(value || '').replace(/\s+/g, '');
        if (!/^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/.test(compact)) continue;
      }
      const signature = await signatureFor(scopeKey, rule.id, normalizeMatchedValue(rule, value));
      if (!approvedSet.has(signature)) found.push({ value, signature });
      if (m.index === re.lastIndex) re.lastIndex++;
    }

    if (found.length) {
      let label = rule.label;
      if (rule.id === 'credit_card_like' && found.some(v => luhn(v.value.replace(/\D/g, '')))) label = 'Valid-looking Credit Card Number';
      const risk = normalizeRisk(rule.risk);
      if (RISK_RANK[risk] > RISK_RANK[highestRisk]) highestRisk = risk;
      if (rule.locked && rule.noOverride && risk === 'critical') lockedNoOverride = true;
      for (const item of found) {
        redacted = redacted.split(item.value).join(rule.redactionLabel || '[REDACTED]');
        approvalSignatures.push(item.signature);
      }
      matches.push({ ...rule, label, risk, count: found.length });
    }
  }

  return { matches, highestRisk, redactedText: redacted, lockedNoOverride, approvalSignatures };
}

function normalizeMatchedValue(rule, value) {
  if (rule.id === 'credit_card_like' || rule.id === 'phone_us' || rule.id === 'phone_international' || rule.id === 'ssn') return String(value || '').replace(/\D/g, '');
  if (rule.id === 'iban' || rule.id === 'swift_bic') return String(value || '').replace(/[\s-]/g, '').toUpperCase();
  if (String(rule.id || '').startsWith('protected_term_')) return String(value || '').replace(/\s+/g, ' ').trim().toLowerCase();
  return String(value || '').trim();
}


function isLikelyIban(value) {
  const compact = String(value || '').replace(/[\s-]/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(compact)) return false;
  // ISO 13616 mod-97 checksum. This prevents many ordinary codes from being flagged as IBANs.
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const part = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
    for (const digit of part) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}

function luhn(digits) {
  if (!/^\d{13,19}$/.test(digits)) return false;
  let sum = 0, double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = Number(digits[i]);
    if (double) { n *= 2; if (n > 9) n -= 9; }
    sum += n; double = !double;
  }
  return sum % 10 === 0;
}

function normalizeRisk(risk) {
  const r = String(risk || '').toLowerCase();
  return ['low','medium','high','critical'].includes(r) ? r : 'medium';
}

function buildMessage(decision, risk, matches) {
  const custom = matches.find(m => m.customMessage)?.customMessage;
  if (custom) return custom;
  const names = [...new Set(matches.map(m => m.label))].slice(0, 3).join(', ');
  if (decision === 'advise') return `Sentinel+ noticed ${names}. Please check before sending.`;
  return `Sentinel+ found ${risk} risk information: ${names}.`;
}

function unsupportedSiteName(url) {
  try {
    const host = new URL(url).hostname.replace(/^www\./, '');
    const copilotHosts = [
      'copilot.microsoft.com',
      'copilot.cloud.microsoft',
      'm365.cloud.microsoft',
      'microsoft365.com',
      'edgeservices.bing.com',
      'sydney.bing.com',
      'bing.com'
    ];
    if (copilotHosts.some(h => host === h || host.endsWith(`.${h}`))) return 'Copilot';
  } catch (_) {}
  return '';
}

async function getPopupState() {
  let data = await storageGet(null);
  data = await refreshIntegrationPresence(data);
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const tabUrl = tab?.url || '';
  const unsupportedName = unsupportedSiteName(tabUrl);
  const siteName = friendlySiteName(tabUrl) || (await getSiteConfigForUrl(tabUrl)).siteName || '';
  const supported = Boolean(siteName);
  const unsupported = Boolean(!supported && unsupportedName);
  const attachment = supported && tab?.id ? await ensureContentScriptAttached(tab.id, siteName) : { attached: false };
  const protectionReady = Boolean(attachment.attached && (attachment.protectionReady || attachment.editorFound));
  const needsRefresh = Boolean(supported && !attachment.attached);
  const supportedButInactive = Boolean(supported && attachment.attached && !protectionReady);
  if (tab?.id && supported) {
    try {
      await chrome.action.setBadgeText({ tabId: tab.id, text: protectionReady ? '•' : '!' });
      await chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color: protectionReady ? '#22c55e' : '#f59e0b' });
    } catch (_) {}
  }
  const lastMetrics = data.metricsVisible && data.llmTester?.present ? data.lastMetrics : null;
  const integrations = buildIntegrationState(data);
  const approvedCount = await countApprovedSession();
  return {
    ok: true,
    version: VERSION,
    siteName,
    supported,
    unsupported,
    unsupportedSiteName: unsupportedName,
    pageAttached: Boolean(attachment.attached),
    protectionReady,
    editorFound: Boolean(attachment.editorFound),
    sendButtonFound: Boolean(attachment.sendButtonFound),
    attachedFrame: attachment.frameUrl || '',
    attachedFrameId: attachment.frameId ?? null,
    attachError: attachment.error || '',
    needsRefresh,
    supportedButInactive,
    protectionStyle: data.protectionStyle || 'balanced',
    userMode: 'Basic',
    lastMetrics,
    integrations,
    activeProfile: sanitizeProfileForPopup(data.activeProfile),
    customSites: data.customSites || data.activeProfile?.customSites || [],
    protectedTerms: data.protectedTerms || [],
    approvedCount,
    rawDebug: data.rawDebug || { enabled:false, expiresAt:0 }
  };
}


function rememberContentFrame(tabId, frameStatus) {
  const frameId = Number.isInteger(frameStatus.frameId) ? frameStatus.frameId : 0;
  let record = activeContentByTab.get(tabId);
  if (!record || !(record.frames instanceof Map)) record = { frames: new Map(), lastSeen: 0 };
  record.frames.set(frameId, { ...frameStatus, frameId, lastSeen: Date.now() });
  record.lastSeen = Date.now();
  activeContentByTab.set(tabId, record);
  return chooseBestContentFrame(tabId, frameStatus.siteName) || frameStatus;
}

function frameStatusScore(status) {
  if (!status) return -1;
  let score = 0;
  if (status.protectionReady) score += 100;
  if (status.editorFound) score += 60;
  if (status.sendButtonFound) score += 10;
  if (Number.isInteger(status.frameId) && status.frameId !== 0) score += 3;
  return score;
}

function chooseBestContentFrame(tabId, expectedSiteName = '') {
  const record = activeContentByTab.get(tabId);
  if (!record || !(record.frames instanceof Map)) return null;
  const now = Date.now();
  const fresh = [];
  for (const [frameId, status] of record.frames.entries()) {
    if (!status || now - status.lastSeen > ACTIVE_CONTENT_TTL_MS) {
      record.frames.delete(frameId);
      continue;
    }
    if (expectedSiteName && status.siteName && status.siteName !== expectedSiteName) continue;
    fresh.push(status);
  }
  if (!record.frames.size) activeContentByTab.delete(tabId);
  if (!fresh.length) return null;
  fresh.sort((a, b) => frameStatusScore(b) - frameStatusScore(a) || (b.lastSeen || 0) - (a.lastSeen || 0));
  return fresh[0];
}

function normalizeAttachment(resp, fallbackFrameId = 0) {
  if (!resp || !resp.attached) return { attached:false };
  return {
    attached: true,
    siteName: resp.siteName || '',
    frameUrl: resp.frameUrl || resp.url || '',
    frameId: Number.isInteger(resp.frameId) ? resp.frameId : fallbackFrameId,
    editorFound: Boolean(resp.editorFound),
    sendButtonFound: Boolean(resp.sendButtonFound),
    protectionReady: Boolean(resp.protectionReady || resp.editorFound)
  };
}

function preferReadyAttachment(...items) {
  const attached = items.filter(item => item && item.attached);
  if (!attached.length) return { attached:false };
  attached.sort((a, b) => frameStatusScore(b) - frameStatusScore(a));
  return attached[0];
}

async function pingContentScript(tabId, frameId = null) {
  try {
    const resp = frameId === null || frameId === undefined
      ? await chrome.tabs.sendMessage(tabId, { type: 'SENTINEL_PING' })
      : await chrome.tabs.sendMessage(tabId, { type: 'SENTINEL_PING' }, { frameId });
    if (resp && resp.ok) {
      return normalizeAttachment({
        attached: true,
        siteName: resp.siteName || '',
        frameUrl: resp.frameUrl || resp.url || '',
        frameId: Number.isInteger(resp.frameId) ? resp.frameId : (frameId ?? 0),
        editorFound: Boolean(resp.editorFound),
        sendButtonFound: Boolean(resp.sendButtonFound),
        protectionReady: Boolean(resp.protectionReady || resp.editorFound)
      }, frameId ?? 0);
    }
  } catch (_) {}
  return { attached: false };
}

function recentActiveContent(tabId, expectedSiteName = '') {
  const best = chooseBestContentFrame(tabId, expectedSiteName);
  if (!best) return { attached:false };
  return normalizeAttachment({ attached:true, ...best }, best.frameId ?? 0);
}

async function ensureContentScriptAttached(tabId, expectedSiteName = '') {
  if (!tabId) return { attached: false, injected: false };

  // First, reuse a recent ready frame if we have one. Do not let a non-ready
  // top frame short-circuit a ready child frame.
  const recent = recentActiveContent(tabId, expectedSiteName);
  if (recent.attached && recent.protectionReady) return { ...recent, injected:false, frameHeartbeat:true };

  const initial = await pingContentScript(tabId);
  const initialOk = initial.attached && (!expectedSiteName || initial.siteName === expectedSiteName);
  if (initialOk && initial.protectionReady) return { ...initial, injected: false };

  let injectionResults = [];
  try {
    injectionResults = await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, files: ['config.js', 'content.js'] });
  } catch (e) {
    // If the content script was already attached but not editor-ready, report
    // that honestly rather than turning it into a misleading refresh prompt.
    if (initialOk || recent.attached) return { ...preferReadyAttachment(recent, initial), injected:false, error: e.message || String(e) };
    return { attached: false, injected: false, error: e.message || String(e) };
  }

  await delay(650);

  const frameIds = [...new Set((injectionResults || []).map(r => r.frameId).filter(id => Number.isInteger(id)))];
  const framePing = await pingKnownFrames(tabId, frameIds, expectedSiteName);
  if (framePing.attached && framePing.protectionReady) return { ...framePing, injected: true };

  const after = await pingContentScript(tabId);
  const afterOk = after.attached && (!expectedSiteName || after.siteName === expectedSiteName);
  if (afterOk && after.protectionReady) return { ...after, injected: true };

  const afterRecent = recentActiveContent(tabId, expectedSiteName);
  if (afterRecent.attached && afterRecent.protectionReady) return { ...afterRecent, injected:true, frameHeartbeat:true };

  const bestNonReady = preferReadyAttachment(afterRecent, framePing, afterOk ? after : null, recent, initialOk ? initial : null);
  if (bestNonReady.attached) return { ...bestNonReady, injected:true, supportedButInactive:true };

  return { attached:false, injected:true, error:'Sentinel+ could not confirm a content-script heartbeat on this tab.' };
}

async function pingKnownFrames(tabId, frameIds, expectedSiteName = '') {
  let fallback = { attached:false };
  for (const frameId of frameIds || []) {
    const resp = await pingContentScript(tabId, frameId);
    if (!resp.attached || (expectedSiteName && resp.siteName !== expectedSiteName)) continue;
    if (resp.protectionReady) return resp;
    fallback = preferReadyAttachment(fallback, resp);
  }
  return fallback;
}

function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function friendlySiteName(url) {
  try {
    const host = new URL(url).hostname.replace(/^www\./,'');
    const map = [
      ['chatgpt.com','ChatGPT'], ['chat.openai.com','ChatGPT'], ['claude.ai','Claude'], ['gemini.google.com','Gemini'],  ['perplexity.ai','Perplexity'], ['grok.com','Grok'], ['chat.mistral.ai','Mistral Chat'], ['chat.deepseek.com','DeepSeek'], ['deepseek.com','DeepSeek'], ['meta.ai','Meta AI'], ['chat.qwen.ai','Qwen / Tongyi'], ['tongyi.aliyun.com','Qwen / Tongyi'], ['qianwen.aliyun.com','Qwen / Tongyi'], ['kimi.moonshot.cn','Kimi'], ['poe.com','Poe']
    ];
    const found = map.find(([h]) => host === h || host.endsWith(`.${h}`));
    return found ? found[1] : '';
  } catch { return ''; }
}

async function refreshIntegrationPresence(data) {
  const updates = {};

  const tester = await pingTester();
  if (tester.present) {
    updates.llmTester = tester;
  } else if (data?.llmTester?.present || data?.metricsVisible) {
    updates.llmTester = { present:false, working:false, lastSeen:0 };
    updates.lastMetrics = null;
    updates.metricsVisible = false;
  }

  const merged = { ...(data || {}), ...updates };
  updates.integrationsKnown = Boolean(
    merged.llmTester?.present ||
    merged.parametizer?.present ||
    merged.localLlm?.present
  );

  if (Object.keys(updates).length) await storageSet(updates);
  return { ...(data || {}), ...updates };
}

function buildIntegrationState(data) {
  const out = [];
  if (data.llmTester?.present) out.push({ id:'llmTester', label:'LLM Tester', working:Boolean(data.llmTester.working), status: data.llmTester.working ? 'connected' : 'refresh' });
  if (data.parametizer?.present) out.push({ id:'parametizer', label:'Parametizer', working:Boolean(data.parametizer.working), status: data.parametizer.working ? 'connected' : 'refresh', vram: data.parametizer.vram || null });
  if (data.localLlm?.present) out.push({ id:'localLlm', label:'Local LLM', working:Boolean(data.localLlm.working), status: data.localLlm.working ? 'connected' : 'refresh' });
  return out;
}

async function refreshActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return { ok:false, error:'No active tab.' };
  try {
    await chrome.tabs.reload(tab.id);
    return { ok:true };
  } catch (e) {
    return { ok:false, error:e.message || String(e) };
  }
}

async function checkIntegrations() {
  const tester = await pingTester();
  const param = await pingParametizer();
  const updates = {
    integrationsKnown: tester.present || param.present,
    llmTester: tester.present ? tester : { present:false, working:false, lastSeen:0 },
    parametizer: param.present ? param : { present:false, working:false, lastSeen:0 }
  };
  if (!tester.present) {
    updates.lastMetrics = null;
    updates.metricsVisible = false;
  }
  await storageSet(updates);
  const merged = { ...await storageGet(null), ...updates };
  const integrations = buildIntegrationState(merged);
  return {
    ok: true,
    integrations,
    message: integrations.length ? 'Status refreshed.' : 'Checked: no integrations detected.'
  };
}

function pingTester() {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendMessage(TESTER_ID, { action:'PING', source:'sentinel-plus', timestamp:Date.now() }, (resp) => {
        if (chrome.runtime.lastError || !resp) resolve({ present:false, working:false });
        else resolve({ present:true, working:true, lastSeen:Date.now() });
      });
    } catch { resolve({ present:false, working:false }); }
  });
}

async function pingParametizer() {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 800);
    const res = await fetch(`${PARAMETIZER_BASE}/ipc/status`, { signal: ctrl.signal });
    clearTimeout(timer);
    if (!res.ok) return { present:false, working:false };
    const data = await res.json().catch(() => ({}));
    return { present:true, working:true, lastSeen:Date.now(), vram: data.vram || data.vramInfo || null };
  } catch { return { present:false, working:false }; }
}

function normalizeMetrics(payload) {
  const tps = payload.tps ?? payload.tokensPerSecond ?? null;
  const ttft = payload.ttftMs ?? payload.ttft ?? payload.timeToFirstTokenMs ?? null;
  return { tps: numericOrString(tps), ttftMs: normalizeTtft(ttft), timestamp: Date.now(), source: 'LLM Tester' };
}
function numericOrString(v) { if (v == null || v === '—') return null; const n = Number(String(v).replace(/ms$/,'')); return Number.isFinite(n) ? n : String(v); }
function normalizeTtft(v) { if (v == null || v === '—') return null; const n = Number(String(v).replace(/ms$/,'')); return Number.isFinite(n) ? n : String(v); }

function writeAudit(entry) {
  chrome.storage.local.get(['auditLog'], (d) => {
    const list = pruneAudit(d.auditLog || []);
    list.unshift({ time: Date.now(), site: entry.site, ruleId: entry.ruleId, category: entry.category, risk: entry.risk, action: entry.action, userMode: entry.userMode });
    chrome.storage.local.set({ auditLog: list.slice(0, 500) });
  });
}
function pruneAudit(list) { const cutoff = Date.now() - AUDIT_RETENTION_DAYS*24*60*60*1000; return (Array.isArray(list) ? list : []).filter(x => x && x.time >= cutoff); }

async function previewProfile(profile) {
  const result = validateProfile(profile);
  if (!result.ok) return result;
  const migrated = migrateProfile(profile);
  return { ok: true, preview: true, profile: migrated, summary: summarizeProfile(migrated), warnings: profileWarnings(migrated) };
}

async function importProfile(profile) {
  const result = validateProfile(profile);
  if (!result.ok) return result;
  const migrated = migrateProfile(profile);
  const customSites = migrated.customSites || [];
  await storageSet({ activeProfile: migrated, customSites });
  await registerCustomSites(customSites);
  return { ok: true, summary: summarizeProfile(migrated), warnings: profileWarnings(migrated) };
}

function validateProfile(profile) {
  if (!profile || typeof profile !== 'object') return { ok:false, error:'Profile must be a JSON object.' };
  const rules = Array.isArray(profile.rules) ? profile.rules : Array.isArray(profile.patterns) ? profile.patterns : [];
  for (const r of rules) {
    if (!r.regex) return { ok:false, error:`Rule ${r.id || r.label || '(unnamed)'} is missing regex.` };
    try { new RegExp(r.regex, r.flags || 'g'); } catch(e) { return { ok:false, error:`Invalid regex in ${r.id || r.label}: ${e.message}` }; }
  }
  const sites = Array.isArray(profile.customSites) ? profile.customSites : [];
  for (const s of sites) {
    if (!s.domain && !s.urlPattern) return { ok:false, error:`Custom site ${s.name || '(unnamed)'} needs a domain or urlPattern.` };
    if (s.inputSelector) { try { documentlessSelectorCheck(s.inputSelector); } catch(e) { return { ok:false, error:`Invalid input selector for ${s.name || s.domain}: ${e.message}` }; } }
    if (s.sendSelector) { try { documentlessSelectorCheck(s.sendSelector); } catch(e) { return { ok:false, error:`Invalid send selector for ${s.name || s.domain}: ${e.message}` }; } }
  }
  return { ok:true };
}

function documentlessSelectorCheck(selector) {
  // Service workers do not have document.querySelector; use a cheap syntax check via registration-time best effort.
  if (typeof selector !== 'string' || !selector.trim()) throw new Error('selector is empty');
  if (/javascript:/i.test(selector)) throw new Error('selector cannot contain javascript:');
  return true;
}

function migrateProfile(profile) {
  const p = { ...profile };
  const notes = Array.isArray(p.migrationNotes) ? [...p.migrationNotes] : [];
  if (!p.schemaVersion) notes.push('Added schemaVersion 2.0');
  p.schemaVersion = '2.0';
  p.profileName = p.profileName || p.name || 'Imported Profile';
  p.rules = Array.isArray(p.rules) ? p.rules : Array.isArray(p.patterns) ? p.patterns : [];
  delete p.patterns;
  p.customSites = Array.isArray(p.customSites) ? p.customSites : [];
  p.migrationNotes = notes.length ? notes : ['Imported/migrated to schema 2.0'];
  return p;
}

function profileWarnings(p) {
  const rules = p.rules || [];
  const warnings = [];
  const locked = rules.filter(r => r.locked).length;
  const noOverride = rules.filter(r => r.noOverride).length;
  if (locked) warnings.push(`${locked} locked rule(s)`);
  if (noOverride) warnings.push(`${noOverride} no-override rule(s) will require a strong consent gate in this build.`);
  if ((p.customSites || []).length) warnings.push(`${p.customSites.length} custom AI site(s) included. Browser permission may be requested for those domains.`);
  return warnings;
}

function summarizeProfile(p) {
  const rules = p.rules || [];
  const riskCounts = rules.reduce((a,r)=>{ const k=normalizeRisk(r.risk); a[k]=(a[k]||0)+1; return a; },{});
  const actionCounts = rules.reduce((a,r)=>{ const k=normalizeRuleAction(r.action || 'default') || 'default'; a[k]=(a[k]||0)+1; return a; },{});
  const categories = [...new Set(rules.map(r => r.category || 'Custom'))].sort();
  return {
    profileName:p.profileName || p.name || 'Imported Profile',
    version:p.version || '',
    schemaVersion:p.schemaVersion,
    trustedSource:p.trustedSource || '',
    ruleCount:rules.length,
    lockedRuleCount:rules.filter(r=>r.locked).length,
    customSiteCount:(p.customSites||[]).length,
    customMessageCount:rules.filter(r=>r.message || r.customMessage).length,
    categories,
    riskCounts,
    actionCounts,
    migrationNotes:p.migrationNotes || []
  };
}

function buildExportProfile(activeProfile, customSites, protectedTerms = []) {
  const base = activeProfile || { schemaVersion:'2.0', profileName:'Sentinel+ Custom Profile', version:'1.0.0', trustedSource:'', rules:[], migrationNotes:[] };
  return { ...base, schemaVersion:'2.0', customSites: customSites || base.customSites || [],
    protectedTerms: protectedTerms || [], exportedAt:new Date().toISOString() };
}
function sanitizeProfileForPopup(p) { if (!p) return null; return summarizeProfile(p); }

async function registerCustomSites(customSites) {
  if (!chrome.scripting?.registerContentScripts) return;
  const existing = await chrome.scripting.getRegisteredContentScripts().catch(() => []);
  const stale = existing.filter(s => s.id.startsWith('sentinel-custom-')).map(s => s.id);
  if (stale.length) await chrome.scripting.unregisterContentScripts({ ids: stale }).catch(() => {});

  const scripts = [];
  for (const site of (Array.isArray(customSites) ? customSites : [])) {
    const matches = siteToMatches(site);
    if (!matches.length) continue;
    scripts.push({
      id: `sentinel-custom-${safeScriptId(site.domain || site.urlPattern || site.name || String(scripts.length))}`.slice(0, 90),
      matches,
      js: ['config.js', 'content.js'],
      runAt: 'document_idle',
      allFrames: false
    });
  }
  if (scripts.length) await chrome.scripting.registerContentScripts(scripts).catch(() => {});
}

function siteToMatches(site) {
  if (!site || typeof site !== 'object') return [];
  if (site.urlPattern) return [String(site.urlPattern)];
  const domain = String(site.domain || '').trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!domain) return [];
  return [`https://${domain}/*`];
}
function safeScriptId(s) { return String(s).toLowerCase().replace(/[^a-z0-9_-]/g, '-').replace(/-+/g, '-'); }

async function getSiteConfigForUrl(url) {
  const data = await storageGet(['customSites']);
  const sites = data.customSites || [];
  let u;
  try { u = new URL(url); } catch { return { ok:false, siteName:'' }; }
  for (const site of sites) {
    const domain = String(site.domain || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
    const host = u.hostname.replace(/^www\./, '');
    const pattern = site.urlPattern || '';
    const matchByDomain = domain && (host === domain || host.endsWith(`.${domain}`));
    const matchByPattern = pattern && urlMatchesPattern(url, pattern);
    if (matchByDomain || matchByPattern) {
      return { ok:true, siteName: site.name || site.friendlyName || domain || 'Custom AI Site', selectors: { inputSelector: site.inputSelector || site.editorSelector || '', sendSelector: site.sendSelector || site.buttonSelector || '' } };
    }
  }
  return { ok:false, siteName:'' };
}

function urlMatchesPattern(url, pattern) {
  const escaped = String(pattern).replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`).test(url);
}

async function testCustomSelectors(tabId) {
  if (!tabId) return { ok:false, error:'No active tab.' };
  try {
    return await chrome.tabs.sendMessage(tabId, { type:'SENTINEL_TEST_SELECTORS' });
  } catch(e) {
    return { ok:false, error:e.message || String(e) };
  }
}

function makeScopeKey(tabId, siteName, siteUrl) {
  let urlPart = '';
  try {
    const u = new URL(siteUrl || '');
    urlPart = `${u.origin}${u.pathname}`;
  } catch { urlPart = String(siteUrl || ''); }
  return `${tabId || 'tab'}|${siteName || 'site'}|${urlPart}`;
}

async function signatureFor(scopeKey, ruleId, normalizedValue) {
  const material = `${scopeKey}|${ruleId}|${normalizedValue}`;
  const data = new TextEncoder().encode(material);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getApprovedStore() {
  const area = chrome.storage.session || chrome.storage.local;
  const data = await new Promise(resolve => area.get(['approvedMatches'], resolve));
  const now = Date.now();
  const store = data.approvedMatches && typeof data.approvedMatches === 'object' ? data.approvedMatches : {};
  let changed = false;
  for (const [sig, meta] of Object.entries(store)) {
    if (!meta || meta.expiresAt <= now) { delete store[sig]; changed = true; }
  }
  if (changed) await new Promise(resolve => area.set({ approvedMatches: store }, resolve));
  return store;
}

async function getApprovedSignatures(scopeKey) {
  const store = await getApprovedStore();
  const set = new Set();
  for (const [sig, meta] of Object.entries(store)) {
    if (meta.scopeKey === scopeKey) set.add(sig);
  }
  return set;
}

async function approveMatchSignatures(scopeKey, signatures) {
  const area = chrome.storage.session || chrome.storage.local;
  const store = await getApprovedStore();
  const expiresAt = Date.now() + APPROVAL_TTL_MS;
  for (const signature of signatures) {
    if (typeof signature === 'string' && signature.length >= 32) {
      store[signature] = { scopeKey, expiresAt };
    }
  }
  await new Promise(resolve => area.set({ approvedMatches: store }, resolve));
  return { ok:true, count:Object.keys(store).length };
}

async function clearApprovedSession() {
  const area = chrome.storage.session || chrome.storage.local;
  await new Promise(resolve => area.set({ approvedMatches: {} }, resolve));
  return { ok:true };
}

async function countApprovedSession() {
  const store = await getApprovedStore();
  return Object.keys(store).length;
}

function storageGet(keys) { return new Promise(resolve => chrome.storage.local.get(keys, resolve)); }
function storageSet(obj) { return new Promise(resolve => chrome.storage.local.set(obj, resolve)); }
