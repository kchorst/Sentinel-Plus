
// content.js — Sentinel+ v2.2.4 beta candidate build
// P0 invariant: Sentinel+ must never silently block. If it stops a send, it must show a visible choice.
// Order: normal drawer -> emergency in-page alert -> native confirm -> visible alert/fail-open.
// No clipboard access. No raw prompt persistence.

(async () => {
  if (globalThis.__sentinelPlusContentLoaded) return;
  globalThis.__sentinelPlusContentLoaded = true;
  const runtimeConfig = await resolveRuntimeConfig();
  const siteName = runtimeConfig.siteName;
  if (!siteName) return;

  const customSelectors = runtimeConfig.selectors || {};
  const siteProfile = getSiteProfile(siteName, location.hostname);
  ensureSentinelStyles();
  announceActive();
  setInterval(announceActive, 10000);
  watchForComposerChanges();

  const SUBMIT_BYPASS_TTL_MS = 1600;
  let isProcessingMutex = false;
  let submitBypass = null;
  let lastSubmitIntent = null;

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' || event.shiftKey) return;
    const editor = findEditor();
    if (!editor || !isSameEditor(event.target, editor)) return;
    intercept(event, 'enter');
  }, true);

  document.addEventListener('click', (event) => {
    const button = findClickedSendButton(event.target, event);
    if (!button) return;
    intercept(event, 'click', button);
  }, true);

  document.addEventListener('submit', (event) => {
    const editor = findEditor();
    if (!editor) return;
    const form = event.target && event.target.nodeType === 1 ? event.target : null;
    if (!form || (editor.form !== form && !form.contains(editor))) return;
    intercept(event, 'submit', null, form);
  }, true);

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || typeof msg !== 'object') return false;
    if (msg.type === 'SENTINEL_PING') {
      const status = getProtectionStatus();
      sendResponse({ ok: true, siteName, url: location.href, ...status });
      return false;
    }
    if (msg.type === 'SENTINEL_TEST_SELECTORS') {
      const status = getProtectionStatus();
      sendResponse({ ok: true, ...status, siteName });
      return false;
    }
    return false;
  });

  function intercept(event, kind, button = null, form = null) {
    const editor = findEditor();
    if (!editor) return;

    let text = readEditor(editor);
    if (!text.trim()) return;

    if (shouldBypassCurrentSubmit(text)) {
      return;
    }

    if (isProcessingMutex) {
      event.preventDefault();
      event.stopImmediatePropagation();
      return;
    }

    isProcessingMutex = true;
    lastSubmitIntent = { kind, button, form };
    event.preventDefault();
    event.stopImmediatePropagation();

    chrome.runtime.sendMessage({ type: 'PROCESS_INPUT', text, siteName, siteUrl: location.href }, async (response) => {
      const err = chrome.runtime.lastError;
      text = null;

      if (err) {
        releaseAndResume();
        return;
      }

      if (!response || response.decision === 'none') {
        releaseAndResume();
        return;
      }

      if (response.decision === 'advise') {
        showAdvisory(response, editor);
        record(response, 'advised');
        setTimeout(releaseAndResume, 350);
        return;
      }

      await handleConsentDecision(response, editor);
    });
  }

  async function handleConsentDecision(response, editor) {
    const action = await getVisibleUserChoice(response);

    if (action === 'continue') {
      await approveMatches(response);
      record(response, 'continued');
      releaseAndResume();
      return;
    }

    if (action === 'redact') {
      const redactedText = response.redactedText || readEditor(editor);
      const wrote = writeEditor(editor, redactedText);
      if (!wrote) {
        showRedactionFallback(redactedText);
        record(response, 'redact_failed');
      } else {
        record(response, 'redacted');
      }
      releaseOnly();
      return;
    }

    record(response, 'cancelled');
    releaseOnly();
  }

  async function getVisibleUserChoice(response) {
    removeAllSentinelUi();

    try {
      const normal = mountConsentUi(response, 'normal');
      if (await verifyVisibleChoice(normal)) {
        return await normal.promise;
      }
      normal.host.remove();
    } catch (_) {
      removeOverlay();
    }

    try {
      const emergency = mountConsentUi(response, 'emergency');
      if (await verifyVisibleChoice(emergency)) {
        return await emergency.promise;
      }
      emergency.host.remove();
    } catch (_) {
      removeEmergency();
    }

    return nativeConfirmFallback(response);
  }

  function mountConsentUi(response, mode) {
    const host = document.createElement('div');
    host.id = mode === 'emergency' ? 'sentinel-emergency-alert' : 'sentinel-consent-overlay';
    host.setAttribute('data-sentinel-ui', mode);
    host.style.setProperty('all', 'initial', 'important');
    host.style.setProperty('position', 'fixed', 'important');
    host.style.setProperty('z-index', '2147483647', 'important');
    host.style.setProperty('pointer-events', 'auto', 'important');

    if (mode === 'emergency') {
      host.style.setProperty('right', '14px', 'important');
      host.style.setProperty('bottom', '14px', 'important');
      host.style.setProperty('width', 'min(420px, calc(100vw - 28px))', 'important');
    } else {
      host.style.setProperty('inset', '0', 'important');
      host.style.setProperty('background', 'rgba(2,6,23,.38)', 'important');
      host.style.setProperty('display', 'flex', 'important');
      host.style.setProperty('align-items', 'flex-end', 'important');
      host.style.setProperty('justify-content', 'center', 'important');
      host.style.setProperty('padding', '18px', 'important');
    }

    let resolveChoice;
    const promise = new Promise(resolve => { resolveChoice = resolve; });

    const card = document.createElement('div');
    card.setAttribute('data-sentinel-card', 'true');
    card.className = mode === 'emergency' ? 'sentinel-emergency-card' : 'sentinel-card';
    card.style.setProperty('font-family', 'Segoe UI, Arial, sans-serif', 'important');
    card.style.setProperty('background', mode === 'emergency' ? '#1f2937' : '#111827', 'important');
    card.style.setProperty('color', '#f8fafc', 'important');
    card.style.setProperty('border', '1px solid rgba(255,255,255,.22)', 'important');
    card.style.setProperty('border-radius', '16px', 'important');
    card.style.setProperty('padding', mode === 'emergency' ? '12px' : '14px', 'important');
    card.style.setProperty('box-shadow', '0 18px 60px rgba(0,0,0,.48)', 'important');
    card.style.setProperty('width', mode === 'emergency' ? '100%' : 'min(520px, calc(100vw - 28px))', 'important');
    card.style.setProperty('box-sizing', 'border-box', 'important');

    const title = document.createElement('div');
    title.textContent = mode === 'emergency' ? 'Sentinel+ needs your choice' : 'Sentinel+ found sensitive information';
    title.style.setProperty('font-weight', '800', 'important');
    title.style.setProperty('font-size', '15px', 'important');
    title.style.setProperty('margin', '0 0 6px', 'important');
    card.appendChild(title);

    const msg = document.createElement('div');
    msg.textContent = response.message || 'Please review before sending.';
    msg.style.setProperty('color', '#cbd5e1', 'important');
    msg.style.setProperty('font-size', '13px', 'important');
    msg.style.setProperty('line-height', '1.35', 'important');
    msg.style.setProperty('margin', '0 0 10px', 'important');
    card.appendChild(msg);

    const list = document.createElement('div');
    for (const match of (response.matches || []).slice(0, 5)) {
      const row = document.createElement('div');
      row.style.setProperty('display', 'flex', 'important');
      row.style.setProperty('justify-content', 'space-between', 'important');
      row.style.setProperty('gap', '12px', 'important');
      row.style.setProperty('border-top', '1px solid rgba(255,255,255,.1)', 'important');
      row.style.setProperty('padding', '7px 0', 'important');

      const label = document.createElement('b');
      label.textContent = match.label || 'Sensitive information';
      label.style.setProperty('color', '#f8fafc', 'important');
      label.style.setProperty('font-size', '13px', 'important');

      const detail = document.createElement('span');
      detail.textContent = `${match.risk || ''} · ${match.category || ''} · ${Number(match.count || 1)}`;
      detail.style.setProperty('color', '#94a3b8', 'important');
      detail.style.setProperty('font-size', '12px', 'important');

      row.append(label, detail);
      list.appendChild(row);
    }
    card.appendChild(list);

    const actions = document.createElement('div');
    actions.style.setProperty('display', 'flex', 'important');
    actions.style.setProperty('gap', '8px', 'important');
    actions.style.setProperty('margin-top', '10px', 'important');

    const continueBtn = makeActionButton('Continue', '#2563eb', '#fff', () => choose('continue'));
    continueBtn.setAttribute('data-sentinel-action', 'continue');
    const redactBtn = makeActionButton('Redact', '#22c55e', '#052e16', () => choose('redact'));
    redactBtn.setAttribute('data-sentinel-action', 'redact');
    const cancelBtn = makeActionButton('Cancel', '#475569', '#fff', () => choose('cancel'));
    cancelBtn.setAttribute('data-sentinel-action', 'cancel');

    actions.append(continueBtn, redactBtn, cancelBtn);
    card.appendChild(actions);
    host.appendChild(card);

    (document.body || document.documentElement).appendChild(host);

    function choose(action) {
      host.remove();
      resolveChoice(action);
    }

    return { host, card, promise };
  }

  function makeActionButton(label, background, color, onClick) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = label;
    btn.style.setProperty('flex', '1', 'important');
    btn.style.setProperty('border', '0', 'important');
    btn.style.setProperty('border-radius', '10px', 'important');
    btn.style.setProperty('padding', '9px 10px', 'important');
    btn.style.setProperty('font-weight', '800', 'important');
    btn.style.setProperty('cursor', 'pointer', 'important');
    btn.style.setProperty('font-family', 'Segoe UI, Arial, sans-serif', 'important');
    btn.style.setProperty('font-size', '13px', 'important');
    btn.style.setProperty('background', background, 'important');
    btn.style.setProperty('color', color, 'important');
    btn.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      onClick();
    });
    return btn;
  }

  async function verifyVisibleChoice(mounted) {
    await nextFrame();
    await nextFrame();

    const host = mounted?.host;
    const card = mounted?.card || host?.querySelector?.('[data-sentinel-card="true"]');
    const continueBtn = host?.querySelector?.('[data-sentinel-action="continue"]');
    const redactBtn = host?.querySelector?.('[data-sentinel-action="redact"]');
    const cancelBtn = host?.querySelector?.('[data-sentinel-action="cancel"]');

    if (!host || !host.isConnected || !card || !continueBtn || !redactBtn || !cancelBtn) return false;
    if (!isElementVisible(host) || !isElementVisible(card) || !isElementVisible(continueBtn)) return false;

    const candidates = [continueBtn, redactBtn, cancelBtn, card];
    return candidates.some(el => isTopClickable(el, host));
  }

  function isElementVisible(el) {
    try {
      const rect = el.getBoundingClientRect();
      const style = window.getComputedStyle(el);
      if (rect.width < 8 || rect.height < 8) return false;
      if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0) return false;
      if (rect.bottom < 0 || rect.right < 0 || rect.top > window.innerHeight || rect.left > window.innerWidth) return false;
      return true;
    } catch (_) {
      return false;
    }
  }

  function isTopClickable(el, host) {
    try {
      const rect = el.getBoundingClientRect();
      const x = Math.min(Math.max(rect.left + rect.width / 2, 1), window.innerWidth - 1);
      const y = Math.min(Math.max(rect.top + rect.height / 2, 1), window.innerHeight - 1);
      const top = document.elementFromPoint(x, y);
      return Boolean(top && (top === el || el.contains(top) || host.contains(top)));
    } catch (_) {
      return false;
    }
  }

  function nextFrame() {
    return new Promise(resolve => requestAnimationFrame(() => resolve()));
  }

  function nativeConfirmFallback(response) {
    const matches = (response.matches || []).slice(0, 5).map(m => `- ${m.label || 'Sensitive information'} (${m.risk || 'risk'})`).join('\n');
    const message = `Sentinel+ found sensitive information.\n\n${matches || 'Sensitive information detected.'}\n\nOK = Continue sending\nCancel = Do not send`;

    try {
      return window.confirm(message) ? 'continue' : 'cancel';
    } catch (_) {
      try {
        window.alert('Sentinel+ found sensitive information, but the page blocked the normal warning. Sentinel+ will continue so your message is not silently blocked.');
      } catch (__) {}
      return 'continue';
    }
  }

  function showAdvisory(response, editor) {
    showToast(response.message || 'Sentinel+ noticed sensitive information. Please check before sending.');
    highlightEditor(editor);
  }

  function highlightEditor(editor) {
    if (!editor) return;
    editor.classList?.add('sentinel-advisory-highlight');
    setTimeout(() => editor.classList?.remove('sentinel-advisory-highlight'), 2600);
  }

  function record(response, action) {
    const first = response.matches?.[0] || {};
    chrome.runtime.sendMessage({
      type: 'RECORD_ACTION',
      site: siteName,
      ruleId: first.id || 'multiple',
      category: first.category || 'Mixed',
      risk: response.highestRisk || first.risk || 'unknown',
      action,
      userMode: 'basic'
    }, () => void chrome.runtime.lastError);
  }

  function approveMatches(response) {
    if (!response.approvalSignatures?.length || !response.scopeKey) return Promise.resolve();
    return new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'APPROVE_MATCHES', scopeKey: response.scopeKey, signatures: response.approvalSignatures }, () => resolve());
    });
  }

  function releaseAndResume() {
    isProcessingMutex = false;
    setSubmitBypassForCurrentText();

    const intent = lastSubmitIntent;
    lastSubmitIntent = null;

    if (intent?.kind === 'click' && intent.button) {
      intent.button.click();
      return;
    }

    if (intent?.kind === 'submit' && intent.form) {
      try {
        if (typeof intent.form.requestSubmit === 'function') intent.form.requestSubmit();
        else intent.form.submit?.();
        return;
      } catch (_) {}
    }

    const btn = findSendButton();
    if (btn) btn.click();
    else simulateEnter(findEditor());
  }

  function releaseOnly() {
    isProcessingMutex = false;
    lastSubmitIntent = null;
  }

  function setSubmitBypassForCurrentText() {
    try {
      const editor = findEditor();
      const text = editor ? readEditor(editor) : '';
      const normalized = normalizeBypassText(text);
      if (!normalized) {
        submitBypass = null;
        return;
      }
      submitBypass = {
        hash: quickHash(normalized),
        expiresAt: Date.now() + SUBMIT_BYPASS_TTL_MS
      };
      window.setTimeout(() => {
        if (submitBypass && submitBypass.expiresAt <= Date.now()) submitBypass = null;
      }, SUBMIT_BYPASS_TTL_MS + 150);
    } catch (_) {
      submitBypass = null;
    }
  }

  function shouldBypassCurrentSubmit(text) {
    if (!submitBypass) return false;
    const current = submitBypass;
    submitBypass = null;
    if (Date.now() > current.expiresAt) return false;
    return current.hash === quickHash(normalizeBypassText(text));
  }

  function normalizeBypassText(text) {
    return String(text || '').replace(/\s+/g, ' ').trim();
  }

  function quickHash(text) {
    let h = 2166136261;
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return `${text.length}:${(h >>> 0).toString(16)}`;
  }

  function findEditor() {
    const selector = customSelectors.inputSelector || customSelectors.editorSelector || '';
    if (selector) {
      const custom = firstDeep(selector);
      if (custom && isEditor(custom)) return normalizeEditorElement(custom);
    }

    const active = normalizeEditorElement(deepActiveElement());
    if (active && isEditor(active) && isUsableEditor(active)) return active;

    const selectors = genericEditorSelectors();
    const candidates = [];
    for (const sel of selectors) candidates.push(...allDeep(sel));

    const usable = [...new Set(candidates)]
      .map(normalizeEditorElement)
      .filter(Boolean)
      .filter(isEditor)
      .filter(isUsableEditor);

    return chooseBestEditor(usable);
  }

  function genericEditorSelectors() {
    return [
      'textarea',
      'input[type="text"]',
      'input[type="search"]',
      '[contenteditable]:not([contenteditable="false"])',
      'div[role="textbox"]',
      '[role="textbox"]',
      '[aria-label*="Message" i]',
      '[aria-label*="prompt" i]',
      '[aria-label*="Ask" i]',
      '[placeholder*="Message" i]',
      '[placeholder*="Ask" i]',
      '[data-testid*="composer" i]',
      '[data-testid*="input" i]'
    ];
  }


  function normalizeEditorElement(el) {
    if (!el || el.nodeType !== 1) return null;
    if (el.matches?.('textarea, input, [contenteditable]:not([contenteditable="false"]), [role="textbox"]')) return el;
    return el.querySelector?.('textarea, input[type="text"], input[type="search"], [contenteditable]:not([contenteditable="false"]), [role="textbox"]') || el;
  }

  function chooseBestEditor(editors) {
    if (!editors.length) return null;
    const active = normalizeEditorElement(deepActiveElement());
    if (active && editors.includes(active)) return active;
    return editors.map(el => ({ el, score: editorScore(el) })).sort((a, b) => b.score - a.score)[0]?.el || null;
  }

  function editorScore(el) {
    const label = elementDescriptor(el);
    const rect = safeRect(el);
    let score = 0;
    if (el.matches?.('textarea')) score += 30;
    if (el.matches?.('[contenteditable]:not([contenteditable="false"])')) score += 24;
    if (el.matches?.('[role="textbox"]')) score += 18;
    if (label.includes('ask')) score += 20;
    if (label.includes('message')) score += 16;
    if (label.includes('prompt')) score += 12;
    if (label.includes('composer')) score += 12;
    if (el === document.activeElement || el.contains?.(document.activeElement)) score += 24;
    if (rect && rect.width > 200) score += 8;
    if (rect && rect.height > 24) score += 4;
    return score;
  }

  function isEditor(el) {
    if (!el || !el.matches) return false;
    const label = elementDescriptor(el);
    const contentEditable = String(el.getAttribute?.('contenteditable') || '').toLowerCase();
    return Boolean(
      el.matches('textarea') ||
      el.matches('input[type="text"], input[type="search"]') ||
      (contentEditable && contentEditable !== 'false') ||
      el.matches('[role="textbox"]') ||
      label.includes('message') ||
      label.includes('prompt') ||
      label.includes('ask') ||
      label.includes('composer')
    );
  }

  function isUsableEditor(el) {
    if (!el || el.disabled || el.readOnly || el.getAttribute?.('aria-disabled') === 'true') return false;
    if (el.matches?.('input') && !['text', 'search'].includes(String(el.type || '').toLowerCase())) return false;
    const active = deepActiveElement();
    return isElementVisible(el) || el === active || el.contains?.(active);
  }

  function isFocusable(el) {
    try { return typeof el.focus === 'function' && el.tabIndex >= 0; }
    catch (_) { return false; }
  }

  function isSameEditor(target, editor) {
    const normalizedTarget = normalizeEditorElement(target);
    return target === editor || normalizedTarget === editor || editor.contains?.(target) || target?.closest?.('textarea, input[type="text"], input[type="search"], [contenteditable]:not([contenteditable="false"]), [role="textbox"]') === editor;
  }

  function readEditor(editor) {
    if (!editor) return '';
    if (editor.value !== undefined) return editor.value;
    if (editor.getAttribute?.('contenteditable')) return editor.innerText || editor.textContent || '';
    return editor.innerText || editor.textContent || '';
  }

  function writeEditor(editor, value) {
    if (!editor) return false;
    const next = String(value || '');
    try {
      editor.focus?.();
      if (editor.value !== undefined) {
        editor.value = next;
        editor.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: next }));
        editor.dispatchEvent(new Event('change', { bubbles: true }));
      } else {
        const selection = window.getSelection?.();
        if (selection && document.createRange) {
          const range = document.createRange();
          range.selectNodeContents(editor);
          selection.removeAllRanges();
          selection.addRange(range);
        }
        if (document.queryCommandSupported?.('insertText')) document.execCommand('insertText', false, next);
        else editor.textContent = next;
        editor.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: next }));
        editor.dispatchEvent(new Event('change', { bubbles: true }));
      }
      const after = normalizeBypassText(readEditor(editor));
      const expected = normalizeBypassText(next);
      return after === expected || (expected.length > 24 && after.includes(expected.slice(0, 24)));
    } catch (_) {
      return false;
    }
  }

  function elementDescriptor(el) {
    if (!el) return '';
    const labelledBy = el.getAttribute?.('aria-labelledby') || '';
    let labelledText = '';
    if (labelledBy) labelledText = labelledBy.split(/\s+/).map(id => document.getElementById(id)?.textContent || '').join(' ');
    return [
      el.getAttribute?.('aria-label'),
      el.getAttribute?.('placeholder'),
      el.getAttribute?.('data-testid'),
      el.getAttribute?.('data-test-id'),
      el.getAttribute?.('title'),
      el.getAttribute?.('name'),
      el.id,
      el.className && typeof el.className === 'string' ? el.className : '',
      labelledText
    ].filter(Boolean).join(' ').toLowerCase();
  }

  function safeRect(el) {
    try { return el.getBoundingClientRect(); } catch (_) { return null; }
  }

  function findClickedSendButton(target, event) {
    const path = event && event.composedPath ? event.composedPath() : [];
    const candidates = [];
    if (target && target.nodeType === 1) candidates.push(target);
    for (const item of path) if (item && item.nodeType === 1) candidates.push(item);
    for (const node of candidates) {
      const button = node.closest?.('button, [role="button"], [aria-label], [title], [data-testid]');
      if (!button || button.disabled || button.getAttribute('aria-disabled') === 'true') continue;
      if (isSendButton(button)) return button;
    }
    return null;
  }

  function findSendButton() {
    const custom = customSelectors.sendSelector || customSelectors.buttonSelector || '';
    if (custom) {
      try {
        const btn = firstDeep(custom);
        if (btn && !btn.disabled && btn.getAttribute('aria-disabled') !== 'true') return btn;
      } catch (_) {}
    }

    const selectors = genericSendSelectors();
    const candidates = [];
    for (const sel of selectors) candidates.push(...allDeep(sel));
    return [...new Set(candidates)].find(btn => !btn.disabled && btn.getAttribute('aria-disabled') !== 'true' && isSendButton(btn)) || null;
  }

  function genericSendSelectors() {
    return [
      'button[type="submit"]',
      'button[data-testid*="send" i]',
      'button[data-testid*="submit" i]',
      'button[aria-label*="Send" i]',
      'button[title*="Send" i]',
      '[role="button"][aria-label*="Send" i]',
      '[data-testid="send-button"]'
    ];
  }


  function deepActiveElement(root = document) {
    let active = root.activeElement || document.activeElement;
    while (active && active.shadowRoot && active.shadowRoot.activeElement) active = active.shadowRoot.activeElement;
    return active;
  }

  function firstDeep(selector) {
    return allDeep(selector)[0] || null;
  }

  function allDeep(selector, root = document) {
    const found = [];
    const visited = new Set();
    const visit = (node) => {
      if (!node || visited.has(node)) return;
      visited.add(node);
      try {
        if (node.nodeType === 1 && node.matches?.(selector)) found.push(node);
      } catch (_) {}
      try {
        if (node.querySelectorAll) found.push(...node.querySelectorAll(selector));
      } catch (_) {}
      const children = node.querySelectorAll ? [...node.querySelectorAll('*')] : [];
      for (const child of children) if (child.shadowRoot) visit(child.shadowRoot);
    };
    visit(root);
    return [...new Set(found)];
  }

  function isSendButton(btn) {
    const text = `${elementDescriptor(btn)} ${String(btn.textContent || '').toLowerCase()}`;
    if (text.includes('stop') || text.includes('cancel') || text.includes('new chat') || text.includes('attach') || text.includes('microphone') || text.includes('voice')) return false;
    if (text.includes('send') || text.includes('submit')) return true;
    if (btn.matches?.('button[type="submit"]')) {
      const form = btn.closest?.('form');
      return true;
    }
    return false;
  }

  function simulateEnter(editor) {
    if (!editor) return;
    const opts = { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true, composed: true };
    editor.dispatchEvent(new KeyboardEvent('keydown', opts));
    editor.dispatchEvent(new KeyboardEvent('keypress', opts));
    editor.dispatchEvent(new KeyboardEvent('keyup', opts));
  }

  function showToast(message) {
    removeToast();
    ensureSentinelStyles();

    const toast = document.createElement('div');
    toast.id = 'sentinel-soft-toast';
    toast.setAttribute('role', 'status');
    toast.setAttribute('aria-live', 'polite');

    const text = document.createElement('div');
    text.className = 'sentinel-soft-toast-text';
    text.textContent = message || 'Sentinel+ noticed possible sensitive information. Please check before sending.';

    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'sentinel-soft-toast-close';
    close.setAttribute('aria-label', 'Dismiss Sentinel+ warning');
    close.textContent = '×';
    close.addEventListener('click', removeToast, { once: true });

    toast.append(text, close);
    document.documentElement.appendChild(toast);
  }

  function showRedactionFallback(redactedText) {
    document.getElementById('sentinel-redact-fallback')?.remove();
    const host = document.createElement('div');
    host.id = 'sentinel-redact-fallback';
    host.setAttribute('role', 'dialog');
    host.style.cssText = 'position:fixed;right:20px;bottom:20px;z-index:2147483647;background:#111827;color:#fff;border:1px solid rgba(255,255,255,.22);border-radius:12px;box-shadow:0 12px 38px rgba(0,0,0,.42);padding:12px;width:min(420px,calc(100vw - 32px));font-family:Segoe UI,Arial,sans-serif;box-sizing:border-box;';
    const title = document.createElement('div');
    title.textContent = 'Sentinel+ could not edit this page';
    title.style.cssText = 'font-weight:800;font-size:14px;margin-bottom:6px;';
    const note = document.createElement('div');
    note.textContent = 'Copy the redacted text below, or log in / refresh the page and try again.';
    note.style.cssText = 'font-size:12px;line-height:1.35;color:#cbd5e1;margin-bottom:8px;';
    const area = document.createElement('textarea');
    area.value = String(redactedText || '');
    area.readOnly = true;
    area.style.cssText = 'width:100%;min-height:110px;resize:vertical;background:#020617;color:#fff;border:1px solid rgba(148,163,184,.35);border-radius:8px;padding:8px;box-sizing:border-box;font:12px Consolas,monospace;';
    const close = document.createElement('button');
    close.type = 'button';
    close.textContent = 'Close';
    close.style.cssText = 'margin-top:8px;border:1px solid rgba(148,163,184,.35);background:#1e293b;color:#fff;border-radius:8px;padding:7px 10px;cursor:pointer;';
    close.addEventListener('click', () => host.remove());
    host.append(title, note, area, close);
    document.documentElement.appendChild(host);
    area.focus();
    area.select();
  }

  function removeToast() {
    document.getElementById('sentinel-soft-toast')?.remove();
  }

  function removeOverlay() {
    document.getElementById('sentinel-consent-overlay')?.remove();
  }

  function removeEmergency() {
    document.getElementById('sentinel-emergency-alert')?.remove();
  }

  function removeAllSentinelUi() {
    removeToast();
    document.getElementById('sentinel-redact-fallback')?.remove();
    removeOverlay();
    removeEmergency();
  }

  function ensureSentinelStyles() {
    if (document.getElementById('sentinel-content-style')) return;
    const style = document.createElement('style');
    style.id = 'sentinel-content-style';
    style.textContent = `
      #sentinel-soft-toast {
        position: fixed !important;
        right: 20px !important;
        bottom: 20px !important;
        z-index: 2147483647 !important;
        display: flex !important;
        align-items: flex-start !important;
        gap: 10px !important;
        background: #111827 !important;
        color: #ffffff !important;
        border: 1px solid rgba(255,255,255,.2) !important;
        border-left: 4px solid #f59e0b !important;
        border-radius: 10px !important;
        padding: 10px 10px 10px 12px !important;
        box-shadow: 0 8px 28px rgba(0,0,0,.32) !important;
        font-family: Segoe UI, Arial, sans-serif !important;
        font-size: 13px !important;
        line-height: 1.35 !important;
        max-width: 380px !important;
      }
      #sentinel-soft-toast .sentinel-soft-toast-text {
        color: #ffffff !important;
        flex: 1 1 auto !important;
      }
      #sentinel-soft-toast .sentinel-soft-toast-close {
        appearance: none !important;
        border: 0 !important;
        background: rgba(255,255,255,.12) !important;
        color: #ffffff !important;
        width: 24px !important;
        height: 24px !important;
        border-radius: 999px !important;
        cursor: pointer !important;
        font-size: 18px !important;
        line-height: 20px !important;
        padding: 0 !important;
        flex: 0 0 auto !important;
      }
      #sentinel-soft-toast .sentinel-soft-toast-close:hover {
        background: rgba(255,255,255,.22) !important;
      }
      .sentinel-advisory-highlight {
        outline: 2px solid rgba(245,158,11,.85) !important;
        outline-offset: 2px !important;
        border-radius: 8px !important;
      }
    `;
    (document.head || document.documentElement).appendChild(style);
  }

  function getProtectionStatus() {
    const editor = findEditor();
    const button = findSendButton();
    return {
      editorFound: Boolean(editor),
      sendButtonFound: Boolean(button),
      protectionReady: Boolean(editor),
      frameUrl: location.href,
      frameHost: location.hostname,
      framePath: location.pathname
    };
  }

  function watchForComposerChanges() {
    let timer = 0;
    try {
      const observer = new MutationObserver(() => {
        if (timer) return;
        timer = window.setTimeout(() => {
          timer = 0;
          announceActive();
        }, 1200);
      });
      observer.observe(document.documentElement || document, { childList: true, subtree: true });
    } catch (_) {}
  }

  function getSiteProfile() {
    return { isCopilot: false };
  }

  async function resolveRuntimeConfig() {
    const builtIn = getBuiltInSiteName(location.hostname);
    if (builtIn) return { siteName: builtIn, selectors: {} };

    try {
      const cfg = await sendRuntimeMessage({ type: 'GET_SITE_CONFIG', url: location.href });
      if (cfg?.ok && cfg.siteName) return { siteName: cfg.siteName, selectors: cfg.selectors || {} };
    } catch (_) {}

    return { siteName: '', selectors: {} };
  }

  function sendRuntimeMessage(msg) {
    return new Promise(resolve => chrome.runtime.sendMessage(msg, res => resolve(res || {})));
  }

  function announceActive() {
    try {
      const status = getProtectionStatus();
      chrome.runtime.sendMessage({ type: 'PAGE_ACTIVE', siteName, siteUrl: location.href, ...status }, () => void chrome.runtime.lastError);
    } catch (_) {}
  }

  function getBuiltInSiteName(host) {
    const h = String(host || '').replace(/^www\./, '');
    const map = [
      ['chatgpt.com', 'ChatGPT'],
      ['chat.openai.com', 'ChatGPT'],
      ['claude.ai', 'Claude'],
      ['gemini.google.com', 'Gemini'],      ['perplexity.ai', 'Perplexity'],
      ['grok.com', 'Grok'],
      ['chat.mistral.ai', 'Mistral Chat'],
      ['chat.deepseek.com', 'DeepSeek'],
      ['deepseek.com', 'DeepSeek'],
      ['meta.ai', 'Meta AI'],
      ['chat.qwen.ai', 'Qwen / Tongyi'],
      ['tongyi.aliyun.com', 'Qwen / Tongyi'],
      ['qianwen.aliyun.com', 'Qwen / Tongyi'],
      ['kimi.moonshot.cn', 'Kimi'],
      ['poe.com', 'Poe']
    ];
    const hit = map.find(([domain]) => h === domain || h.endsWith(`.${domain}`));
    return hit ? hit[1] : '';
  }
})();
