
// config.js — Sentinel+ v2.2.4 beta candidate defaults
// Pure configuration. No clipboard access. No raw prompt persistence.

const SENTINEL_CONFIG = {
  VERSION: '2.2.4',
  PRODUCT_NAME: 'Sentinel+',
  POPUP_TAGLINE: 'Screen before you send.',
  README_TAGLINE: 'Let Sentinel+ screen your messages for sensitive information before you send them to the cloud.',
  DEFAULT_PROTECTION_STYLE: 'balanced', // gentle | balanced | strict
  LLM_TESTER_EXTENSION_ID: 'njggbbcnjobebgflkngifbpnanlgfekc',
  PARAMETIZER_ENDPOINT: 'http://127.0.0.1:9820',
  LOCAL_LLM_PORTS: [11434, 1234, 8080, 8081, 8082, 3000, 7860],
  SUPPORTED_SITES: [{"name": "ChatGPT", "matches": ["https://chatgpt.com/*", "https://chat.openai.com/*"]}, {"name": "Claude", "matches": ["https://claude.ai/*"]}, {"name": "Gemini", "matches": ["https://gemini.google.com/*"]}, {"name": "Perplexity", "matches": ["https://www.perplexity.ai/*", "https://perplexity.ai/*"]}, {"name": "Grok", "matches": ["https://grok.com/*"]}, {"name": "Mistral Chat", "matches": ["https://chat.mistral.ai/*"]}, {"name": "DeepSeek", "matches": ["https://chat.deepseek.com/*", "https://www.deepseek.com/*"]}, {"name": "Meta AI", "matches": ["https://www.meta.ai/*", "https://meta.ai/*"]}, {"name": "Qwen / Tongyi", "matches": ["https://chat.qwen.ai/*", "https://tongyi.aliyun.com/*", "https://qianwen.aliyun.com/*"]}, {"name": "Kimi", "matches": ["https://kimi.moonshot.cn/*"]}, {"name": "Poe", "matches": ["https://poe.com/*"]}],
  RISK_ORDER: { low: 1, medium: 2, high: 3, critical: 4 },
  DEFAULT_PATTERNS: [
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
  ],
  DEFAULT_PROFILE: {
    schemaVersion: '2.0',
    profileId: 'sentinel-default-v2',
    profileName: 'Sentinel+ Default Protection',
    version: '2.0.0',
    trustedSource: 'Sentinel+',
    notes: 'Default PII and credential rules only. Organization-specific rules belong in consultant profiles.',
    rules: [],
    customSites: [],
    migrationNotes: []
  }
};
