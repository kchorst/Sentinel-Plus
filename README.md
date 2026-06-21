# Sentinel+ v2.2.4 Beta

**Screen before you send.** Sentinel+ screens messages on supported cloud AI chat sites for personal, credential, and confidential information before the message leaves the browser.

This beta package contains **Sentinel+ only**. LLM Tester is intentionally not included in this build.

Licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0). You are free to share and adapt these materials for any purpose, including commercial use, as long as you give appropriate credit, provide a link to the license, and indicate if changes were made. License details: https://creativecommons.org/licenses/by/4.0/

## First install default

- Mode: **Basic**
- Protection style: **Balanced**
- Default popup: minimal status only
- Optional tools stay hidden until opened, and anything opened can be hidden again.

## Supported cloud AI sites

Sentinel+ is designed for major browser-based AI chat sites, including ChatGPT, Claude, Gemini, Perplexity, Grok, Mistral Chat, DeepSeek, Meta AI, Qwen/Tongyi, Kimi, and Poe.

If Sentinel+ was installed, reloaded, or enabled while an AI chat page was already open, the popup may show:

> Refresh this chat page to activate Sentinel+ protection.

Use the **Refresh chat page** button rather than assuming protection is attached.


## Copilot status

Microsoft Copilot is **not supported in this beta**. Real-world testing showed that Copilot did not reliably expose a protected chat editor to Sentinel+, even after login and refresh. To avoid false confidence, Sentinel+ does not advertise Copilot as protected in this build.

Copilot can be revisited later as a separate compatibility project after its current DOM/frame/editor behavior is inspected and verified.

## What Sentinel+ screens by default

Default detection includes:

- Email addresses
- US/Canada phone numbers
- International phone-like numbers
- Social Security number patterns
- Credit-card-like numbers
- IP addresses
- API keys and tokens
- Password or secret assignments
- Private key blocks
- IBAN bank account numbers
- SWIFT/BIC codes
- Labeled passport numbers
- Labeled tax/VAT/TIN numbers

Default Sentinel+ intentionally does not guess every company-specific confidential phrase. Users can add those through **Protected Terms**.

## Protection styles

### Gentle

Shows a persistent soft warning until dismissed. It usually does not block sending.

### Balanced

Recommended default. Low and medium risk items show a soft warning. High and critical risk items show **Continue / Redact / Cancel**.

### Strict

Every detection requires review before sending.

## Protected Terms

Protected Terms are for client names, case names, project names, company names, confidential topics, or private business terms that are not normal PII.

Open **Settings → Protected Terms → Manage** and enter one term per line. Do not use commas as separators, because real names may contain commas, such as `ChatGPT, Inc.`.

Protected Terms are hidden by default. The popup shows only the count until the user clicks **Manage**.

## Privacy posture

- No clipboard access
- No raw prompt persistence by default
- Approved sensitive-item memory uses signatures/fingerprints, not raw PII
- Audit logs contain metadata only: time, site, rule/category, risk, action, and mode

## IT Pro / Consultant customization

Advanced users can import/export JSON profiles for custom regex rules, custom messages, custom redaction labels, locked/no-override rules, and custom AI site selectors.

The JSON/Profile area includes a **Regex Help** button that opens the MDN JavaScript Regular Expressions guide. Use fake sample data only. Do not paste client, legal, financial, medical, company, or personal information into online regex tools.

## Beta notes

This beta candidate marks Microsoft Copilot as not supported rather than showing an unreliable active state. LLM Tester remains separate and should not be changed unless bridge compatibility requires it.
