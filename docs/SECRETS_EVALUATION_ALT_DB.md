# Rigorous evaluation of captured secrets (alt DB)

This document summarizes an audit of all secret types in `domain_status_alt.db`: for each type we sampled context, compared to page semantics, and classified findings as **legit** (real secret or meaningful identifier) vs **false positive** (artifact that matched a regex but is not a secret). Recommended fixes are listed per type.

## Summary by secret type

| secret_type | Count | Verdict | Notes |
|-------------|-------|---------|--------|
| jwt | 143 | **Legit** | Real JWTs: storefront tokens, video stream tokens, mapkit, contact form, API Bearer. |
| gcp-api-key | 137 | **Legit** | Real Google/ Firebase keys in script, data-*, JSON (Maps, Firebase, reCAPTCHA). |
| sourcegraph-access-token | 4 | **Mostly FP** | Image hashes, captcha IDs, one possible real token; 40-char hex is overloaded. |
| algolia-api-key | 7 | **Legit** | Real Algolia search keys in script/JSON. |
| contentful-delivery-api-token | 3 | **Legit** | Real Contentful delivery/preview tokens in page config. |
| linkedin-client-secret | 3 | **False positive** | Captured `extensionPointId`, `pageJsonFileName` (block/page IDs), not secrets. |
| linkedin-client-id | 1 | **False positive** | Captured `interactionUrl` (JSON key), not a client ID. |
| aws-access-token | 2 | **Legit** | AWS creds in signed URLs (X-Amz-Credential, AWSAccessKeyId). |
| sumologic-access-token | 2 | **False positive** | `sumoSiteId` in embed script = public site ID, not access token. |
| github-pat | 1 | **Legit** | Real PAT in HTML comment (`<!-- ghp_... -->`). |
| hashicorp-tf-password | 2 | **False positive** | Rule for .tf/.hcl ran on HTML; captured "ConfirmRegForm" (validation group name). |
| adobe-client-id | 1 | **Legit** | Client ID in page config (public by design for embed). |
| twitch-api-token | 1 | **Legit (low risk)** | Twitch **client ID** in config; public by design. |

## Detailed findings and root cause

### 1. jwt — Legit

- **Where**: url_parameter (video stream tokens), inline_script (storefront, mapkit), html_body (graphQLToken, storefrontAPIToken, contact form JWT), data_attribute, meta_tag.
- **Context**: Real JWTs used for auth, CORS, or short-lived stream tokens. No false positives in sample.
- **Action**: None.

### 2. gcp-api-key — Legit

- **Where**: html_body (firebaseConfig, mapsApiKey, google_api_key, etc.), inline_script, data_attribute (data-key, data-gmap, data-api-key), url_parameter, html_comment.
- **Context**: Real Google Maps / Firebase / reCAPTCHA keys embedded in frontend. Intentionally exposed but still credentials.
- **Action**: None.

### 3. sourcegraph-access-token — Mostly false positives

- 40-char hex in image `alt`/`src` (e.g. `wp-content/uploads/.../25fcd2f6aa55a8a7a21442797bd47a25876d0f59`) — **image hash / cache ID**, not a token.
- 40-char hex in CAPTCHA URL `id=54ca98cb2ffa...` — **captcha/session ID**, not Sourcegraph.
- `address_api_token = 'a01aecfdcf4dfa829bf2e7a71ab03de7cba631cd'` — could be a **real** API token (wrong product name).
- **Root cause**: Rule matches any 40-char hex when “sourcegraph” appears; same pattern used for image hashes, captcha IDs, and generic tokens.
- **Action**: Add allowlist regexes for: image URLs (e.g. `wp-content/uploads`, `alt="[^"]*[0-9a-fA-F]{40}`), `_siwp_captcha`, `wp-image-`.

### 4. linkedin-client-id / linkedin-client-secret — False positives

- **linkedin-client-id**: Matched “Linkedin” in “Social | Linkedin” and captured 14-char `interactionUrl` (JSON key).
- **linkedin-client-secret**: Matched “linkedin” in “footer-linkedin”, “thank-you-linkedin”, “ESSAI LINKEDIN” and captured 16-char `extensionPointId`, `pageJsonFileName` (block/page identifiers).
- **Root cause**: Rule matches any 14/16 alphanumeric near the word “linkedin”; page structure (menus, form names, block IDs) satisfies the pattern.
- **Action**: Add line-target allowlist for lines containing: `extensionPointId`, `pageJsonFileName`, `interactionUrl`, `menu-item#`, `interactionSource`, or `footer-linkedin`.

### 5. sumologic-access-token — False positive

- **Context**: `j.dataset.sumoSiteId='38d92200...'` — Sumo Logic **site ID** for the embed script (public identifier), not an access token.
- **Root cause**: Rule matches 64-char hex after “sumo”; sumoSiteId uses the same format but is not a secret.
- **Action**: Allowlist line containing `sumoSiteId` or `sumoSiteId=`.

### 6. hashicorp-tf-password — False positive

- **Context**: HTML with `UserPassword_rfvConfirmPassword.validationGroup = "ConfirmRegForm"`; rule captured quoted string `"ConfirmRegForm"` (validation group name).
- **Root cause**: Rule is intended for `.tf`/`.hcl` files (`path = '''(?i)\.(?:tf|hcl)$'''`). We run all rules on the single HTML blob and ignore path, so it runs on HTML and matches “password” in variable names plus a quoted 8–20 char string.
- **Action**: When scanning a single blob (e.g. HTML) with no file path, **skip rules that have a `path` restriction** so Terraform-specific rules do not run on HTML.

### 7. hubspot-api-key (from earlier audit)

- **Context**: `data-hubspot-form="uuid"` = form/embed ID, not API key.
- **Action**: Already fixed with allowlist `data-hubspot-form=`, `data-hubspot-form-id=` (not overfit: semantic form-ID pattern).

### 8. adobe-client-id, twitch-api-token

- **adobe-client-id**: Real client ID in config; public by design for embed.
- **twitch-api-token**: Twitch **client ID** (`TWITCH_CLIENT_ID`); public by design. Rule name is misleading; finding is legit but low risk.
- **Action**: No code change; document or treat as low severity if desired.

### 9. github-pat, aws-access-token, algolia-api-key, contentful-delivery-api-token

- All sampled findings are real credentials or meaningful identifiers in script/URL/config.
- **Action**: None.

## Implementation checklist

- [x] **Path-restricted rules**: Skip rules with `path` set when scanning HTML (single-blob, no path). Fixes hashicorp-tf-password and any other file-type–specific rules. Implemented in `src/parse/gitleaks.rs` (CompiledRule.path) and `src/parse/secrets.rs` (skip when `rule.path.is_some()`).
- [x] **sourcegraph-access-token**: Add allowlist regexes for image/captcha patterns (`wp-content/uploads`, `wp-image-`, `_siwp_captcha`, `alt="[^"]*[0-9a-fA-F]{40}`) in `config/gitleaks.overrides.toml`.
- [x] **linkedin-client-id / linkedin-client-secret**: Add line-target allowlist for page-structure identifiers (extensionPointId, pageJsonFileName, interactionUrl, menu-item#, interactionSource, footer-linkedin) in `config/gitleaks.overrides.toml`.
- [x] **sumologic-access-token**: Add allowlist for line containing `sumoSiteId` in `config/gitleaks.overrides.toml`.
- [x] **HubSpot**: Already allowlisted; no further change.

## Overfitting vs semantic allowlists

The HubSpot allowlist is **not** overfit: it excludes only the **semantic** pattern “HubSpot form/embed ID” (`data-hubspot-form=`, `data-hubspot-form-id=`), not all UUIDs. Same approach for Sumo Logic (site ID vs token) and LinkedIn (block/URL keys vs client id/secret). For sourcegraph we exclude **context** (image hashes, captcha IDs), not all 40-char hex. Path-based skip is a **scope** fix: Terraform rules should not run on HTML at all.
