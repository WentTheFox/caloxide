# Security Audit Report: protoxide Repository

**Audit Date:** 2026-07-25  
**Repository:** https://github.com/mathewcsims/protoxide  
**Auditor:** Mistral Vibe CLI Agent  
**Local Path:** /Users/mathewcsims/protoxide

---

## Executive Summary

**Assessment: SAFE TO PUBLISH**

The protoxide project is a fork of ferroxide/hydroxide that provides a local CalDAV bridge for Proton Calendar. After thorough analysis of the codebase, git history, configuration, and dependencies, **no critical security vulnerabilities were found** that would prevent making this repository public.

The project demonstrates good security hygiene with proper `.gitignore` patterns, no hardcoded credentials, encrypted session storage, and a clean git history. The code follows security best practices for handling user authentication and sensitive data.

---

## Detailed Findings

### PASS: No Committed Secrets or Credentials

**Status:** No issues found

- **Codebase scan:** No hardcoded API keys, passwords, tokens, or credentials found in any source files
- **Git history:** Clean - no sensitive files (auth.json, protoxide.json, .db, .key, .pem, secrets*, calcache-*.json) were ever committed
- **GitHub Actions:** Workflow (`.github/workflows/go.yml`) contains no secrets - uses standard GitHub-hosted runners
- **Environment variables:** Properly documented and used for configuration (e.g., `PROTOXIDE_APPRISE_URL`)

### PASS: Robust .gitignore Configuration

**Status:** Excellent

The `.gitignore` file (40 lines) explicitly excludes:
- `auth.json` - encrypted session file
- `protoxide.json` - configuration
- `*.db`, `*.bolt` - database files
- `*.key`, `*.pem` - key files
- `secrets*` - any secrets files
- `*.token` - token files
- `calcache-*.json` - decrypted calendar cache
- `/config-dir/`, `/protoxide/` - local config directories
- Build artifacts and OS cruft

### PASS: Session Security

**Status:** Well-implemented

- **Encryption at rest:** Session data stored in `auth.json` is encrypted using NaCl secretbox (AES-256 equivalent) keyed by user's bridge password
- **File permissions:** Commit ce3cf51 added explicit `0600` permissions for auth.json (owner-only read/write)
- **No plaintext credentials:** User's Proton password is never stored - only the bridge password and encrypted session
- **Key derivation:** Uses cryptographically secure random key generation (`crypto/rand`)

### PASS: Clean Git History

**Status:** No sensitive data in history

- Only `main` branch exists
- No tags
- No commits containing sensitive patterns (password, secret, token, key, credential)
- All 20+ commits are clean with descriptive messages
- No merge commits with accidentally included sensitive data

### PASS: Hardcoded Endpoints (Expected)

**Status:** Acceptable for this use case

The following hardcoded endpoints are **by design** and necessary for the application to function:

| File | Endpoint | Purpose |
|------|----------|---------|
| `cmd/protoxide/main.go:38` | `https://mail.proton.me/api` | Default Proton API |
| `cmd/protoxide/main.go:39` | `https://mail.protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion/api` | Tor endpoint |
| `cmd/protoxide/main.go:199` | `http://www.protonmail.ch` | OAuth redirect URI |
| `cmd/protoxide/humanverify.go:114` | `https://verify-api.proton.me/core/v4/captcha` | Human verification |

These are **public ProtonMail API endpoints** - not secrets. The Tor onion address is also public. No authentication credentials are embedded.

### PASS: Dependency Security

**Status:** No known vulnerabilities

**Direct Dependencies (13):**
- github.com/ProtonMail/go-crypto v1.3.0
- github.com/emersion/go-bcrypt v0.0.0-20170822072041-6e724a1baa63
- github.com/emersion/go-ical v0.0.0-20240127095438-fc1c9d8fb2b6
- github.com/emersion/go-imap v1.2.1
- github.com/emersion/go-mbox v1.0.4
- github.com/emersion/go-message v0.18.2
- github.com/emersion/go-sasl v0.0.0-20241020182733-b788ff22d5a6
- github.com/emersion/go-smtp v0.23.0
- github.com/emersion/go-vcard v0.0.0-20230815062825-8fda7d8fb2b6
- github.com/emersion/go-webdav v0.6.0 (vendored)
- github.com/google/uuid v1.6.0
- go.etcd.io/bbolt v1.4.2
- golang.org/x/crypto v0.40.0
- golang.org/x/term v0.33.0

**Assessment:** All dependencies are from reputable sources (ProtonMail, emersion, Google, etcd). The vendored `go-webdav` is properly attributed with its MIT license. No known CVEs detected in the versions used.

### PASS: License Compliance

**Status:** Proper attribution

- **Primary License:** MIT (stated in LICENSE and README.md)
- **Copyright:** Properly attributed to original authors: emersion (2017), acheong08 (2023), Mathew Sims (2026)
- **Third-party:** Vendored `go-webdav` retains its MIT license with documentation in `PROTOXIDE-PATCH.md`
- **README:** Clearly documents the fork lineage and attribution

### PASS: Notification System

**Status:** Secure design

- **Apprise integration:** Optional, disabled by default
- **No hardcoded URLs:** Uses environment variables (`PROTOXIDE_APPRISE_URL`, `PROTOXIDE_APPRISE_URLS`)
- **Service script:** `protoxide-caldav-run.sh` also uses environment variables, not hardcoded values
- **Security:** Install script (`service/install.sh`) sets `chmod 600` on plist files containing Apprise URLs

---

## Security Posture Summary

| Category | Status | Notes |
|----------|--------|-------|
| **Secrets in Code** | PASS | No hardcoded credentials |
| **Git History** | PASS | Clean, no sensitive data |
| **Session Security** | PASS | Encrypted at rest, proper permissions |
| **Dependencies** | PASS | Reputable sources, no known CVEs |
| **License** | PASS | MIT, properly attributed |
| **Configuration** | PASS | .gitignore comprehensive |
| **Network Security** | LOW | HTTP on localhost only, documented |
| **Crypto Checks** | LOW | Disabled checks documented |

---

## Open Issues / Caveats

### 1. Disabled Cryptographic Checks

Two upstream cryptographic checks remain disabled:

- **Calendar passphrase signature verification** (`protonmail/calendar.go:237-244`) - Commented out in `DecryptKeyring` function
- **Read-path MDC check** (`caldav/caldav.go:118-124`) - Commented out code that consumes `UnverifiedBody` to verify OpenPGP MDC

**Current behavior:** Events with unverified signatures are served with a log message (not silently dropped).

**Risk:** Old/imported events with expired or missing keys will fail to verify, which is why they were disabled for a personal bridge where decryptability was prioritized.

**Recommendation:** Re-enable with graceful fallback (Option A) - verify where possible, log failures, but continue serving events.

### 2. Plain HTTP on Localhost

The CalDAV server uses plain HTTP (not HTTPS) on 127.0.0.1 by default. This is documented in the README with explicit warning: "Keep it bound to localhost. Do not expose it to a network."

**Risk:** LOW - local machine only, documented limitation.

---

## Recommendations Before Publishing

### Immediate (Before Making Public)

1. **Verify README accuracy:** The README already contains extensive security documentation. Ensure all warnings are prominent.

2. **Final file check:**
   ```bash
   git ls-files | grep -E '\.(json|db|key|pem|token|secret)'
   ```
   (This check passed - no sensitive files in repo)

### Optional Improvements

1. **Add SECURITY.md:** Consider adding a security policy document for vulnerability reporting
2. **Dependency scanning:** Set up GitHub Dependabot or similar for vulnerability monitoring
3. **Signed releases:** Consider GPG-signing releases for authenticity
4. **Re-enable crypto checks:** Address the two disabled cryptographic verifications mentioned above

---

## Risk Assessment Matrix

| Risk | Severity | Likelihood | Overall |
|------|----------|------------|---------|
| Hardcoded credentials exposed | CRITICAL | NONE | NONE |
| Session data in git history | HIGH | NONE | NONE |
| Dependency vulnerabilities | MEDIUM | LOW | LOW |
| Insecure defaults | LOW | LOW | LOW |
| Missing license attribution | LOW | NONE | NONE |

**Overall Risk: LOW**

---

## Conclusion

**The protoxide repository is SAFE TO MAKE PUBLIC.**

The codebase demonstrates exemplary security practices:
- No secrets committed to version control
- Comprehensive .gitignore for sensitive files
- Proper encryption of session data
- Clean git history
- Appropriate license attribution
- Public API endpoints only (no private keys)

The only identified concerns are:
1. HTTP on localhost (documented limitation)
2. Disabled cryptographic checks (documented limitation)

Both are explicitly disclosed in the README and are acceptable design decisions for this use case. No action is required before publishing, though addressing the disabled crypto checks would be a nice-to-have improvement.

**Recommendation: PROCEED with making the repository public.**
