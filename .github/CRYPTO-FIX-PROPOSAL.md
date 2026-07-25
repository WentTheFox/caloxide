# Proposal: Re-enable Disabled Cryptographic Checks

## Issue Summary

Two upstream cryptographic verification checks are currently disabled in the codebase:

1. **Passphrase signature verification** in `protonmail/calendar.go` (lines 237-244)
2. **Read-path MDC check** in `caldav/caldav.go` (lines 118-124)

These were disabled because old/imported Proton events may have signatures that no longer verify (expired keys, key rotation, etc.). For a personal bridge, the current implementation prioritizes **decryptability** over **signature verification** - events are served even if their signatures don't verify, with a log message.

While this is a reasonable design choice for a personal-use bridge, re-enabling these checks (with graceful fallback) would strengthen the security posture without breaking compatibility.

---

## Background

### 1. Passphrase Signature Verification (`protonmail/calendar.go:237-244`)

In the `DecryptKeyring` function, there is commented-out code that verifies the detached PGP signature on the calendar passphrase:

```go
/*  signatureData, err := armor.Decode(strings.NewReader(passphrase.Signature))
    if err != nil {
        return nil, err
    }
    _, err = openpgp.CheckArmoredDetachedSignature(userKr, bytes.NewReader(passphraseBytes), signatureData.Body, nil)
    if err != nil {
        return nil, err
    }*/
```

This signature verifies that the passphrase (used to decrypt calendar keys) was signed by the user's keyring. Without this check, a compromised or tampered passphrase could be used to decrypt calendar keys without detection.

### 2. Read-Path MDC Check (`caldav/caldav.go:118-124`)

In `readEventCard`, there is commented-out code that would consume the entire `UnverifiedBody` to verify the OpenPGP Modification Detection Code:

```go
// TODO: mdc hash mismatch (?)
/*_, err = io.Copy(io.Discard, md.UnverifiedBody)
if err != nil {
    return nil, fmt.Errorf("caldav/readEventCard: error copying unverified body: (%w)", err)
}*/
```

The MDC packet in OpenPGP provides integrity verification for encrypted messages. However, consuming the body breaks the detached signature verification that happens later (via `detachedSignatureReader`), which is why it was disabled.

---

## Proposed Solution: Option A (Graceful Fallback)

Re-enable both checks with **graceful fallback** - verify where possible, log failures, but continue serving events. This maintains backward compatibility with old/imported events while adding security for well-formed, properly-signed data.

### Fix 1: Passphrase Signature Verification

**File:** `protonmail/calendar.go`  
**Lines:** 237-244

**Change:** Replace the commented block with active code that fails on malformed signatures but logs and continues on verification failures:

```go
// Verify passphrase signature - fail on malformed, warn on verification failure
signatureData, err := armor.Decode(strings.NewReader(passphrase.Signature))
if err != nil {
    return nil, fmt.Errorf("DecryptKeyring: failed to decode passphrase signature: (%w)", err)
}
if _, err = openpgp.CheckArmoredDetachedSignature(userKr, bytes.NewReader(passphraseBytes), signatureData.Body, nil); err != nil {
    log.Printf("DecryptKeyring: passphrase signature verification failed (may be old/imported): %v", err)
    // Continue - prioritize decryptability over verification for personal bridge
}
```

**Rationale:** 
- If we can't even parse the signature armor, it's malformed - fail hard
- If verification fails (expired key, wrong key, etc.), log it but continue - the event may still be decryptable
- This preserves the current behavior for problematic events while adding verification for valid ones

### Fix 2: Read-Path MDC Check

**File:** `caldav/caldav.go`  
**Lines:** After 116 (after the malformed event recovery)

**Change:** Add body buffering for encrypted messages to enable both MDC verification and signature checking:

```go
// For encrypted messages, we must buffer the body to enable both MDC verification
// and detached signature checking. The detachedSignatureReader will tee the data
// from our buffered reader.
if md.IsEncrypted {
    bodyBytes, err := io.ReadAll(md.UnverifiedBody)
    if err != nil {
        return nil, fmt.Errorf("caldav/readEventCard: failed to read encrypted body: (%w)", err)
    }
    if err := md.UnverifiedBody.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
        return nil, fmt.Errorf("caldav/readEventCard: failed to close body: (%w)", err)
    }
    md.UnverifiedBody = bytes.NewReader(bodyBytes)
}
```

**Rationale:**
- OpenPGP's `ReadMessage` already verifies the MDC during decryption - but the issue is that the body needs to be fully consumed for the verification to complete
- By buffering the decrypted body, we can reset it and provide it to the `detachedSignatureReader` for signature verification
- This allows both checks to work without breaking the streaming signature verification

**Note:** The current `detachedSignatureReader` (defined in `protonmail/calendar.go:138-147`) already tees the body for signature verification. By resetting the body after MDC verification, we ensure the signature check still has access to the full content.

---

## Alternative Approaches Considered

### Option B: Configuration Flag

Add a `--verify-signatures` flag that enables strict verification mode. Users who want maximum security can enable it; those with old events can leave it disabled.

**Pros:** Maximum flexibility  
**Cons:** More complexity, security depends on user configuration

### Option C: Fail Fast (Strict Mode)

Simply uncomment both blocks and fail on any verification error.

**Pros:** Strongest security  
**Cons:** Will break for users with old/imported events

**Not recommended** as the default, but could be Option B's strict mode.

---

## Testing Strategy

After implementing the proposed changes:

1. **Test with known-good events:** Verify events still decrypt and serve correctly with valid signatures
2. **Test with old/imported events:** Verify they still work with logged warnings about verification failures
3. **Test with tampered data:** Create test cases with modified signatures/passphrases to verify detection and proper error handling
4. **Update documentation:** Revise the README to remove or revise the caveat about disabled checks

---

## Impact Assessment

| Change | Backward Compatibility | Security Improvement | Complexity |
|--------|------------------------|---------------------|------------|
| Passphrase signature verification | Maintained (graceful fallback) | HIGH | Low |
| MDC check | Maintained (graceful fallback) | MEDIUM | Medium |

**Overall:** High security benefit with minimal risk to existing functionality.

---

## Files to Modify

1. `protonmail/calendar.go` - Re-enable passphrase signature verification (lines 237-244)
2. `caldav/caldav.go` - Add body buffering for MDC + signature verification (after line 116)

---

## Acceptance Criteria

- [ ] Passphrase signatures are verified when possible
- [ ] Verification failures are logged but don't prevent decryption
- [ ] MDC verification works for encrypted messages
- [ ] Detached signature verification still works
- [ ] All existing tests pass
- [ ] Old/imported events with verification failures still serve correctly
- [ ] README is updated to reflect the changes

---

## Questions / Discussion Points

1. Should we add a strict mode flag (Option B) in addition to or instead of the graceful fallback?
2. Should the log messages for verification failures be more prominent (e.g., rate-limited alerts)?
3. Are there any known edge cases with specific Proton event types that we should test against?

---

## Related

- README.md section "Two upstream-disabled cryptographic checks remain disabled" (lines 103-107)
- Commit 43173d0: "protonmail: decrypt encrypted-but-unsigned calendar cards"
- Issue: Better handling of old/imported events with signature verification
