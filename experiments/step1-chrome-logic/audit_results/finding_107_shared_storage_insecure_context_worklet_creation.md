# Finding 107: Shared Storage Worklet Creation Skips Secure Context Enforcement

## Severity: MEDIUM

## Location
- `content/browser/shared_storage/shared_storage_document_service_impl.cc`, lines 130-134

## Description

The `CreateWorklet()` method in `SharedStorageDocumentServiceImpl` explicitly comments that it **skips mojom validation for secure context**, deferring to a renderer-side check that cannot be trusted:

```cpp
// There's no consistent secure context check between the renderer process and
// the browser process (see crbug.com/1153336). This is particularly
// problematic when the origin is opaque. Hence, we skip the mojom validation
// for secure context. Until the issue is addressed, an insecure context (in
// a compromised renderer) can create worklets and execute operations.
```

This is in direct contrast with `SharedStorageUpdate()` and `SharedStorageBatchUpdate()` (lines 174, 212), which DO check `CheckSecureContext()` -- though even those merely return an error rather than calling `ReportBadMessage()`, as noted by the TODO at crbug.com/40068897.

## Impact

A compromised renderer in an insecure (HTTP) context can:
1. Create Shared Storage worklets
2. Execute `run()` and `selectURL()` operations
3. Read and write to the Shared Storage database
4. Access cross-site data via the Privacy Sandbox APIs

This bypasses the security guarantee that Shared Storage is only available in secure contexts. The comment itself acknowledges this as a known gap.

## Exploit Scenario

1. Attacker compromises a renderer process (e.g., via a memory corruption bug)
2. From an HTTP context, attacker creates a Shared Storage worklet via the mojo interface
3. The browser-side `CreateWorklet()` does NOT enforce secure context
4. Attacker can now read cross-site data from Shared Storage and exfiltrate it via `selectURL()` or Private Aggregation

## Additional Note

The `SharedStorageUpdate()` and `SharedStorageBatchUpdate()` methods have TODOs (crbug.com/40068897) about upgrading the insecure context check from a soft error to `ReportBadMessage()`. Until this is done, a compromised renderer could also call these methods from insecure contexts without being terminated.

## References
- crbug.com/1153336 (secure context inconsistency)
- crbug.com/40068897 (missing bad message for insecure context)
