# Coverage Expansion Audit — Round 3 Continuation

## Date: 2026-04-30

## Areas Investigated This Session

### 1. ORB (Opaque Response Blocking) — `services/network/orb/`
**Result: No critical exploitable bugs**
- `is_attribution_response_` only affects reporting, NOT blocking decision
- Fail-open after 1024 bytes sniffing is by design (known trade-off)
- Missing `nosniff` and non-OK status enforcement are spec-acknowledged gaps
- All require server-side misconfiguration to exploit

### 2. Protected Audience / FLEDGE — `content/services/auction_worklet/`
**Result: One code defect found (Finding 242)**
- `registerAdMacro()` missing `return` after `ThrowException()` — input validation bypass
- Browser process trusts worklet-provided macros without re-validation
- Limited direct impact (macros only substitute into bidder-controlled URLs)
- Still a legitimate trust boundary violation worth reporting

### 3. WebAuthn & Payment Handler — `content/browser/webauth/`, `components/payments/`
**Result: No exploitable bugs found**
- WebAuthn RP ID validation is browser-side, independent of renderer
- SPC bypass is well-defended (only InternalAuthenticator, credential store filters)
- PaymentHandler openWindow() has double defense (renderer + browser same-origin check)
- ChangePaymentMethod has no method-name scoping but data only reaches merchant page

### 4. FedCM — `content/browser/webid/`
**Result: Feature-gated issue found**
- `redirect_to` in token response navigates to ANY HTTP/HTTPS URL without origin check
- BUT `can_accept_redirect_to_` requires `kFedCmNavigationInterception` (disabled by default)
- Or `HasEmbedderLoginRequest` (enterprise/embedder-only)
- Not exploitable on stable Chrome without flags

### 5. CSP / Synthetic Responses
**Result: No new exploitable bugs**
- Synthetic response CSP enforcement is behind experimental features
- `document.open()` origin aliasing is a known legacy issue (being deprecated)

### 6. WebSocket / WebTransport Sec-Fetch-* Headers
**Result: Confirmed (already reported from earlier session)**
- WebSocket connections send NO Sec-Fetch-* headers
- WebTransport also lacks Sec-Fetch-* headers
- Both bypass `SetFetchMetadataHeaders()` entirely

### 7. Service Worker Static Router `race-network-and-cache`
**Result: CONFIRMED NEW FINDING (already written up)**
- Logic bug at `service_worker_main_resource_loader.cc:915` 
- Validation only checks `matched_source_type == kCache`, misses `kRaceNetworkAndCache`
- Exploitable as CORS bypass when cache wins the race
- VRP report written: `vrp_report_sw_race_network_cache_bypass.md`

## Summary Table

| Area | Files Audited | Finding? | Severity | Exploitable on Stable? |
|------|--------------|----------|----------|----------------------|
| ORB | 5 | No | N/A | N/A |
| FLEDGE | 4 | Yes (242) | Low-Medium | Yes (code defect) |
| WebAuthn/Payment | 8 | No | N/A | N/A |
| FedCM | 5 | Feature-gated | Medium | No (disabled by default) |
| CSP | 3 | No | N/A | N/A |
| WS/WT Sec-Fetch | 4 | Yes (existing) | Medium | Yes |
| SW Static Router | 2 | Yes (new) | High | Yes |

## Key Deliverables This Session

1. **VRP Report** (new): `vrp_report_sw_race_network_cache_bypass.md` — race-network-and-cache logic bug
2. **Finding** (new): `finding_242_register_ad_macro_missing_return.md` — FLEDGE input validation bypass
3. **Finding** (new): `finding_243_coop_reporting_self_comparison.md` — COOP reporting self-comparison (always-true condition)
4. **PoC** (new): `poc/sw_race_cache_bypass.js` + `poc/sw_race_cache_bypass_test.html`

---

## Continuation Session — Additional Coverage Expansion

### 8. COOP (Cross-Origin-Opener-Policy) Enforcement
**Result: One code defect found (Finding 243)**
- `cross_origin_opener_policy_status.cc:275,303` — `response_origin.IsSameOriginWith(response_origin)` always true
- Self-comparison means reports are always queued (gating condition is dead code)
- Only affects reporting, NOT enforcement (BrowsingInstance swap is correctly computed)
- Potential privacy impact: leaks previous URL to response reporter in some cases

### 9. Speculation Rules Prefetch
**Result: No exploitable bugs**
- Cookie change events dropped during pause window (by design)
- No-Vary-Search DCHECK-only validation in release (defense-in-depth gap)
- Contamination delay has timing side-channel weakness (known limitation)
- Cross-origin response isolation is correct

### 10. Drag-Drop / Download
**Result: No exploitable bugs**
- Cross-origin drag-drop has two-layer defense (browser + renderer)
- Download filename sanitization prevents path traversal
- FileSystemAccess token redemption checks process ID

### 11. Web Locks API
**Result: No exploitable bugs**
- Properly partitioned by StorageKey/BucketId
- `steal: true` is same-origin only
- BFCache eviction on contention is by design
- SharedStorage worklet bypass is defended by browser-side origin control

### 12. BFCache + Opener Relationships
**Result: Known design limitation, not exploitable**
- Pages without Cache-Control: no-store restored with stale document state after cookie changes
- This is documented/known behavior, not a logic bug
- BroadcastChannel message race during eviction/restore (extremely narrow window)

### 13. Permission Delegation
**Result: No exploitable bugs**
- Fenced frame permission denial enforced browser-side
- Navigation correctly destroys/recreates permission state
- BFCache/prerender properly handle permission transitions
- DevTools override bypassing fenced frame restrictions is by design

### 14. History API / pushState
**Result: No exploitable bugs on stable**
- `CanChangeToUrlForHistoryApi` allows path changes for "standard" schemes (filesystem:, custom)
- Browser-side `ValidateURLAndOrigin()` provides backup validation
- `kEnforceSameDocumentOriginInvariants` disabled by default but doesn't create exploitable window

### 15. Navigation Origin Mismatch (Active Workaround)
**Result: Documented workaround, not directly exploitable**
- `navigation_request.cc:12506-12519` — weakened origin check allows precursor tuple comparison
- `CHECK(..., base::NotFatalUntil::M140)` — only warning until Chrome 140
- Known bug (crbug.com/421948889) being actively addressed

## Updated Summary Table (Full Session)

| Area | Files Audited | Finding? | Severity | Exploitable on Stable? |
|------|--------------|----------|----------|----------------------|
| ORB | 5 | No | N/A | N/A |
| FLEDGE | 4 | Yes (242) | Low-Medium | Yes (code defect) |
| WebAuthn/Payment | 8 | No | N/A | N/A |
| FedCM | 5 | Feature-gated | Medium | No (disabled by default) |
| CSP | 3 | No | N/A | N/A |
| WS/WT Sec-Fetch | 4 | Yes (existing) | Medium | Yes |
| SW Static Router | 2 | Yes (new) | High | Yes |
| COOP | 3 | Yes (243) | Low | Yes (reporting only) |
| Speculation Rules | 6 | No | N/A | N/A |
| Drag-Drop/Download | 8 | No | N/A | N/A |
| Web Locks | 5 | No | N/A | N/A |
| BFCache | 6 | No (design) | N/A | N/A |
| Permission Delegation | 8 | No | N/A | N/A |
| History/Navigation | 5 | No | N/A | N/A |
