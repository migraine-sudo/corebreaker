# Round 3: Navigation State Machine Timing -- Origin Confusion During Commit

## Audit Scope

Focused audit of Chromium navigation lifecycle state machine for logic bugs
exploitable without a compromised renderer, on Chrome stable with default flags.

Examined the following attack surfaces:
1. javascript: URL navigation timing and origin inheritance
2. document.open() during pending navigation
3. about:blank initial navigation + immediate cross-origin navigation
4. Window references across navigations (opener access timing)

## Key Files Examined

- `content/browser/renderer_host/navigation_request.cc` (12626 lines)
- `content/browser/renderer_host/render_frame_host_impl.cc`
- `third_party/blink/renderer/core/loader/document_loader.cc`
- `third_party/blink/renderer/core/loader/frame_loader.cc`
- `third_party/blink/renderer/core/dom/document.cc`
- `third_party/blink/renderer/bindings/core/v8/script_controller.cc`
- `content/browser/renderer_host/navigator.cc`
- `third_party/blink/renderer/platform/weborigin/security_origin.cc`

## Navigation State Machine Summary

```
NOT_STARTED -> WAITING_FOR_RENDERER_RESPONSE -> WILL_START_REQUEST
            -> WILL_REDIRECT_REQUEST -> WILL_PROCESS_RESPONSE
            -> READY_TO_COMMIT -> DID_COMMIT
```

The READY_TO_COMMIT -> DID_COMMIT window has a **30 second timeout**
(`kDefaultCommitTimeout`, navigation_request.cc:253), during which the
browser has sent the CommitNavigation IPC but the renderer has not yet
processed it.

---

## Finding 1: document.open() Origin Aliasing Still Active on Stable

**Severity: Medium (defense-in-depth concern, potential for escalation)**

### Description

The feature flag `DocumentOpenOriginAliasRemoval` is set to `"experimental"`
in `runtime_enabled_features.json5:2324`, which means it is **NOT enabled on
Chrome stable** with default flags.

When `document.open()` is called across different windows of the same origin,
the following code in `document.cc:3840-3847` executes:

```cpp
if (!RuntimeEnabledFeatures::DocumentOpenOriginAliasRemovalEnabled()) {
    dom_window_->GetSecurityContext().SetSecurityOrigin(
        entered_window->GetMutableSecurityOrigin());
    entered_window->GetMutableSecurityOrigin()
        ->set_aliased_by_document_open();
}
```

This causes two windows to **share the same mutable SecurityOrigin object**.
Any mutation to one (e.g., `document.domain` setter) directly affects the other.

### Security Implications

1. The browser process is NOT notified of this origin aliasing (document.cc
   comments at lines 3807-3821 explicitly acknowledge this: "From the browser
   process point of view, all of those operations are not considered to produce
   new documents. No IPCs are sent, it is as if it was a no-op.").

2. Combined with `document.domain` (which is deprecated but not yet removed),
   an attacker could use document.open() to alias an origin, then use
   document.domain to relax the same-origin policy, affecting both windows
   simultaneously.

3. The cookie URL is also inherited: `cookie_url_ = entered_window->document()->CookieURL()` (line 3862), meaning cookie scope can shift.

### Exploitation Scenario

```
Window A (attacker.example.com) opens Window B (same origin)
Window A calls B.document.open() -> origins are now aliased
Window A sets document.domain = "example.com"
This mutation affects Window B's origin too (shared object)
```

While document.domain is in deprecation, it is still functional on Chrome
stable and creates a concrete attack surface when combined with origin aliasing.

### Status

The Chromium team is aware this is problematic (extensive TODO comments in code,
UseCounter tracking at WebFeature::kDocumentOpenDifferentWindow and
kDocumentOpenAliasedOriginDocumentDomain). However, the removal is behind an
experimental flag with 0.02% page load impact, suggesting it remains deployed
for compatibility.

---

## Finding 2: javascript: URL Async Execution -- Race with Incoming CommitNavigation

**Severity: Low-Medium (timing-dependent, mitigated by single-threaded execution)**

### Description

When a javascript: URL is navigated, the execution is **deferred** via an async
task posted to the networking task runner:

```cpp
// document.cc:9682-9688
void Document::ProcessJavaScriptUrl(const KURL& url, const DOMWrapperWorld* world) {
    pending_javascript_urls_.push_back(...);
    if (!javascript_url_task_handle_.IsActive()) {
        javascript_url_task_handle_ = PostCancellableTask(
            *GetTaskRunner(TaskType::kNetworking), FROM_HERE,
            BindOnce(&Document::ExecuteJavaScriptUrls, WrapWeakPersistent(this)));
    }
}
```

When `ExecuteJavaScriptUrls` eventually runs (document.cc:9661-9673), it
executes against `dom_window_->GetScriptController()`, using the window's
**current** security context at execution time.

### Analysis

The javascript: URL execution inherits the origin from `IsolatedCopy()` of the
current window's SecurityOrigin (document_loader.cc:2696):

```cpp
} else if (IsJavaScriptURLOrXSLTCommitOrDiscard()) {
    security_origin = frame_->DomWindow()->GetSecurityOrigin()->IsolatedCopy();
}
```

**Mitigating factors:**
- Blink's single-threaded execution model means a CommitNavigation IPC cannot
  interleave with the javascript: URL execution within the same task.
- If a cross-document navigation commits between `ProcessJavaScriptUrl` and
  `ExecuteJavaScriptUrls`, the pending JS URLs are cancelled during
  `Document::Shutdown()` (document.cc:3322) and `Document::open()` (line 3895).
- The script_controller.cc:307-310 check explicitly prevents document
  replacement if a provisional navigation started during execution.

**Remaining concern:** If the parent navigates the iframe via the browser
process (e.g., by setting iframe.src), and the javascript: URL was posted but
not yet executed, there is a theoretical window where the CommitNavigation IPC
for the new document could arrive and be queued while the JS URL task is still
pending. However, since both happen on the same thread and the commit path calls
`FrameLoader::CommitNavigation` which calls `CancelProvisionalLoaderForNewNavigation`,
the pending JS URLs should be properly cleaned up.

**NOT EXPLOITABLE** with an uncompromised renderer under current architecture.

---

## Finding 3: document.open() Does Not Cancel Browser-Side READY_TO_COMMIT Navigation

**Severity: Medium (state inconsistency, potential for further exploitation)**

### Description

When `document.open()` is called on a frame, the renderer-side logic
(document.cc:3891-3893) checks for provisional navigations and stops them:

```cpp
if (GetFrame() && (GetFrame()->Loader().HasProvisionalNavigation() ||
                   IsHttpRefreshScheduledWithin(base::TimeDelta()))) {
    GetFrame()->Loader().StopAllLoaders(/*abort_client=*/true);
}
```

`HasProvisionalNavigation()` returns true only if the renderer has started
processing a navigation (`committing_navigation_ || client_navigation_.get()`).

**Critical gap:** If a browser-initiated navigation has reached READY_TO_COMMIT
in the browser process (CommitNavigation IPC sent) but the renderer has not yet
received/processed it, `HasProvisionalNavigation()` returns **false**, and
`document.open()` proceeds without cancelling the navigation.

The `DidOpenDocumentInputStream` IPC sent to the browser (render_frame_host_impl.cc:6625)
only updates the document URL and calls `set_not_on_initial_empty_document()`.
It does **NOT** cancel the pending NavigationRequest in the browser.

### Impact Analysis

After `document.open()` completes in the renderer:
- The renderer has a document with the opener's origin and URL
- The browser still has a READY_TO_COMMIT navigation pending

When the CommitNavigation IPC finally arrives at the renderer, it will call
`FrameLoader::CommitNavigation()` which will create a new DocumentLoader and
proceed to commit, overwriting the document.open()'d content. The navigation
will likely succeed because the browser had already approved it.

However, during the window between `document.open()` completing and the
CommitNavigation IPC arriving, the document has an inconsistent state between
browser and renderer:
- Browser thinks: navigation to cross-origin URL is pending commit
- Renderer thinks: document belongs to the opener's origin

This window is typically very short (same-process IPC delivery), but:
- Under heavy system load, this window can extend
- The opener can execute JavaScript in the document.open()'d frame during
  this window, potentially setting up state that persists through the commit

### Reproduction difficulty

Hard to exploit in practice because:
1. The window is typically microseconds on same-process IPCs
2. Cross-process navigations use speculative RFH, making the timing even tighter
3. The eventual commit will overwrite the document.open() state

---

## Finding 4: about:blank Origin Inheritance + Synchronous Scripting Window

**Severity: Low (by design, but creates implicit trust assumptions)**

### Description

When an iframe is created, its initial about:blank document **inherits the
parent's origin** via `SetOriginDependentStateOfNewFrame` (render_frame_host_impl.cc:5706-5783):

```cpp
new_frame_origin = new_frame_should_be_sandboxed
                       ? creator_origin.DeriveNewOpaqueOrigin()
                       : creator_origin;
```

And for the renderer-side about:blank navigation, `CalculateOrigin()`
(document_loader.cc:2384) uses `GetMutableSecurityOrigin()` to **alias**
the origin with the parent:

```cpp
origin = owner_document->domWindow()->GetMutableSecurityOrigin();
```

This aliasing is intentional per spec, but creates a window where:
1. An about:blank iframe has the parent's full origin
2. `is_on_initial_empty_document_` is true
3. The iframe is fully scriptable by the parent
4. A cross-origin navigation may be pending in the browser process

### Analysis

The existing test `OriginOfFreshFrame_Subframe_NavCancelledByDocWrite`
(render_frame_host_impl_browsertest.cc:4196) demonstrates that synchronous
`document.open()/write()` cancels pending navigations and the frame retains
the parent origin. This is working as intended.

**However**, the origin aliasing via `GetMutableSecurityOrigin()` means
modifications to the parent's SecurityOrigin (e.g., via document.domain)
affect the about:blank child's origin too, and vice versa. This is the
same aliasing issue as Finding 1 but through a different code path.

### Process model concern

The browser grants the about:blank frame the initiator's origin in `GetUrlInfo()`
(navigation_request.cc:4462-4484):

```cpp
} else if (GetURL().IsAboutBlank() && GetInitiatorOrigin().has_value()) {
    url_info_init.WithOrigin(*GetInitiatorOrigin());
}
```

The comment at navigation_request.cc:4466-4476 acknowledges corner cases where
the source SiteInstance cannot be used, potentially leading to process assignment
issues (referenced crbug.com/1426928).

---

## Finding 5: Window Handle Cross-Navigation Access Timing

**Severity: Low (properly mitigated by existing checks)**

### Description

When `window.open()` returns a handle and the popup navigates cross-origin,
the opener's scripting access must be revoked. The question is whether there
is a gap between "navigation committed" and "security context updated."

### Analysis

The access check uses `SecurityOrigin::CanAccess()` (security_origin.cc:348),
which checks `IsSameOriginDomainWith()` and agent cluster IDs. The origin is
stored in the `SecurityContext` of the `LocalDOMWindow`.

For cross-process navigation of the popup:
1. The popup's LocalFrame is replaced with a RemoteFrame in the opener's
   renderer process
2. The RemoteFrame's security context uses the replicated origin from the
   browser process
3. This replication happens atomically from the opener's perspective via
   `RenderFrameHostManager::DidNavigateFrame()` (navigator.cc:602)

For same-process navigation (e.g., same-site cross-origin with COOP):
1. The origin is updated in `DocumentLoader::InitializeWindow()` ->
   `SetSecurityOrigin()` (document_loader.cc:2869)
2. This happens during `CommitNavigation()` which is synchronous
3. No JavaScript can execute between the old and new security context

**Conclusion:** The existing architecture properly prevents opener access
during the commit transition. Cross-process navigations use RemoteFrame
proxy replacement which is atomic. Same-process navigations update the
security context synchronously during commit.

---

## Summary of Findings

| # | Finding | Severity | Exploitable? |
|---|---------|----------|-------------|
| 1 | document.open() origin aliasing active on stable | Medium | Potentially, with document.domain |
| 2 | javascript: URL async execution race | Low-Medium | No (single-threaded mitigation) |
| 3 | document.open() doesn't cancel browser READY_TO_COMMIT nav | Medium | Difficult (tiny timing window) |
| 4 | about:blank origin aliasing via mutable SecurityOrigin | Low | By design, limited impact |
| 5 | Window handle cross-navigation access | Low | No (properly mitigated) |

## Recommended Next Steps

1. **Finding 1 (highest priority):** Investigate whether the combination of
   document.open() origin aliasing + document.domain can be used to bypass
   site isolation or cookie scoping in a way that constitutes a security
   vulnerability. Specifically:
   - Can origin aliasing + document.domain allow reading cookies from a
     different subdomain?
   - Can the aliased origin be used to bypass CORS checks?

2. **Finding 3:** Construct a PoC that maximizes the timing window between
   document.open() and the arrival of CommitNavigation IPC. Consider:
   - Creating many subframes to increase IPC latency
   - Using slow-loading resources to control navigation timing
   - Check whether any persistent state set during the inconsistency window
     survives the eventual commit

3. **General:** Monitor the rollout of `DocumentOpenOriginAliasRemoval` and
   `kEnforceSameDocumentOriginInvariants` (currently DISABLED by default)
   for schedule and any regressions that might delay deployment.
