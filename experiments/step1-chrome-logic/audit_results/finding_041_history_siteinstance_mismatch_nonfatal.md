# Finding 041: History Navigation SiteInstance Mismatch Check Non-Fatal (NotFatalUntil::M141)

## Summary

The SiteInstance validation on session history navigation commit (which verifies the renderer committed in the expected process) uses `base::NotFatalUntil::M141`. Before Chrome M141, this check is non-fatal — a mismatch is logged but does not crash or abort the navigation. Combined with a DSN=-1 bypass (cross-document redirects clear the document sequence number), this allows a navigation to commit in the wrong SiteInstance/process.

Additionally, the check is gated behind `kCheckSiteInstanceOnHistoryNavigation` feature flag.

## Affected Files

- `content/browser/renderer_host/navigation_controller_impl.cc:2062-2083` — NotFatalUntil::M141 SiteInstance check
- `content/browser/renderer_host/navigation_controller_impl.cc:2251-2255` — Entry resurrection for pruned entries

## Details

### Non-fatal SiteInstance mismatch

```cpp
// navigation_controller_impl.cc:2062-2083
if (base::FeatureList::IsEnabled(kCheckSiteInstanceOnHistoryNavigation) &&
    frame_entry && frame_entry->site_instance()) {
  int64_t dsn = navigation_request->frame_entry_document_sequence_number();
  if (dsn != -1 && dsn == frame_entry->document_sequence_number()) {
    CHECK(rfh->GetSiteInstance() == frame_entry->site_instance(),
          base::NotFatalUntil::M141)  // NON-FATAL before M141
        << "Session history navigation committed in a different SiteInstance";
  }
}
```

Before M141, this CHECK is equivalent to a `DumpWithoutCrashing` — the mismatch is detected, logged, but the navigation proceeds. The renderer that committed in the wrong process continues running.

### DSN bypass via cross-document redirect

When a cross-document redirect occurs during history navigation, the document sequence number is cleared to -1. This causes the `dsn != -1` check to fail, skipping the SiteInstance validation entirely. A crafted redirect during back/forward navigation bypasses the check.

### Entry resurrection

```cpp
// navigation_controller_impl.cc:2251-2255
if (existing_entry_index == -1) {
  // The renderer has committed a navigation to an entry that no longer
  // exists. Because the renderer is showing that page, resurrect that entry.
  return NAVIGATION_TYPE_MAIN_FRAME_NEW_ENTRY;
}
```

A compromised renderer committing with a fabricated or stale `nav_entry_id` causes entry resurrection — creating a new history entry from renderer-supplied parameters without validating the original entry.

## Attack Scenario

1. Attacker crafts a page that establishes session history entries
2. A cross-document redirect during back navigation clears the DSN to -1
3. The history navigation commits in a different SiteInstance than expected
4. The SiteInstance check is skipped (DSN=-1) or non-fatal (NotFatalUntil::M141)
5. The renderer now runs content from origin A in a process potentially locked to origin B
6. Site isolation boundary is violated

### Entry resurrection attack

1. Compromised renderer sends a commit IPC with a `nav_entry_id` for a pruned/removed entry
2. `ClassifyNavigation` returns `NAVIGATION_TYPE_MAIN_FRAME_NEW_ENTRY` (resurrection)
3. A new history entry is created from renderer-supplied URL/origin parameters
4. The attacker has injected an arbitrary entry into session history

## Impact

- **Site isolation bypass**: Navigation can commit in wrong SiteInstance without fatal consequence
- **Feature-gated + non-fatal**: Double defense failure — check may be disabled AND is non-fatal
- **Session history corruption**: Entry resurrection from renderer parameters
- **DSN bypass**: Cross-document redirects circumvent the validation entirely

## VRP Value

**Medium** — The SiteInstance mismatch being non-fatal is a significant defense-in-depth gap. The DSN bypass through cross-document redirects provides a clean evasion path. Requires either a compromised renderer or a redirect-based timing attack. The entry resurrection pattern amplifies the impact.
