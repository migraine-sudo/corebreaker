# Finding 089: Session History Navigation SiteInstance Mismatch (NotFatalUntil::M141)

## Summary

When a session history (back/forward) navigation commits, Chrome checks that the committed RenderFrameHost's SiteInstance matches the one stored in the FrameNavigationEntry. This CHECK uses `NotFatalUntil::M141`, meaning before M141, a mismatch is logged but does NOT crash the browser. A SiteInstance mismatch means a navigation committed in the wrong process, potentially violating site isolation.

## Affected Files

- `content/browser/renderer_host/navigation_controller_impl.cc:2074-2075` — NotFatalUntil::M141 CHECK
- `content/browser/renderer_host/navigation_controller_impl.cc:143-144` — kCheckSiteInstanceOnHistoryNavigation ENABLED_BY_DEFAULT

## Details

```cpp
// navigation_controller_impl.cc:2074-2075
CHECK(rfh->GetSiteInstance() == frame_entry->site_instance(),
      base::NotFatalUntil::M141)
    << "Session history navigation committed in a different SiteInstance "
       "than intended.";
```

Comment at line 2058-2059 explains: "A mismatch can occur if the renderer lies or due to a unique name collision after a race with an OOPIF."

## Relationship to Other Findings

- Finding 055: PageState not cleared on origin mismatch (NotFatalUntil::M140)  
- Finding 080: ValidateCommitOrigin disabled
- Finding 089 (this): SiteInstance mismatch on history nav (NotFatalUntil::M141)

Together these form a chain: stale session history entries can lead to cross-origin PageState delivery in the wrong process.

## Attack Scenario

1. Compromised renderer triggers a session history navigation
2. Through unique name collision or other race condition, the navigation commits in a different SiteInstance
3. The CHECK doesn't crash (pre-M141), allowing the mismatch to persist
4. The wrong-process RenderFrameHost may access data from another site's session history entry
5. Combined with Finding 055 (PageState not cleared), cross-origin data may leak

## Impact

- **Requires compromised renderer or race condition**: SiteInstance mismatch needs a lie or race
- **Site isolation violation**: Navigation in wrong process
- **Known issue**: Actively being hardened (M141 deadline)

## VRP Value

**Medium** — Site isolation bypass via session history mismatch. The CHECK will become fatal at M141, but currently it's not enforced.
