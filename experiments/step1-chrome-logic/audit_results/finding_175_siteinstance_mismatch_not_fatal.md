# Finding 175: Session History Navigation Commits in Wrong SiteInstance (NotFatalUntil::M141)

## Summary

When restoring a session history navigation, Chrome should verify that the navigation commits in the same SiteInstance that was stored in the FrameNavigationEntry. This CHECK is marked `NotFatalUntil::M141`, meaning that in current releases, a session history navigation can commit in a different SiteInstance than intended without crashing the browser process.

## Affected Files

- `content/browser/renderer_host/navigation_controller_impl.cc:2074-2081` — SiteInstance CHECK with NotFatalUntil::M141

## Details

```cpp
// navigation_controller_impl.cc:2074-2081
CHECK(rfh->GetSiteInstance() == frame_entry->site_instance(),
      base::NotFatalUntil::M141)
    << "Session history navigation committed in a different SiteInstance "
       "than intended. "
    << "FrameNavigationEntry SiteInstance: "
    << frame_entry->site_instance()
    << ", Committed RFH SiteInstance: " << rfh->GetSiteInstance()
    << ", URL: " << params.url;
```

When the document sequence number (DSN) matches but the SiteInstance differs, the CHECK is non-fatal. This means:
- A navigation intended for one renderer process committed in another
- Site isolation boundaries may be violated
- The committed page runs in a process that has access to different site data

The check at line 2084-2086 sets `frame_entry = nullptr` if there's a mismatch, but doesn't prevent the navigation from completing.

## Attack Scenario

1. User has session history entries for `https://bank.com` and `https://attacker.com`
2. A race condition or redirect during history restoration causes the bank navigation to commit in the attacker's SiteInstance
3. The CHECK doesn't crash (NotFatalUntil::M141)
4. The bank page runs in a process that also handles `attacker.com`, breaking process isolation
5. If the attacker can compromise their own renderer process, they can now access bank page data from the same process

## Impact

- **Process isolation bypass**: Navigation commits in wrong SiteInstance/process
- **Site isolation violation**: Cross-site pages may share a renderer process
- **Known issue**: The CHECK is intentionally non-fatal, indicating the violation can actually occur
- **Cascading effect**: Finding 174's PageState leak and this SiteInstance mismatch can compound

## VRP Value

**Medium** — Requires specific navigation history state and potentially a compromised renderer to fully exploit. However, the SiteInstance mismatch alone represents a site isolation boundary violation, which Chrome considers high-priority.
