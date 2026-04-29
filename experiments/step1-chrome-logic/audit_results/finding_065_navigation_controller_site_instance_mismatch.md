# Finding 065: Session History Navigation SiteInstance Mismatch Not Enforced (NotFatalUntil::M141)

## Summary

When a session history (back/forward) navigation commits, the NavigationController checks whether the committed RenderFrameHost's SiteInstance matches the one stored in the FrameNavigationEntry. This CHECK is `NotFatalUntil::M141` — not enforced in current releases. A SiteInstance mismatch means a page committed in the wrong process, violating site isolation.

Additionally, a second CHECK at line 4342 (`NotFatalUntil::M140`) allows navigating a FrameTreeNode from the wrong NavigationController (wrong FrameTree).

## Affected Files

- `content/browser/renderer_host/navigation_controller_impl.cc:2074-2075` — SiteInstance mismatch not enforced
- `content/browser/renderer_host/navigation_controller_impl.cc:4342-4343` — Wrong NavigationController not enforced

## Details

### SiteInstance mismatch at commit

```cpp
// navigation_controller_impl.cc:2074-2075
CHECK(rfh->GetSiteInstance() == frame_entry->site_instance(),
      base::NotFatalUntil::M141)
    << "Session history navigation committed in a different SiteInstance "
       "than intended.";
```

This means a back/forward navigation can commit in a process assigned to a different site. Data for the wrong site could become accessible to the process.

### Wrong NavigationController

```cpp
// navigation_controller_impl.cc:4342-4343
CHECK(!FrameTreeNode::GloballyFindByID(params.frame_tree_node_id),
      base::NotFatalUntil::M140);
```

If a FrameTreeNode from one FrameTree (e.g., incognito) is navigated via a NavigationController from another FrameTree (e.g., regular), session history could be mixed.

## Impact

- **Site isolation bypass**: Page commits in wrong process
- **Cross-site data access**: Wrong SiteInstance means wrong security principal
- **Session history confusion**: FrameTreeNode navigated via wrong controller

## VRP Value

**Medium** — These are defensive checks that catch bugs in navigation logic. Triggering them from web content is not straightforward but not impossible (e.g., race conditions during back/forward navigation with redirects).
