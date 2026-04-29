# Finding 037: Fenced Frame Network Cutoff Race — disableUntrustedNetwork() Bypass via Child Navigation

## Summary

A documented race condition in fenced frame network cutoff allows a child fenced frame to retain network access after the parent believes network has been disabled. When a parent fenced frame calls `disableUntrustedNetwork()` while a child nested fenced frame has an ongoing navigation, the network cutoff is deferred via a deny-list rather than enforced atomically. The race window allows the child's navigation to complete with full network access.

## Affected Files

- `content/browser/renderer_host/render_frame_host_impl.cc:11265-11279` — Race condition mitigation (incomplete)

## Details

```cpp
// render_frame_host_impl.cc:11265-11279
if ((!network_cutoff_ready || it->HasNavigation()) &&
    it->GetParentOrOuterDocument() &&
    it->GetParentOrOuterDocument()->IsNestedWithinFencedFrame()) {
  // Check for ongoing navigations to prevent race conditions. If a parent
  // fenced frame embeds a child nested fenced frame, and that child frame
  // disables its network and then immediately is navigated by its parent,
  // we can end up in a state where the parent thinks network is revoked for
  // all its children, but network is still allowed in the child fenced
  // frame.
  nodes_not_eligible_for_network_cutoff.insert(
      it->GetParentOrOuterDocument()
          ->GetMainFrame()
          ->frame_tree_node()
          ->frame_tree_node_id());
}
```

The mitigation is a **deny-list approach**: nodes with ongoing navigations are marked as not eligible for network cutoff. But this only prevents the cutoff from being applied — it doesn't ensure the cutoff is eventually enforced after the navigation completes. The race window between `disableUntrustedNetwork()` and the navigation completion remains open.

## Attack Scenario

1. Ad tech script creates a parent fenced frame (from Protected Audiences auction)
2. Parent fenced frame embeds a child nested fenced frame
3. Parent calls `disableUntrustedNetwork()` to satisfy the API requirement for cross-site data access
4. Simultaneously, parent navigates the child fenced frame to a new URL
5. The child's navigation started before the network cutoff propagated
6. Child's new document loads with full network access
7. The parent believes network is disabled for all children
8. The child can exfiltrate cross-site data that should have been sealed after the network cutoff

### Privacy Sandbox violation

The Privacy Sandbox fenced frame API promises that after `disableUntrustedNetwork()`, no further network requests can leak cross-site data. This race violates that promise — the child fenced frame can make arbitrary network requests after the parent has "disabled" network.

## Impact

- **No compromised renderer needed**: Standard JavaScript API usage from fenced frame content
- **Privacy Sandbox data leak**: Cross-site data accessible after "network disabled"
- **Race condition**: Requires timing coordination between parent and child fenced frames
- **Acknowledged but incomplete fix**: The current mitigation narrows but does not close the race window

## VRP Value

**Medium** — The race condition is documented in the code comments. The deny-list mitigation is acknowledged as incomplete. The attack requires timing coordination but is web-level (no renderer compromise). Privacy Sandbox data isolation is the primary security property at risk.
