# Finding 109: Shared Storage Budget Charger Can Be Bypassed via Initiator Frame Destruction Race

## Severity: MEDIUM

## Location
- `content/browser/shared_storage/shared_storage_budget_charger.cc`, lines 43-55

## Description

The `SharedStorageBudgetCharger::DidStartNavigation()` method charges the Shared Storage budget when a fenced frame triggers a top-level navigation. However, this budget charge depends on finding the initiator frame at navigation start time. The code explicitly acknowledges a bypass:

```cpp
// Skip if we cannot find the initiator frame host. This can happen when the
// initiator frame starts a top navigation and then triggers its own
// destruction by navigating to a cross-origin frame, so that it may no longer
// exist by the time we get here.
//
// The risk of getting unlimited budget this way seems to be small: the ideal
// timing can vary from time to time, and whether the timing exist at all also
// depends on the ordering of messaging.
//
// For now, allow the leak and track with UMA (and revisit as needed).
// https://crbug.com/1331111
if (!initiator_frame_host)
  return;
```

When the initiator frame is destroyed between initiating a top-level navigation and `DidStartNavigation()` being called, the budget is never charged. This is a known race condition that the Chromium team has acknowledged but left open.

## Impact

The Shared Storage navigation budget is the primary defense against cross-site information leakage through selectURL. If a site can reliably trigger top-level navigations from a fenced frame while simultaneously destroying the initiator frame, it can exfiltrate arbitrary amounts of cross-site data without being charged any budget.

The comment says the timing is hard to hit reliably, but it depends on message ordering between the renderer and browser processes, which an attacker with sufficient control over timing (e.g., via worker threads, precise setTimeout) could potentially exploit.

## Exploit Scenario

1. Call `selectURL()` to resolve a URN containing cross-site information in the URL
2. Navigate a fenced frame to the URN
3. From the fenced frame, initiate a top-level navigation (clicks or form submission)
4. Simultaneously, have the initiator frame navigate itself to a cross-origin URL, causing its RenderFrameHost to be destroyed
5. `DidStartNavigation()` fires but cannot find the initiator frame, so budget is not charged
6. Repeat to exfiltrate more bits of information

## References
- crbug.com/1331111
- UMA metric: `Navigation.MainFrame.RendererInitiated.InitiatorFramePresentAtStart`
