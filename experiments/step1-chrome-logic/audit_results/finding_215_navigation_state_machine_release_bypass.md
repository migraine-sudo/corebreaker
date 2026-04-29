# Finding 215: Navigation State Machine Validation Completely Skipped in Release Builds

## Summary

`NavigationRequest::CheckStateTransition()` validates the entire navigation state machine (the sequence of states a navigation goes through), but this validation is completely inside `#if DCHECK_IS_ON()`. In release builds, a compromised renderer can send navigation messages in any order, bypassing the state machine. This means critical state transitions (e.g., skipping from NOT_STARTED directly to DID_COMMIT) are not caught.

## Affected Files

- `content/browser/renderer_host/navigation_request.cc:10901-10966` — State machine validation DCHECK-only

## Details

```cpp
// navigation_request.cc:10901-10966
void NavigationRequest::CheckStateTransition(NavigationState state) const {
#if DCHECK_IS_ON()
    static const base::NoDestructor<base::StateTransitions<NavigationState>>
        transitions(base::StateTransitions<NavigationState>({
            {NOT_STARTED, {WAITING_FOR_RENDERER_RESPONSE, WILL_START_NAVIGATION, WILL_START_REQUEST}},
            {WILL_START_REQUEST, {WILL_REDIRECT_REQUEST, WILL_PROCESS_RESPONSE, ...}},
            {READY_TO_COMMIT, {NOT_STARTED, DID_COMMIT, DID_COMMIT_ERROR_PAGE}},
            // ... full state machine definition
        }));
    DCHECK_STATE_TRANSITION(transitions, state_, state);
#endif  // DCHECK_IS_ON()
}
```

The navigation state machine defines valid transitions:
- NOT_STARTED → WILL_START_NAVIGATION → WILL_START_REQUEST → WILL_PROCESS_RESPONSE → READY_TO_COMMIT → DID_COMMIT

In release builds, this entire validation is skipped. A compromised renderer could attempt to:
1. Skip directly from NOT_STARTED to DID_COMMIT (bypassing security checks in intermediate states)
2. Go from CANCELING back to normal states
3. Commit without going through WILL_PROCESS_RESPONSE (where CORS/CORB checks happen)

## Attack Scenario

1. Compromised renderer sends a DidCommit IPC for a navigation that hasn't gone through the full pipeline
2. In debug builds, CheckStateTransition would catch the invalid transition and crash
3. In release builds, the state machine check is skipped entirely
4. The navigation might commit without having gone through:
   - Security checks in WillStartRequest
   - CORS/ORB checks in WillProcessResponse
   - CSP checks in ReadyToCommit
5. This could lead to committing a document in the wrong security context

## Impact

- **Requires compromised renderer**: Must forge Mojo navigation messages
- **State machine bypass**: Navigation security checks in intermediate states can be skipped
- **Defense-in-depth failure**: State machine is the foundation of navigation security
- **Systematic**: All 12 state transitions are unchecked in release

## VRP Value

**Medium** — The navigation state machine is fundamental to Chrome's navigation security model. While individual security checks exist at each state, the state machine ensures they execute in order. Skipping this validation in release means a compromised renderer has more freedom to manipulate navigation flow.
