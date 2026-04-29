# Finding 133: Actor Login Federated Credentials Fetcher Does Not Check Source Origin

## Summary

The `ActorLoginFederatedCredentialsFetcher` retrieves federated credentials from an `IdentityCredentialSource` associated with the current document, but does NOT verify that the source document's origin matches the `request_origin_`. The TODO at crbug.com/480004512 explicitly acknowledges this gap. If the document navigates away during the async fetch, credentials could be obtained from or sent to the wrong origin.

## Affected Files

- `chrome/browser/password_manager/actor_login/internal/actor_login_federated_credentials_fetcher.h:70` — Missing origin check
- `chrome/browser/password_manager/actor_login/internal/actor_login_delegate_impl.cc:267` — Related double-check TODO

## Details

```cpp
// actor_login_federated_credentials_fetcher.h:70
// TODO(crbug.com/480004512): Check the origin of the source before using it.
IdentityCredentialSourceCallback get_source_callback_;
```

The `get_source_callback_` retrieves the `IdentityCredentialSource` bound to the current document. Since the source is fetched lazily (not at request time), there's a TOCTOU race:

1. Actor initiates federated credential fetch for `example.com`
2. Before the async callback completes, the document navigates to `attacker.com`
3. `get_source_callback_` returns the `IdentityCredentialSource` for `attacker.com`
4. Credentials intended for `example.com` may be exposed to `attacker.com`

Additionally, `actor_login_delegate_impl.cc:267` has:
```
// TODO(crbug.com/486089293): Double check that it's impossible to reach
```

## Attack Scenario

1. User asks Actor to log into `example.com`
2. Actor starts the federated login flow
3. Via prompt injection or page script, the page navigates to `attacker.com` during the async credential fetch
4. The credential source callback returns the source for the new document
5. Credentials are used/exposed in the wrong origin context

## Impact

- **No compromised renderer required**: Navigation during async flow is a standard web behavior
- **Credential exposure**: Federated credentials may be sent to wrong origin
- **Actor-specific**: Only affects the AI agent automated login flow
- **Known issue**: crbug.com/480004512

## VRP Value

**Medium-High** — TOCTOU credential exposure in the Actor's automated login flow. Particularly concerning because the AI agent performs multiple async steps where page state can change.
