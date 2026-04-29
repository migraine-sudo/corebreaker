# Finding 181: ORB (Opaque Response Blocking) Fails Open — Skips JS Parsing and Allows Unknown Responses

## Summary

Chrome's ORB implementation departs from the spec in two critical ways: (1) it skips step 15 (JavaScript parsing check) entirely, and (2) it changes step 16 from "return false" (block) to "return true/kAllow" (allow). This means responses that can't be positively identified as safe to pass through are allowed rather than blocked, creating a fail-open behavior.

## Affected Files

- `services/network/orb/orb_impl.cc:473-482` — Spec deviations documented in comments

## Details

```cpp
// orb_impl.cc:473-482
// TODO(lukasza): Departure from the spec...
// Diff: Skipping/ignoring step 15:
//     15. If response's body parses as JavaScript and does not parse as JSON,
//         then return true.
// Diff: Changing step 16 to fail open (e.g. return true / kAllow):
//     16. Return false.
return Decision::kAllow;
```

The ORB spec is designed to block cross-origin responses that shouldn't be readable. The algorithm works by:
1. Allowing known-safe response types (CORS-approved, same-origin)
2. Blocking known-dangerous types (HTML, XML, JSON)
3. For ambiguous cases (step 15-16), the spec says to parse as JavaScript — if it IS valid JS but NOT valid JSON, block it. Otherwise block it.

Chrome's implementation skips step 15 entirely (no JavaScript parsing) and allows everything that wasn't caught by earlier steps.

## Attack Scenario

### Cross-origin data exfiltration via script tag
1. Attacker has a `<script src="https://victim.com/api/user-data">` tag
2. The response is JSON data containing user information
3. ORB should block this (step 15: "parses as JavaScript" → true for valid JSON; "does not parse as JSON" → false for valid JSON; so step 15 doesn't trigger)
4. But for responses with unusual content-types or edge cases that fall through to step 16, the spec says block (return false)
5. Chrome says allow (return true/kAllow)
6. The response data may be accessible through error handlers or timing side-channels

### Spectre-style attack amplification
1. ORB is a defense-in-depth against Spectre attacks
2. By failing open, ORB allows more cross-origin response data into the renderer process
3. This increases the attack surface for Spectre-style side-channel reads
4. The full JavaScript parsing step (step 15) was specifically designed to catch edge cases

## Impact

- **No compromised renderer required**: Script tag injection is standard HTML
- **Spec violation**: ORB spec explicitly says to block in step 16
- **Defense-in-depth weakening**: ORB is a critical Spectre mitigation
- **Known deviation**: Explicitly documented as a TODO departure from spec

## VRP Value

**Medium** — ORB is a defense-in-depth mechanism against Spectre and data leakage. While individual cases where this fail-open matters may be rare (most dangerous cases are caught by earlier steps), the principle of failing closed is important for security. Chrome acknowledges this is a spec deviation.
