# Finding 094: Supervised User Parent Approval Bypass via Unsupported Requirements

## Summary

When an extension has unsupported requirements, the parent approval prompt is skipped. If those requirements are later satisfied (e.g., after a Chrome update), the extension can be enabled via `management.setEnabled()` without ever getting parent approval.

## Affected Files

- `extensions/browser/api/management/management_api.cc:681-686` — Parent approval bypass

## Details

```cpp
// management_api.cc:681-686
  // Don't prompt the user if the extension has unsupported requirements.
  // TODO(crbug.com/40127008): If OnRequirementsChecked() passes, the extension
  // will enable, bypassing parent approval.
  if (HasUnsupportedRequirements(extension_id_)) {
    return false;  // false = "parent approval not required"
  }
```

## Attack Scenario

1. Child user on supervised account installs extension X
2. Extension X has requirements that are currently unsupported → parent approval skipped
3. Chrome updates, requirements now satisfied
4. Any code calling `management.setEnabled()` enables the extension without parent consent
5. Extension is now active on supervised account without parental review

## Impact

- **No compromised renderer required**: Standard extension management flow
- **Parental controls bypass**: Extension enabled without parent consent
- **Known issue**: crbug.com/40127008

## VRP Value

**Medium** — Parental controls bypass. Specific conditions required but the impact is clear.
