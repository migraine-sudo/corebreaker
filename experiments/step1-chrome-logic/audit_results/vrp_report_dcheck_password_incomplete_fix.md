# Chrome VRP Report: Incomplete Fix for CVE-2026-6312 — Residual DCHECK-only Security Checks in Password Manager

## Summary

CL 7735722 fixed CVE-2026-6312 (High) by converting a DCHECK to a runtime check in `PasswordManager::OnPresaveGeneratedPassword`. However, the same security property (`IsSavingAndFillingEnabled`) is still guarded by DCHECK-only assertions in **3 other code paths** within the Password Manager. The most critical is in `CredentialManagerImpl::OnProvisionalSaveComplete`, where a DCHECK-only check combined with an asynchronous callback creates a TOCTOU window that allows credential storage even when saving is disabled by policy or Incognito mode.

## Affected Component

`components/password_manager/core/browser/`

## Chromium Version

Tested against Chromium HEAD as of 2026-04-27 (shallow clone).

## Vulnerability Details

### Background: CVE-2026-6312 Fix

CL 7735722 converted `DCHECK(client_->IsSavingAndFillingEnabled(...))` to a runtime `if` check in `OnPresaveGeneratedPassword` (password_manager.cc:724). This prevents password pre-saving when the user is in Incognito or enterprise policy disables password saving.

### Residual DCHECK Locations

Three other call sites still use DCHECK for the same security-critical check:

#### 1. `credential_manager_impl.cc:325` — `OnProvisionalSaveComplete` (Most Critical)

```cpp
void CredentialManagerImpl::OnProvisionalSaveComplete() {
  DCHECK(form_manager_);
  const PasswordForm& form = form_manager_->GetPendingCredentials();
  DCHECK(client_->IsSavingAndFillingEnabled(form.url));  // <-- DCHECK only
  // ...
  form_manager_->Save();  // Saves credential without runtime check!
}
```

**TOCTOU Attack Chain:**

1. Web page calls `navigator.credentials.store(credential)` — the `Store()` method at line 77 performs a runtime `IsSavingAndFillingEnabled()` check, which passes.
2. `Store()` creates a `CredentialManagerPasswordFormManager` which triggers an asynchronous password store query (`FormFetcherImpl`).
3. **During the async fetch**, the policy state changes (e.g., MDM pushes a policy disabling password saving, user enters Incognito, or user toggles password saving off in settings).
4. The fetch completes and calls `OnFetchCompleted()` → `NotifyDelegate()` → `OnProvisionalSaveComplete()`.
5. The DCHECK at line 325 is a no-op in release builds.
6. `form_manager_->Save()` is called — **credential is saved despite saving being disabled**.

#### 2. `password_manager.cc:698` — `OnPasswordNoLongerGenerated`

```cpp
void PasswordManager::OnPasswordNoLongerGenerated(...) {
  DCHECK(client_->IsSavingAndFillingEnabled(form_data.url()));  // DCHECK only
  // Continues to modify form manager state
}
```

Impact: Low — only clears the generation flag on a form manager.

#### 3. `password_manager.cc:714` — `SetGenerationElementAndTypeForForm`

```cpp
if (form_manager) {
  DCHECK(client_->IsSavingAndFillingEnabled(form_manager->GetURL()));  // DCHECK only
  form_manager->SetGenerationElement(generation_element);
  form_manager->SetGenerationPopupWasShown(type);
}
```

Impact: Low-Medium — marks a field as the password generation element and records that the generation popup was shown.

### Contrast with the Fix

The fixed function `OnPresaveGeneratedPassword` at line 724 uses a proper runtime check:

```cpp
void PasswordManager::OnPresaveGeneratedPassword(...) {
  if (!client_->IsSavingAndFillingEnabled(form_data.url())) {
    return;  // Proper runtime check
  }
  // ...
}
```

The three unfixed locations use the exact same security property but rely on DCHECK, which is compiled out in release builds (`-DNDEBUG`).

## Impact

- **Policy Bypass**: Enterprise administrators who disable password saving via policy may have credentials stored despite the policy.
- **Incognito Bypass**: Credentials saved via the Credential Management API may persist even if the saving context transitions to one where saving should be disabled.
- **Severity**: Medium-High for the credential_manager_impl.cc path (actual credential storage); Low for the password_manager.cc paths (state modification only).

## Suggested Fix

Replace the 3 DCHECKs with runtime if-checks, consistent with the CVE-2026-6312 fix:

```cpp
// credential_manager_impl.cc:325
void CredentialManagerImpl::OnProvisionalSaveComplete() {
  DCHECK(form_manager_);
  const PasswordForm& form = form_manager_->GetPendingCredentials();
  if (!client_->IsSavingAndFillingEnabled(form.url))
    return;
  // ... rest of function
}

// password_manager.cc:698
void PasswordManager::OnPasswordNoLongerGenerated(...) {
  if (!client_->IsSavingAndFillingEnabled(form_data.url()))
    return;
  // ... rest of function
}

// password_manager.cc:714
if (form_manager) {
  if (!client_->IsSavingAndFillingEnabled(form_manager->GetURL()))
    return;
  form_manager->SetGenerationElement(generation_element);
  form_manager->SetGenerationPopupWasShown(type);
}
```

## Related

- CVE-2026-6312 (High): Fixed by CL 7735722
- This report: Incomplete fix — same security property, same component, 3 unfixed code paths
