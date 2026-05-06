# Intent Redirection Scan Results

**Date**: 2026-04-30
**Target**: services.jar DEX files
**Total findings**: 6
**Unmitigated**: 4
**Mitigated**: 2

---

## Unmitigated Findings (Priority Review)

### `android.accounts.AccountManager$AmsTask$Response.onResult`

- **Signature**: `(Landroid/os/Bundle;)V`
- **Sinks**: startActivity
- **Sources**: getParcelable
- **Mitigations**: NONE

### `android.service.chooser.ChooserManager.startSession`

- **Signature**: `(Landroid/content/Context;Landroid/content/Intent;)Landroid/service/chooser/ChooserSession;`
- **Sinks**: startActivity
- **Sources**: getAction
- **Mitigations**: NONE

### `android.service.quicksettings.IQSService$Stub.onTransact`

- **Signature**: `(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z`
- **Sinks**: startActivity
- **Sources**: readTypedObject, readTypedObject, readTypedObject
- **Mitigations**: NONE

### `com.android.ims.internal.uce.uceservice.IUceService$Stub.onTransact`

- **Signature**: `(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z`
- **Sinks**: startService
- **Sources**: readTypedObject, readTypedObject, readTypedObject, readTypedObject
- **Mitigations**: NONE

---

## Mitigated Findings

- `android.app.IActivityManager$Stub.onTransact` — setPackage
- `android.app.IActivityTaskManager$Stub.onTransact` — setPackage, setPackage
