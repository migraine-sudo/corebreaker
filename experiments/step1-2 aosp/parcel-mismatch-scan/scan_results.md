# Parcel Mismatch Scan Results

**Target**: Pixel 10 framework.jar (Android 16, CP1A.260405.005)
**Date**: 2026-04-30
**Classes scanned**: 73
**Classes with data**: 73
**Findings**: HIGH=7 MEDIUM=1 OK=64 INFO=0

---

## [HIGH] `android.app.appfunctions.GenericDocumentWrapper`

**LENGTH MISMATCH: writes=4 reads=1 (diff=3)**

writeToParcel (4 calls):
```
  writeInt
  writeBlob
  writeInt
  writeInt
```

createFromParcel (1 calls):
```
  readInt
```

---

## [HIGH] `android.companion.virtual.camera.VirtualCameraConfig`

**LENGTH MISMATCH: writes=8 reads=7 (diff=1)**

writeToParcel (8 calls):
```
  writeString8
  writeStrongInterface
  writeParcelableArray
  writeInt
  writeInt
  writeBoolean
  writeTypedObject
  writeTypedObject
```

createFromParcel (7 calls):
```
  readString8
  readStrongBinder
  readParcelableArray
  readInt
  readInt
  readBoolean
  readTypedObject
```

---

## [HIGH] `android.telephony.satellite.PlmnSatelliteConfig`

**LENGTH MISMATCH: writes=3 reads=2 (diff=1)**

writeToParcel (3 calls):
```
  writeInt
  writeInt
  writeInt
```

createFromParcel (2 calls):
```
  readInt
  readInt
```

---

## [HIGH] `android.telephony.satellite.SatelliteCapabilities`

**LENGTH MISMATCH: writes=9 reads=7 (diff=2)**

writeToParcel (9 calls):
```
  writeInt
  writeInt
  writeInt
  writeBoolean
  writeInt
  writeInt
  writeInt
  writeParcelable
  writeInt
```

createFromParcel (7 calls):
```
  readInt
  readInt
  readBoolean
  readInt
  readInt
  readInt
  readParcelable
```

---

## [HIGH] `android.telephony.satellite.SatelliteModemEnableRequestAttributes`

**LENGTH MISMATCH: writes=3 reads=4 (diff=-1)**

writeToParcel (3 calls):
```
  writeBoolean
  writeBoolean
  writeBoolean
```

createFromParcel (4 calls):
```
  readBoolean
  readBoolean
  readBoolean
  readParcelable
```

---

## [HIGH] `android.telephony.satellite.SatelliteSessionStats`

**LENGTH MISMATCH: writes=12 reads=11 (diff=1)**

writeToParcel (12 calls):
```
  writeInt
  writeInt
  writeInt
  writeInt
  writeInt
  writeLong
  writeLong
  writeLong
  writeInt
  writeInt
  writeParcelable
  writeInt
```

createFromParcel (11 calls):
```
  readInt
  readInt
  readInt
  readInt
  readInt
  readLong
  readLong
  readLong
  readInt
  readInt
  readParcelable
```

---

## [HIGH] `android.telephony.satellite.SystemSelectionSpecifier`

**LENGTH MISMATCH: writes=11 reads=8 (diff=3)**

writeToParcel (11 calls):
```
  writeString8
  writeInt
  writeInt
  writeInt
  writeInt
  writeInt
  writeInt
  writeTypedArray
  writeInt
  writeInt
  writeInt
```

createFromParcel (8 calls):
```
  readString
  readInt
  readInt
  readInt
  readInt
  readList
  readInt
  readInt
```

---

## [MEDIUM] `android.hardware.biometrics.IdentityCheckStatus`

**TYPE MISMATCH at 2 positions: @0: writeBoolean vs readByte; @1: writeBoolean vs readByte**

writeToParcel (2 calls):
```
  writeBoolean
  writeBoolean
```

createFromParcel (2 calls):
```
  readByte
  readByte
```

---

## OK (matched)

- `android.app.appfunctions.AppFunctionAidlSearchSpec`: Matched (3 fields)
- `android.app.appfunctions.AppFunctionException`: Matched (3 fields)
- `android.app.appfunctions.AppFunctionMetadata`: Matched (2 fields)
- `android.app.appfunctions.AppFunctionName`: Matched (2 fields)
- `android.app.appfunctions.AppFunctionPackageMetadata`: Matched (1 fields)
- `android.app.appfunctions.AppFunctionSchemaMetadata`: Matched (3 fields)
- `android.app.appfunctions.AppFunctionSearchSpec`: Matched (5 fields)
- `android.app.appfunctions.AppFunctionUriGrant`: Matched (1 fields)
- `android.app.appfunctions.ExecuteAppFunctionAidlRequest`: Matched (3 fields)
- `android.app.appfunctions.ExecuteAppFunctionRequest`: Matched (4 fields)
- `android.app.appfunctions.ExecuteAppFunctionResponse`: Matched (2 fields)
- `android.companion.virtual.ActivityPolicyExemption`: Matched (3 fields)
- `android.companion.virtual.ViewConfigurationParams`: Matched (9 fields)
- `android.companion.virtual.VirtualDevice`: Matched (5 fields)
- `android.companion.virtual.camera.VirtualCameraSessionConfig`: Matched (1 fields)
- `android.companion.virtual.camera.VirtualCameraStreamConfig`: Matched (5 fields)
- `android.companion.virtual.computercontrol.ComputerControlSessionParams`: Matched (3 fields)
- `android.companion.virtual.sensor.VirtualSensor`: Matched (6 fields)
- `android.companion.virtual.sensor.VirtualSensorAdditionalInfo`: Matched (3 fields)
- `android.companion.virtual.sensor.VirtualSensorEvent`: Matched (3 fields)
- `android.credentials.ClearCredentialStateRequest`: Matched (1 fields)
- `android.credentials.CreateCredentialRequest`: Matched (6 fields)
- `android.credentials.CreateCredentialResponse`: Matched (1 fields)
- `android.credentials.Credential`: Matched (2 fields)
- `android.credentials.CredentialDescription`: Matched (3 fields)
- `android.credentials.CredentialOption`: Matched (5 fields)
- `android.credentials.CredentialProviderInfo`: Matched (5 fields)
- `android.credentials.GetCandidateCredentialsRequest`: Matched (3 fields)
- `android.credentials.GetCandidateCredentialsResponse`: Matched (3 fields)
- `android.credentials.GetCredentialRequest`: Matched (4 fields)
- `android.credentials.GetCredentialResponse`: Matched (1 fields)
- `android.credentials.ListEnabledProvidersResponse`: Matched (1 fields)
- `android.credentials.PrepareGetCredentialResponseInternal`: Matched (5 fields)
- `android.credentials.RegisterCredentialDescriptionRequest`: Matched (1 fields)
- `android.credentials.SetEnabledProvidersRequest`: Matched (1 fields)
- `android.credentials.UnregisterCredentialDescriptionRequest`: Matched (1 fields)
- `android.credentials.selection.AuthenticationEntry`: Matched (5 fields)
- `android.credentials.selection.BaseDialogResult`: Matched (1 fields)
- `android.credentials.selection.CancelSelectionRequest`: Matched (3 fields)
- `android.credentials.selection.CreateCredentialProviderData`: Matched (2 fields)
- `android.credentials.selection.Entry`: Matched (5 fields)
- `android.credentials.selection.FailureDialogResult`: Matched (1 fields)
- `android.credentials.selection.GetCredentialProviderData`: Matched (4 fields)
- `android.credentials.selection.ProviderPendingIntentResponse`: Matched (2 fields)
- `android.credentials.selection.RequestInfo`: Matched (9 fields)
- `android.credentials.selection.UserSelectionDialogResult`: Matched (4 fields)
- `android.hardware.biometrics.IdentityCheckInfo`: Matched (3 fields)
- `android.proximity.RangingParams`: Matched (2 fields)
- `android.security.talisman.TalismanIdentitySet`: Matched (5 fields)
- `android.service.autofill.ConvertCredentialRequest`: Matched (2 fields)
- `android.service.autofill.ConvertCredentialResponse`: Matched (3 fields)
- `android.service.security.talisman.TalismanIdentitySetNeed`: Matched (4 fields)
- `android.telephony.satellite.AntennaDirection`: Matched (3 fields)
- `android.telephony.satellite.AntennaPosition`: Matched (2 fields)
- `android.telephony.satellite.EarfcnRange`: Matched (2 fields)
- `android.telephony.satellite.NtnSignalStrength`: Matched (1 fields)
- `android.telephony.satellite.PointingInfo`: Matched (2 fields)
- `android.telephony.satellite.SatelliteAccessConfiguration`: Matched (3 fields)
- `android.telephony.satellite.SatelliteDatagram`: Matched (1 fields)
- `android.telephony.satellite.SatelliteInfo`: Matched (4 fields)
- `android.telephony.satellite.SatellitePosition`: Matched (2 fields)
- `android.telephony.satellite.SatelliteSubscriberInfo`: Matched (5 fields)
- `android.telephony.satellite.SatelliteSubscriberProvisionStatus`: Matched (2 fields)
- `android.telephony.satellite.SatelliteSubscriptionInfo`: Matched (2 fields)

## INFO (incomplete extraction)

