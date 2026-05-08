# Remote Start (RST) — Developer Notes

> Reverse-engineered from the myVW Android APK (decompiled via jadx) and
> validated against a 2024 VW Atlas (ICE, TSP="ATC") in May 2025.
> Related GitHub issue: https://github.com/zackcornelius/CarConnectivity-connector-volkswagen-na/issues/38

## Overview

Remote Start (RST) is available on ICE and hybrid VW NA vehicles that use the
**Aeris** telematics provider (TSP = `"ATC"`). Electric vehicles use WirelessCar
(`"WCT"`) and do not support RST — they use climatization pre-conditioning instead.

The RST API uses a **5-step challenge-response flow** that requires two separate
SPIN challenges (each challenge is single-use).

## TSP (Telematics Service Provider)

The TSP value comes from the RRS (Remote Rendered Shell) vehicle data at:
```
GET /rrs/v1/vehicles  →  data[].tsp
```
- `"WCT"` — WirelessCar (MEB/EV platform, e.g. ID.4)
- `"ATC"` — Aeris (ICE platform, e.g. Atlas, Taos, Tiguan, Jetta)

The TSP determines which session endpoint to use and which auth token to
pass as Bearer to RST endpoints.

## API Flow

### Step 1: Fetch Challenge 1
```
GET /ss/v1/user/{userId}/challenge
Authorization: Bearer {OAuth access_token}
→ {"data": {"challenge": "...", "remainingTries": N}}
```

### Step 2: Create ATC Session → carnetVehicleToken
```
POST /ss/v1/user/{userId}/vehicle/{vehicleId}/session
Authorization: Bearer {OAuth access_token}
Content-Type: application/json

{
  "idToken": "{OIDC id_token}",
  "spinHash": "{SHA-512(challenge1 + '.' + spin)}",
  "tsp": "ATC"
}

→ {"data": {"carnetVehicleToken": "eyJ..."}}
```
The `carnetVehicleToken` is a JWT issued by the ATC backend. It is used as
Bearer auth for all subsequent RST calls.

### Step 3: Fetch Challenge 2
```
GET /ss/v1/user/{userId}/challenge
Authorization: Bearer {OAuth access_token}
→ {"data": {"challenge": "...", "remainingTries": N}}
```
**CRITICAL:** Must fetch a NEW challenge. Challenge 1 was consumed by Step 2.
Re-using it will fail with `SPIN_CHALLENGE_NOT_FOUND` (404).

### Step 4: Climate Control Check → roToken
```
POST /ss/v1/user/{userId}/vehicle/{vehicleId}/operation/climateControl/check
Authorization: Bearer {carnetVehicleToken}
Content-Type: application/json

{
  "spinHash": "{SHA-512(challenge2 + '.' + spin)}"
}

→ {"data": {"roToken": "base64-encoded-opaque-token"}}
```
The `roToken` is an opaque server-issued token (NOT a JWT). It must be passed
as-is in the RST request body.

### Step 5a: Start Engine
```
POST /rst/v1/vehicle/{vehicleId}
Authorization: Bearer {carnetVehicleToken}
Content-Type: application/json

{
  "roToken": "{roToken from Step 4}"
}

→ {"result": 0, "correlationId": "uuid-string"}
```

### Step 5b: Stop Engine
```
DELETE /rst/v1/vehicle/{vehicleId}
Authorization: Bearer {carnetVehicleToken}

→ {"result": 0, "correlationId": "uuid-string"}
```

### Command Status Polling
```
GET /history/v1/vehicle/{vehicleId}/correlationId/{correlationId}/ro/
Authorization: Bearer {carnetVehicleToken}
```

## Wire Field Names

Field names in the JSON payloads differ from Kotlin variable names in the APK:

| Wire (JSON)                   | Kotlin variable       | Notes                           |
|-------------------------------|-----------------------|---------------------------------|
| `spinHash`                    | `spinHash`            | SHA-512 of challenge + "." + SPIN |
| `rstSpinHash`                 | `rstPinHash`          | Alternative name in some flows  |
| `roToken`                     | `roToken`             | Opaque base64, NOT a JWT        |
| `encryptedPayloadSignature`   | `encryptedSignature`  | For paired/signed requests      |

## SPIN Hash Computation

```python
import hashlib
spin_hash = hashlib.sha512(f"{challenge}.{spin}".encode("utf-8")).hexdigest().upper()
```

## Device Pairing (Optional)

The full APK flow supports device pairing with encrypted payloads:
```
GET /pair/v1/vehicle/{vehicleId}
Authorization: Bearer {carnetVehicleToken}
→ {"data": {"pairingId": "...", "pairingKeySeed": "...", "pairingStatus": "..."}}
```

When paired, the RST body can include additional fields:
- `timestamp` — XOR'd with pairing key seed
- `encryptedPayload` — CRC of timestamp
- `encryptedPayloadSignature` — ECDSA signature from AndroidKeyStore

**However**, our testing shows that the minimal body `{"roToken": "..."}` works
without pairing data. The server accepts it and returns a correlationId.
Pairing may be required for some vehicle models or firmware versions.

## Capability Detection

The vehicle's RRS data includes capability information:
```json
{
  "shortCode": "RemoteStart",
  "longCode": "RemoteStart:ALL",
  "capabilityStatus": "AVAILABLE",
  "subscriptionStatus": "AVAILABLE",
  "privilege": ["RS:*:D"]
}
```

Check for `RemoteStart:ALL` with status `AVAILABLE` before registering the command.

## Error Reference

| Error                          | Cause                                           | Fix                                      |
|--------------------------------|-------------------------------------------------|------------------------------------------|
| `UNABLE_TO_PARSE_SECURED_RO_TOKEN` | Passed carnetVehicleToken as roToken       | Use roToken from climateControl/check     |
| `USER_NOT_AUTHORIZED` (403)    | Used OAuth token as Bearer for RST endpoint     | Use carnetVehicleToken as Bearer          |
| `SPIN_CHALLENGE_NOT_FOUND` (404) | Reused a consumed challenge                   | Fetch two separate challenges             |
| `500` on check endpoint       | Used `pinHash` field name                        | Use `spinHash` field name                 |

## Similarity to EU Auxiliary Heater

The EU version of the VW API has an "auxiliary heater" feature that is functionally
similar to remote start for ICE vehicles. It likely uses the same or similar
`climateControl/check` → roToken flow. The RST endpoint paths may differ but the
authentication pattern (two-challenge, ATC session, roToken) should be applicable.
See: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/issues/XXX
