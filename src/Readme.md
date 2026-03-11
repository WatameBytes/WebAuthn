# WebAuthn Attestation Demo

Quick setup to capture `attestation_format`, `attestation_statement`, AAGUID,
and all attestation fields using Yubico's `webauthn-server-core` with
`AttestationConveyancePreference.DIRECT` and `allowUntrustedAttestation(true)`.

## Run

```bash
mvn spring-boot:run
```

---

## Endpoints

### 1. Create User
```
POST /users
{ "username": "rex" }
```

### 2. Register — Start
```
POST /register/start
{ "username": "rex" }
```
Returns `sessionId` + `publicKey` (PublicKeyCredentialCreationOptions).
Pass `publicKey` to `navigator.credentials.create()`.

### 3. Register — Finish ← Attestation is captured here
```
POST /register/finish
{
  "sessionId": "<from start>",
  "credential": <PublicKeyCredential from navigator.credentials.create()>
}
```
On success, attestation info is written to `attestation-dump.json` in the working directory.

### 4. Authenticate — Start (USERNAMELESS)
```
POST /authenticate/start
{}
```
No username. `allowCredentials` will be empty → authenticator uses a discoverable/resident credential.
Returns `sessionId` + `publicKey` (PublicKeyCredentialRequestOptions).

### 5. Authenticate — Finish
```
POST /authenticate/finish
{
  "sessionId": "<from start>",
  "credential": <PublicKeyCredential from navigator.credentials.get()>
}
```

---

## Attestation dump file

After every successful registration, a line is appended to `attestation-dump.json`:

```json
{
  "timestamp": "2026-03-10T12:00:00Z",
  "username": "rex",
  "credentialId": "base64url...",
  "attestationFormat": "packed",
  "attestationStatement": {
    "alg": -7,
    "sig": "base64url...",
    "x5c": ["<leaf cert>", "<intermediate>"]
  },
  "aaguid": "2fc0579f-8113-47ea-b116-bb5a8db9202a",
  "authenticatorDataFlags": {
    "userPresent": true,
    "userVerified": true,
    "attestedDataIncluded": true,
    "extensionsIncluded": false
  },
  "signCount": 0,
  "attestedCredentialData": {
    "aaguid": "2fc0579f-8113-47ea-b116-bb5a8db9202a",
    "credentialId": "base64url...",
    "publicKeyCose": "base64url..."
  },
  "clientData": {
    "type": "webauthn.create",
    "origin": "http://localhost:8080",
    "challenge": "base64url..."
  }
}
```

---

## Attestation formats you'll see from a YubiKey

| Format       | What's in attStmt                                     |
|--------------|-------------------------------------------------------|
| `packed`     | `alg`, `sig`, optionally `x5c` (cert chain)           |
| `fido-u2f`   | `sig`, `x5c` — older U2F-style attestation            |
| `tpm`        | `ver`, `alg`, `sig`, `x5c`, `certInfo`, `pubArea`     |
| `none`       | Empty `{}` — authenticator opted out                  |
| `android-key`| `alg`, `sig`, `x5c`                                   |

With `DIRECT` + `allowUntrustedAttestation(true)`, all of the above will pass
`finishRegistration()` regardless of whether the AAGUID is in a trusted metadata store.

---

## Does attestation appear in authentication?

**No.** The `AuthenticatorAssertionResponse` contains:
- `authenticatorData` — flags, sign count, rpIdHash
- `clientDataJSON`
- `signature`
- `userHandle` (for usernameless resolution)

There is no `attestationObject`, no `fmt`, no `attStmt` in authentication.
Attestation is a registration-only concept — it answers "what authenticator made this key",
not "prove you have the key".

---

## Quick browser test snippet

```javascript
// Register
const startRes = await fetch('/register/start', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'rex' })
}).then(r => r.json());

// Convert challenge from base64url
const options = startRes.publicKey;
options.challenge = base64urlToBuffer(options.challenge);
options.user.id = base64urlToBuffer(options.user.id);

const credential = await navigator.credentials.create({ publicKey: options });

// Serialize and finish
await fetch('/register/finish', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    sessionId: startRes.sessionId,
    credential: credentialToJson(credential)  // serialize ArrayBuffers to base64url
  })
});
```