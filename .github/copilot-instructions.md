# Copilot Instructions — FIDOBridge

## Project Overview

FIDOBridge is an Android app that emulates an NFC FIDO2 security key using Host-based Card Emulation (HCE). It bridges NFC CTAP2 requests to the Android Credential Manager / WebAuthn API, delegating credential creation and assertion to the system password manager.

**Data flow:** NFC Reader → `HostApduService` (APDU framing) → CTAP2 command dispatcher (CBOR decode) → WebAuthn/Credential Manager API → system password manager → CTAP2 CBOR response → APDU response → NFC Reader.

The project name in code is `FIDOBridge`.

## Reference Implementation

A working FIDO2 NFC authenticator lives at `/home/cifred/AndroidStudioProjects/android-fido-authenticator`. It implements CTAP2 over NFC with its own key management and credential store. FIDOBridge reuses the same NFC/APDU/CTAP2 framing patterns but replaces the crypto/credential layer with Android's Credential Manager API.

### What to reuse from the reference project
- **NFC HCE service pattern** — `HostApduService` subclass, AID filter XML (`A0000006472F0001`), APDU request/response parsing
- **CTAP2 command routing** — command byte dispatch (`0x01` MakeCredential, `0x02` GetAssertion, `0x04` GetInfo), `SELECT AID` handling returning `"U2F_V2"`
- **CBOR encoding/decoding** — custom CBOR implementation (CborValue hierarchy, CborLongMap/CborTextStringMap, typed encoding/decoding), CTAP2 message constants
- **Response framing** — `toCtapSuccessResponse()` (leading `0x00` + CBOR), `CtapErrorException` for error responses
- **authenticatorData construction** — rpIdHash + flags + signCount + attestedCredentialData format

### What NOT to reuse (replaced by Credential Manager)
- `KeyManager` / `RamKeyManager` — FIDOBridge does not generate or store keys directly
- `CredentialStore` — credentials live in the system password manager
- `Certificate` / attestation signing — attestation comes from the WebAuthn API response
- Direct `Signature.getInstance("SHA256withECDSA")` calls — signing happens in the password manager

## Tech Stack

- **Language:** Kotlin
- **UI:** Jetpack Compose with Material 3
- **Min SDK:** 34 (Android 14) — modern APIs only, no legacy compat needed
- **Target/Compile SDK:** 36
- **Build:** Gradle with Kotlin DSL, version catalog (`gradle/libs.versions.toml`)
- **CBOR:** Custom implementation (no external library) — `CborValue` sealed hierarchy with `writeAsCbor()` / `fromCborToEnd()`

## Build & Test Commands

```bash
# Build
./gradlew assembleDebug

# Run all unit tests
./gradlew test

# Run a single unit test class
./gradlew testDebugUnitTest --tests "com.puntokek.fidobridge.ExampleUnitTest"

# Run instrumented tests (requires emulator/device)
./gradlew connectedAndroidTest

# Lint
./gradlew lint
```

## Architecture

### Layers

1. **Transport layer** (`transport/`)
   - `FidoNfcService : HostApduService` — receives raw APDUs from NFC
   - `ApduRequest` / `ApduResponse` — parse/encode ISO 7816-4 APDUs with status words
   - AID selection: responds to `SELECT` for `A0000006472F0001` with `"U2F_V2"`
   - Routes `CLA=0x80 INS=0x10` APDUs to CTAP2 dispatcher; `CLA=0x00` to CTAP1/U2F
   - For async commands (MakeCredential/GetAssertion), returns `null` from `processCommandApdu()` and calls `sendResponseApdu()` when the CredentialManager operation completes

2. **Protocol layer** (`protocol/`)
   - `CTAPAuthenticator` — top-level dispatcher, routes CTAP2 command bytes to handlers
   - `Authenticator` companion object — implements `handleGetInfo()`, `handleMakeCredential()`, `handleGetAssertion()`
   - CTAP2 commands: `0x01` MakeCredential, `0x02` GetAssertion, `0x04` GetInfo

3. **CBOR layer** (`protocol/cbor/`)
   - `CborEncoding.kt` — `CborValue` type hierarchy (`CborLong`, `CborByteString`, `CborTextString`, `CborArray`, `CborLongMap`, `CborTextStringMap`, etc.)
   - `CborDecoding.kt` — `fromCborToEnd()` parser
   - `CborConstants.kt` — CBOR major type constants
   - `Messages.kt` — CTAP2 field constants (`MAKE_CREDENTIAL_CLIENT_DATA_HASH = 0x1L`, etc.), `RequestCommand` enum, `CtapError` enum, COSE key templates, authenticator flags

4. **WebAuthn Bridge layer** (`bridge/`)
   - `WebAuthnBridge` — converts CTAP2 CBOR params to WebAuthn JSON requests and parses responses back to CTAP2 CBOR
   - `CredentialBridgeActivity` — transparent activity that calls `CredentialManager.createCredential()` / `getCredential()` with `setOrigin("https://{rpId}")` and passes `clientDataHash` directly so the credential provider signs over the correct hash
   - `PendingCredentialOperation` — data class holding request state + `CompletableDeferred<ByteArray>` for async communication between NFC service and activity
   - `FidoBridgeApplication` manages single-flight pending operations with cancellation

### Async NFC Flow

For MakeCredential and GetAssertion (which require user interaction):
1. `processCommandApdu()` returns `null` (async indicator)
2. `PendingCredentialOperation` is stored in `FidoBridgeApplication`
3. `CredentialBridgeActivity` is launched with `FLAG_ACTIVITY_NEW_TASK`
4. Activity calls CredentialManager, user interacts with passkey UI
5. Activity completes the `CompletableDeferred` with CTAP2 response bytes
6. NFC service coroutine calls `sendResponseApdu()`
7. `onDeactivated()` cancels any pending operation if NFC link drops

### setOrigin Permission

`setOrigin()` requires `android.permission.CREDENTIAL_MANAGER_SET_ORIGIN` (signature-level). The app must be signed with a platform key or have the permission granted through a privileged allowlist.

### Key Protocol Details

- **FIDO CTAP NFC AID:** `A0000006472F0001`
- **CTAP2 response framing:** status byte (`0x00` = success) followed by CBOR payload
- **authenticatorData format:** `rpIdHash (32B) + flags (1B) + signCount (4B, big-endian) [+ attestedCredentialData]`
- **attestedCredentialData:** `aaguid (16B) + credentialIdLength (2B, big-endian) + credentialId + COSE public key (CBOR)`
- **Supported algorithm:** ES256 only (COSE algorithm ID `-7`)
- **CBOR map key ordering:** maps are sorted by encoded key bytes before serialization (per CTAP2 canonical CBOR)

## Conventions

- Package: `com.puntokek.fidobridge`
- Dependencies managed via version catalog at `gradle/libs.versions.toml` — add new deps there, not as inline version strings
- Java 11 source/target compatibility
- Manual dependency injection via `Application` subclass (no Hilt/Dagger) — `FidoApplication` wires up the `CTAPAuthenticator` and passes it to the HCE service
- HCE service must be declared in `AndroidManifest.xml` with `android.permission.BIND_NFC_SERVICE` and the AID filter XML resource
- Use `FIDOBridgeTheme` as the root Compose wrapper
- Compose-first UI — no XML layouts

## Debug Logging

The app includes a comprehensive APDU debug logging system, gated behind `BuildConfig.DEBUG`, that must be disabled for production.

### What to log

Every APDU exchange must be logged at two levels:

1. **Raw APDU** — hex dump of the full byte array, plus parsed ISO 7816-4 fields: `CLA`, `INS`, `P1`, `P2`, `Lc`, `Data`, `Le` (request) or `Data`, `SW1`, `SW2` (response)
2. **Decoded payload** — when the APDU data contains CTAP2 content:
   - Command byte name (e.g. `GetInfo`, `MakeCredential`, `GetAssertion`)
   - CBOR-decoded request/response as a human-readable structure (key names resolved to their CTAP2 field names, byte arrays as hex/base64url)
   - For `SELECT AID`: the selected AID in hex

### Where logs go

- **Logcat** — tagged `APDU-DEBUG`, one structured log entry per APDU request and response
- **UI** — a scrollable debug log panel in the main Compose UI showing timestamped entries with raw + decoded info. Use a `StateFlow<List<LogEntry>>` in a shared `DebugLog` singleton so the HCE service and UI observe the same log stream
- Both destinations receive identical information

### Implementation pattern

```kotlin
// Gate all debug logging behind BuildConfig.DEBUG
if (BuildConfig.DEBUG) {
    DebugLog.logApdu(...)
}
```

- `DebugLog` singleton: thread-safe append to a `MutableStateFlow<List<LogEntry>>`, capped at a reasonable size (e.g. 200 entries)
- `LogEntry` data class: timestamp, direction (IN/OUT), raw hex, parsed fields, decoded CTAP2 content (nullable)
- The UI collects the flow and renders entries in a `LazyColumn`
