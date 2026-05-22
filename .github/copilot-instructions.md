# Copilot Instructions — FIDOBridge

## Project Overview

FIDOBridge is an Android app that emulates an NFC FIDO2 security key using Host-based Card Emulation (HCE). It bridges NFC CTAP2 requests to the Android Credential Manager / WebAuthn API, delegating credential creation and assertion to the system password manager.

**Data flow:** NFC Reader → `FidoNfcService` (APDU framing) → `Ctap2CommandRouter` (CBOR decode/dispatch) → WebAuthn/Credential Manager API → system password manager → CTAP2 CBOR response → APDU response → NFC Reader.

## Reference Implementation

A working FIDO2 NFC authenticator exists in the sibling directory `android-fido-authenticator` (relative to this project's parent). It implements CTAP2 over NFC with its own key management and credential store. FIDOBridge reuses the same NFC/APDU/CTAP2 framing patterns but replaces the crypto/credential layer with Android's Credential Manager API.

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
- **CBOR:** Custom implementation (no external library) — `CborValue` interface hierarchy with `writeAsCbor()` / `fromCborToEnd()`
- **Crypto:** BouncyCastle (`bcpkix-jdk18on`) for attestation certificate generation

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
   - `FidoNfcService : HostApduService` — receives raw APDUs from NFC, manages async lifecycle
   - `ApduRequest` / `ApduResponse` (in `transport/apdu/`) — parse/encode ISO 7816-4 APDUs with status words
   - AID selection: responds to `SELECT` for `A0000006472F0001` with FIDO version string
   - Routes `CLA=0x80 INS=0x10` APDUs to `Ctap2CommandRouter`
   - For async commands, returns `null` from `processCommandApdu()` and calls `sendResponseApdu()` when complete
   - Pre-checks GetAssertion credentials via `CredentialManager.prepareGetCredential()` before launching UI
   - **caBLE scaffold** (`transport/cable/`):
     - `CableTransportService` — singleton managing caBLE session lifecycle (QR → BLE → tunnel → CTAP2)
     - `CableSession` — state machine for a single caBLE connection (IDLE → ADVERTISING → ACTIVE → CLOSED)
     - `CableQrCode` — parsed representation of the FIDO2 caBLE QR code (peer public key + secret)
     - `CableConstants` — protocol constants (BLE UUID, tunnel domain, QR CBOR keys, Noise protocol)

2. **Protocol layer** (`protocol/`)
   - `Ctap2CommandRouter` — dispatches CTAP2 command bytes to handlers, returns `CtapResult` (sealed class: `Immediate` or `Async`)
   - `Ctap2Authenticator` — Kotlin `object` implementing `handleGetInfo()` (synchronous response)
   - `Ctap2Constants.kt` — `Ctap2Command` enum, `Ctap2StatusCode` enum, COSE constants, parameter enums (`MakeCredentialParam`, `GetAssertionParam`, etc.)
   - `CtapResult` — sealed class representing sync (`Immediate`) vs async (`Async`) command results
   - `AuthDataParser` — parses raw authenticatorData bytes into structured `ParsedAuthData` (rpIdHash, flags, signCount, attestedCredData)

3. **CBOR layer** (`protocol/cbor/`)
   - `CborEncoding.kt` — `CborValue` interface + implementations (`CborLong`, `CborByteString`, `CborTextString`, `CborArray`, `CborLongMap`, `CborTextStringMap`, `CborBoolean`, etc.). Uses `CborBoxedValue<T>` for typed value extraction.
   - `CborDecoding.kt` — `fromCborToEnd()` parser
   - `CborConstants.kt` — CBOR major type constants
   - `CborHelpers.kt` — navigation/extraction helpers (`unbox<T>()`, `getRequired()`, `toCtap2SuccessResponse()`)

4. **WebAuthn Bridge layer** (`bridge/`)
   - `WebAuthnBridge` — converts CTAP2 CBOR params to WebAuthn JSON requests and parses responses back to CTAP2 CBOR
   - `CredentialBridgeActivity` — transparent activity that calls `CredentialManager.createCredential()` / `getCredential()` with `setOrigin("https://{rpId}")` and passes `clientDataHash` directly
   - `PendingCredentialOperation` — data class holding request state + `CompletableDeferred<ByteArray>` for async communication between NFC service and activity

5. **Crypto layer** (`crypto/`)
   - `AttestationKey` — manages batch attestation key pair and X.509 certificate chain (self-signed CA + leaf with FIDO AAGUID extension). Keys persisted to app-private files.

6. **Settings layer** (`settings/`)
   - `AppSettings` — singleton managing SharedPreferences with reactive `StateFlow` for Compose UI (AAGUID, certificate subject/issuer/expiry, advertised transports)
   - `RpIdOverrideRepository` — manages per-RP ID origin overrides

7. **Application** (`FidoBridgeApplication`)
   - Initializes `AttestationKey` and `Ctap2CommandRouter` in `onCreate()`
   - Manages single-flight `PendingCredentialOperation` with `@Synchronized` accessors
   - No DI framework (Hilt/Dagger) — manual wiring via companion object statics

### Async NFC Flow

For MakeCredential and GetAssertion (which require user interaction):
1. `processCommandApdu()` returns `null` (async indicator)
2. `PendingCredentialOperation` is stored in `FidoBridgeApplication`
3. `CredentialBridgeActivity` is launched with `FLAG_ACTIVITY_NEW_TASK`
4. Activity calls CredentialManager, user interacts with passkey UI
5. Activity completes the `CompletableDeferred` with CTAP2 response bytes
6. NFC service coroutine calls `sendResponseApdu()`
7. `onDeactivated()` cancels any pending operation if NFC link drops
8. While async is in-flight, duplicate commands from the reader are absorbed (returns `null`)

### Key Protocol Details

- **FIDO CTAP NFC AID:** `A0000006472F0001`
- **CTAP2 response framing:** status byte (`0x00` = success) followed by CBOR payload
- **authenticatorData format:** `rpIdHash (32B) + flags (1B) + signCount (4B, big-endian) [+ attestedCredentialData]`
- **attestedCredentialData:** `aaguid (16B) + credentialIdLength (2B, big-endian) + credentialId + COSE public key (CBOR)`
- **Supported algorithm:** ES256 only (COSE algorithm ID `-7`)
- **CBOR map key ordering:** maps are sorted by encoded key bytes before serialization (per CTAP2 canonical CBOR)
- **setOrigin permission:** `android.permission.CREDENTIAL_MANAGER_SET_ORIGIN` (signature-level) — requires platform signing or privileged allowlist

## Conventions

- Package: `com.puntokek.fidobridge`
- Dependencies managed via version catalog at `gradle/libs.versions.toml` — add new deps there, not as inline version strings
- Java 11 source/target compatibility
- Release builds use ProGuard minification + resource shrinking (`isMinifyEnabled = true`, `isShrinkResources = true`)
- Manual dependency injection via `FidoBridgeApplication` companion object — no Hilt/Dagger
- HCE service declared in `AndroidManifest.xml` with `android.permission.BIND_NFC_SERVICE` and AID filter XML resource
- Use `FIDOBridgeTheme` as the root Compose wrapper
- Compose-first UI — no XML layouts
- Utility extensions in `util/Extensions.kt`: `ByteArray.sha256()`, `.base64url()`, `.toHex()`, `UInt.bytes()`, etc.
- CTAP2 errors thrown via `ctap2Error(status, message)` helper — caught and converted to error responses in `Ctap2CommandRouter`
- `@OptIn(ExperimentalUnsignedTypes::class)` used throughout protocol/CBOR code for `UByte`/`UByteArray`

## Debug Logging

APDU debug logging is gated behind `BuildConfig.DEBUG` and must remain disabled in production.

- **Logcat tag:** `APDU-DEBUG`
- **UI:** scrollable debug log panel via `DebugLog` singleton (`StateFlow<List<LogEntry>>`) rendered in a `LazyColumn`
- Every APDU exchange is logged with raw hex + parsed ISO 7816-4 fields + decoded CTAP2 content
- `DebugLog.logRequest()` / `DebugLog.logResponse()` called from `FidoNfcService`
