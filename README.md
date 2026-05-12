# FIDOBridge

An Android app that turns your phone into an **NFC FIDO2 security key** using Host Card Emulation (HCE).

When an NFC reader requests a FIDO2 authentication or registration, FIDOBridge intercepts the CTAP2 commands and delegates them to Android's [CredentialManager API](https://developer.android.com/identity/sign-in/credential-manager), which in turn uses your system password manager (e.g. Bitwarden) to handle passkeys.

## How it works

1. **Tap your phone** on an NFC reader that requests FIDO2 authentication
2. FIDOBridge receives the CTAP2 command via NFC
3. Your password manager prompts you to select or create a passkey
4. The response is sent back to the NFC reader

This effectively lets you use your phone's password manager as an NFC security key — no dedicated hardware token needed.

## Supported CTAP2 commands

| Command | Description |
|---|---|
| `GetInfo` | Returns authenticator capabilities |
| `MakeCredential` | Creates a new passkey (delegates to CredentialManager) |
| `GetAssertion` | Signs an authentication challenge (delegates to CredentialManager) |

## Setup

### Requirements

- Android 14+ (API 34)
- A password manager that supports passkeys **and** allows manually trusting third-party apps as privileged callers (e.g. Bitwarden)
- NFC enabled on your phone

### Installation

Download the latest APK from the [Releases](https://github.com/cifred98/FIDOBridge/releases) page, or build from source:

```bash
./gradlew assembleDebug
```

The APK will be at `app/build/outputs/apk/debug/app-debug.apk`.

### First use

1. Install FIDOBridge and open it once (no configuration needed)
2. Make sure NFC is enabled on your phone
3. Tap your phone on an NFC reader that requests FIDO2

The app runs entirely in the background via NFC HCE — you don't need to open it before tapping.

## Example: Bitwarden

### Registering a passkey

1. On a computer or another device, go to a website that supports passkeys (e.g. a Bitwarden vault, GitHub, Google)
2. Start the "Add security key" flow and choose NFC
3. Tap your phone on the NFC reader
4. Bitwarden will prompt you to save the passkey — confirm and follow the prompts
5. The passkey is now stored in your Bitwarden vault

### Authenticating

1. On the website, start the sign-in flow with a security key
2. Tap your phone on the NFC reader
3. Bitwarden will prompt you to select the passkey — confirm with biometrics
4. You're signed in

### Trusting the app origin

FIDOBridge uses `setOrigin()` to pass the relying party's domain to CredentialManager. Since FIDOBridge is not in the system's trusted browser allowlist, your password manager will show a warning that the app is **not a trusted caller**.

Your password manager **must** support manually trusting third-party apps as privileged callers.
**In Bitwarden**:
1. On the first authentication, a warning will appear about an untrusted app
2. Choose to **trust this app**
3. Subsequent authentications will work without the warning

## NFC reader compatibility

> [!NOTE]
> **Android phones as NFC readers**: Android only recently added support for reading FIDO2 security keys over NFC. If the phone acting as the **reader** (not the phone running FIDOBridge) does not support this, you will need to install [AuthNKey](https://f-droid.org/it/packages/pl.lebihan.authnkey/) on the reader phone to enable FIDO2 NFC reader functionality.
>
> This is **only needed on the reader side**. The phone running FIDOBridge does not need any additional apps.
>
> **iPhones** acting as NFC readers should work without any additional setup.

## Debug logging

In debug builds, FIDOBridge shows an APDU debug log in the main activity with:
- Raw APDU hex data
- Decoded CTAP2 commands and CBOR payloads
- Response status codes and data

This is also output to Logcat under the `APDU-DEBUG` tag.

## Architecture

```
NFC Reader
    │
    ▼ (ISO 7816 APDUs)
FidoNfcService (HCE)
    │
    ▼ (CTAP2 commands)
Ctap2CommandRouter
    │
    ├── GetInfo → Ctap2Authenticator (immediate response)
    │
    └── MakeCredential / GetAssertion
            │
            ▼
        CredentialBridgeActivity
            │
            ▼ (WebAuthn JSON)
        Android CredentialManager
            │
            ▼
        Password Manager (Bitwarden, etc.)
```

## License

This project is provided as-is for educational and personal use.
