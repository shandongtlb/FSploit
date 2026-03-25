# FSploit MITM Research Notes

Scope: authorized testing on devices you own or explicitly control. This note is about product direction and technical feasibility, not deployment guidance.

## Bottom Line

If FSploit is allowed to require root, the most realistic first-generation MITM design is:

1. root-managed transparent traffic redirection
2. an embedded local interception backend
3. optional TLS interception only for cooperative or lab-controlled targets

The key constraint is not packet redirection. The hard part is trust:

- Android 7.0+ apps do not automatically trust user-added CAs
- apps can pin certificates
- some traffic may use transports that do not map cleanly to a classic HTTP proxy workflow

That means:

- root makes network redirection feasible
- root does not automatically make HTTPS decryption universal

## What The Android Platform Docs Mean For Us

### 1. `VpnService` is real, but not the best primary path if root is already accepted

Official Android docs describe `VpnService` as creating a virtual interface and letting the app read outgoing IP packets and write injected incoming packets. They also note:

- user consent is required before establishing the VPN
- only one VPN can run at a time
- the system shows a managed VPN notification

Implication for FSploit:

- `VpnService` is useful as a non-root fallback later
- if we already accept root, a root transparent mode is operationally simpler for a MITM-focused tool
- `VpnService` should not be the primary design if the product goal is a root laboratory toolkit

### 2. User-installed CAs are not enough for arbitrary third-party apps

Android documentation for Network Security Config and Android 7.0 states that apps targeting API 24+ that want to trust user-added CAs must opt into that behavior.

Implication for FSploit:

- importing a CA into the user certificate store will not make modern apps universally interceptable
- a rooted device may let us place a CA deeper in the system trust path, but that still does not solve certificate pinning
- any design promise like "root MITM works for all apps" would be technically false

### 3. Certificate pinning remains a hard stop for generic HTTPS interception

Android security documentation explicitly discusses certificate pinning and unsafe trust managers in the context of MITM risk.

Implication for FSploit:

- cooperative apps and lab endpoints can be intercepted
- many production apps will still reject the intercepted certificate chain
- pinning bypass should not be a first-phase product goal

## Product Direction

FSploit should treat MITM as three distinct capabilities, not one:

### A. Traffic redirection

Goal:

- route selected app or device traffic into a local interception backend

Why this is feasible with root:

- root can manage low-level network policy
- root can supervise local binaries and long-running services

### B. Session visibility without TLS break

Goal:

- observe destination metadata
- identify flows
- record SNI, addresses, ports, timing, protocol hints, and DNS behavior where available

Why this matters:

- this mode still works when full HTTPS interception is impossible
- it gives immediate value without overpromising decryption

### C. Full HTTPS interception for cooperative targets

Goal:

- decrypt and inspect HTTP/TLS for explicitly controlled test targets

Expected constraints:

- trust-anchor acceptance
- certificate pinning
- transport behavior outside classic HTTP proxy flows

## Recommended FSploit Architecture

Inference from the platform constraints above:

### 1. `MitmCoordinator`

Owns the session lifecycle:

- start session
- stop session
- choose mode
- collect status

### 2. `RootCommandExecutor`

Build on the existing shell layer:

- execute root commands
- validate environment
- report failures clearly

This should be separate from UI and from MITM backend logic.

### 3. `TrafficRedirectManager`

Owns redirection policy:

- enable redirect
- disable redirect
- isolate affected scope
- restore state on crash or reboot

This layer should be abstract. FSploit should not couple the app directly to one redirection mechanism.

### 4. `MitmBackend`

An abstraction over the actual interception engine.

Options later:

- embedded HTTP/TLS interception binary
- external helper process
- protocol-limited first-party engine

For the first version, embedding an established backend is lower risk than writing a TLS interception engine from scratch.

### 5. `CaAuthorityManager`

Owns:

- CA generation
- CA storage
- install-state diagnostics
- trust validation checks

This component should report what is true on the device, not assume success.

### 6. `MitmSessionStore`

Persist:

- current session state
- selected target scope
- backend status
- logs
- failure reasons

### 7. UI Modules

Recommended drawer entries:

- `MITM`
- `Sessions`
- `Certificates`
- `Tools`

The first MITM screen should be diagnostic, not "start attack".

## What The First MITM Release Should Actually Do

Phase 1 should be conservative and honest:

### Phase 1

- root diagnostics
- backend availability diagnostics
- CA status diagnostics
- traffic redirection dry-run
- metadata-only flow capture

Success means:

- FSploit can prove root
- prove backend launch
- prove local redirect control
- show session lifecycle and recovery

### Phase 2

- selective interception for cooperative hosts
- visible certificate status
- decrypted HTTP request/response view where trust conditions permit

### Phase 3

- app scoping
- session export
- richer protocol parsing

## What We Should Not Promise

FSploit should not position the first MITM module as:

- universal HTTPS interception on modern Android
- guaranteed support for all third-party apps
- automatic defeat of certificate pinning

That would be technically weak and would turn into constant bug reports that are actually platform constraints.

## Recommended Immediate Next Step

Start with a `MITM Readiness` implementation, not packet modification.

That means building:

1. a new `MITM` drawer module
2. root/backend/CA diagnostics
3. a session state model
4. a backend abstraction

Only after that should we wire actual traffic redirection.

## Sources

- Android `VpnService` reference: https://developer.android.com/reference/android/net/VpnService
- Android VPN guide: https://developer.android.com/develop/connectivity/vpn
- Android 7.0 network security changes: https://developer.android.com/about/versions/nougat/android-7.0
- Android Network Security Configuration: https://developer.android.com/training/articles/security-config
- Android security guidance on unsafe trust managers: https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager
- Android TLS/security guidance: https://developer.android.com/privacy-and-security/security-ssl
