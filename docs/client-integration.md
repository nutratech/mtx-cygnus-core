# Cygnus SDK and client integration

This crate is the protocol core. It should provide deterministic identity,
certificate, and event operations that SDKs can call; it should not reimplement
each SDK's Matrix client, room timeline, or UI.

## Repository inventory

The sibling checkouts use different layers:

| Project           | Existing integration layer                                                                                                                                                                                                                                     | Cygnus work needed                                                                                                                              |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `matrix-js-sdk`   | Room-version strings and Matrix event/client APIs. The sibling SDK does not yet integrate Cygnus, but `cygnus-wasm` already exports link verification, bootstrap-response checks, device-certificate creation, event hashing/signing, and user-chain rotation. | Integrate the existing wasm exports; add Cygnus-aware event construction, verification and room flows, gated on advertised server support.      |
| `matrix-rust-sdk` | `matrix-sdk-base` uses Ruma room-version rules; `matrix-sdk-crypto` exposes `vodozemac`; Android uses the Rust SDK's UniFFI surface. The Cygnus Rust core exists, but no Cygnus UniFFI integration is present.                                                 | Add explicit Cygnus handling to the SDK and Ruma rules; expose the core through UniFFI without making ordinary room-v12 rooms use Cygnus rules. |
| `ruma`            | Typed Matrix IDs/events, room-version rules, canonical JSON/redaction, and event-auth support. `RoomVersionId` accepts custom strings, but custom versions have no rules. No Cygnus-specific types or rules were found.                                        | Add Cygnus event/content types and an explicit Cygnus room-version rules variant, with proposal vectors as conformance tests.                   |
| Cinny             | Uses `matrix-js-sdk` 41.5.0.                                                                                                                                                                                                                                   | Cygnus support should arrive through the SDK; add UI for identity and device status after the SDK exposes it.                                   |
| Element Web       | Uses the Matrix JS SDK stack.                                                                                                                                                                                                                                  | Same JS SDK boundary; add account/device and room-creation UI after protocol support exists.                                                    |
| Element X Android | Uses the Matrix Rust SDK Android package (`org.matrix.rustcomponents:sdk-android`) backed by UniFFI.                                                                                                                                                           | Add Rust SDK APIs and bindings, then device/identity and room-version UI.                                                                       |
| FluffyChat        | Uses the Dart `matrix` SDK (`^10.0.1`).                                                                                                                                                                                                                        | Add Cygnus to that SDK or provide a Dart FFI binding; then account/device and room-creation UI.                                                 |

The requested `matrix-sdk-rust` path is named `matrix-rust-sdk` in this
workspace. The six sibling projects were inspected read-only; this plan does
not modify them.

## Protocol APIs the core must expose

For all four client stacks to implement the same wire behavior, Cygnus needs a
small stable API with shared JSON fixtures:

1. **Principal and link operations**: the core parses/renders identifiers,
   builds genesis and successor links, and verifies chains. `cygnus-wasm`
   exposes principal parsing, chain verification, link parsing, bootstrap
   response checks and user-chain rotation; server-side genesis construction
   remains a Rust-core operation.
2. **Certificate operations**: the core creates and verifies master →
   self-signing → device certificates. `cygnus-wasm` exposes certificate
   creation and device-signature verification; SDKs still need to integrate
   those exports and handle certificate lifecycle flows.
3. **Event envelope operations**: the core provides room-v12/Cygnus redaction, canonical bytes,
   content/reference hashes, signing-object construction, and device/custodian
   signatures are in `envelope`. Verifying a PDU also needs `bundle` (epochs
   and link bundles), `auth` (authorization), and the caller's selected room
   state.
4. **Epoch and bundle operations**: parse and verify epoch/burn events, resolve
   link tips and authorization state, and validate supplied link bundles.
5. **Client flow data**: bootstrap link construction (fresh rotation key,
   commitment C₀, user/server genesis and successors) is in `bootstrap`;
   higher-level typed flows for device certification, revocation, custodian
   migration/rebinding, room creation/upgrade, and relay/ingress decisions
   remain. HTTP itself stays in each SDK.
6. **Bindings**: `cygnus-wasm` already provides the `wasm-bindgen` surface for
   the JS SDK. UniFFI for Element X and a Dart bridge or Dart SDK integration
   for FluffyChat remain. Keep these as thin wrappers over the same Rust
   behavior.

## Required cross-SDK tests

- Run Appendix A/B/C models and vectors from `../proposals` in CI; preserve
  `KNOWN` gaps as expected outcomes and keep `SPEC` rows out of normative
  acceptance criteria.
- Test the same valid and invalid link, certificate, envelope, epoch, and burn
  fixtures through Rust, wasm, UniFFI, and Dart-facing APIs.
- Include canonical JSON cases for key ordering, escaping, duplicate keys,
  floats, `-0`, exponent notation, and the ±(2^53−1) integer boundary.
- Exercise client flow cases: initial account/device setup, device addition,
  device revocation, user migration between custodians, stale room state,
  unsupported server capability, and rooms that remain ordinary room v12.
- DMLS and `m.room.device_root` stay a separate experimental milestone until
  Open Problem 3 is specified; their prototype tests are retained as research
  oracles, not Cygnus conformance tests.

## Current coverage

The core crate implements principal IDs, link encoding/verification and
bootstrap (caller-CSPRNG rotation keys, commitments, genesis/successor
builders), device-certificate creation via `DeviceCertificate::issue` and
verification, the event envelope (redaction,
hashes, event IDs, device and custodian signatures), epoch/burn/seal/tip-bundle
verification, Pass 0 resolution, and the Cygnus authorization overlay. With
`state-res`, it can run Rezzy's Matrix v12 base authorization on
caller-selected state; state selection and resolution remain the caller's
responsibility.

The `cygnus-wasm` crate exposes principal parsing, link and chain inspection,
bootstrap-response verification, device-certificate creation via
`createDeviceCertificate`, event hashing,
device/custodian signature verification, event signing, and user-chain
rotation. These are usable wasm-bindgen exports, not integrations in
`matrix-js-sdk` or another client SDK. The exports still require the caller to
supply and store seeds; they do not provide private-key storage/backup, HTTP
flows, or client UI. UniFFI and Dart bindings remain planned. The bootstrap API
never derives identity material from Olm or Megolm keys; secret storage and
recovery remain client responsibilities. Ordinary room-v12 behavior remains
separate from full Cygnus support.
