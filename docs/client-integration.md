# Cygnus SDK and client integration

This crate is the protocol core. It should provide deterministic identity,
certificate, and event operations that SDKs can call; it should not reimplement
each SDK's Matrix client, room timeline, or UI.

## Repository inventory

The sibling checkouts use different layers:

| Project           | Existing integration layer                                                                                                                                                                                              | Cygnus work needed                                                                                                                                      |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `matrix-js-sdk`   | Room-version strings and Matrix event/client APIs. Unknown room versions currently receive the room-v12/Hydra creator behavior; there is no Cygnus link, certificate, or event-signing support.                         | Add Cygnus-aware event construction and verification through a wasm binding; gate room creation and flows on advertised server support.                 |
| `matrix-rust-sdk` | `matrix-sdk-base` uses Ruma room-version rules; `matrix-sdk-crypto` exposes `vodozemac`; Android uses the Rust SDK's UniFFI surface.                                                                                    | Add explicit Cygnus handling to the SDK and Ruma rules; expose the Cygnus core through its FFI without making ordinary room-v12 rooms use Cygnus rules. |
| `ruma`            | Typed Matrix IDs/events, room-version rules, canonical JSON/redaction, and event-auth support. `RoomVersionId` accepts custom strings, but custom versions have no rules. No Cygnus-specific types or rules were found. | Add Cygnus event/content types and an explicit Cygnus room-version rules variant, with proposal vectors as conformance tests.                           |
| Cinny             | Uses `matrix-js-sdk` 41.5.0.                                                                                                                                                                                            | Cygnus support should arrive through the SDK; add UI for identity and device status after the SDK exposes it.                                           |
| Element Web       | Uses the Matrix JS SDK stack.                                                                                                                                                                                           | Same JS SDK boundary; add account/device and room-creation UI after protocol support exists.                                                            |
| Element X Android | Uses the Matrix Rust SDK Android package (`org.matrix.rustcomponents:sdk-android`) backed by UniFFI.                                                                                                                    | Add Rust SDK APIs and bindings, then device/identity and room-version UI.                                                                               |
| FluffyChat        | Uses the Dart `matrix` SDK (`^10.0.1`).                                                                                                                                                                                 | Add Cygnus to that SDK or provide a Dart FFI binding; then account/device and room-creation UI.                                                         |

The requested `matrix-sdk-rust` path is named `matrix-rust-sdk` in this
workspace. The six sibling projects were inspected read-only; this plan does
not modify them.

## Protocol APIs the core must expose

For all four client stacks to implement the same wire behavior, Cygnus needs a
small stable API with shared JSON fixtures:

1. **Principal and link operations**: parse/render identifiers, build genesis
   links, validate successor chains, report height and active signing keys.
2. **Certificate operations**: create and verify master → self-signing → device
   certificates, with stable error categories and strict version/encoding
   checks.
3. **Event envelope operations**: room-v12/Cygnus redaction, canonical bytes,
   content/reference hashes, signing-object construction, device/custodian
   signatures, and PDU verification. This is the next protocol gate after the
   current link and certificate modules.
4. **Epoch and bundle operations**: parse and verify epoch/burn events, resolve
   link tips and authorization state, and validate supplied link bundles.
5. **Client flow data**: bootstrap link construction (fresh rotation key,
   commitment C₀, user/server genesis and successors) is in `bootstrap`;
   higher-level typed flows for device certification, revocation, custodian
   migration/rebinding, room creation/upgrade, and relay/ingress decisions
   remain. HTTP itself stays in each SDK.
6. **Bindings**: `wasm-bindgen` for the JS SDK, UniFFI for Element X, and a Dart
   bridge or Dart SDK integration for FluffyChat. Keep these as thin wrappers
   over the same Rust behavior.

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

The crate implements principal IDs, link encoding/verification and bootstrap
(rotation keys, commitments, genesis/successor builders), device-certificate
verification, the event envelope (redaction, hashes, event IDs, device and
custodian signatures), epoch/burn/tip-bundle verification, Pass 0 resolution,
and the Cygnus authorization overlay. It does not yet provide certificate
creation, private-key storage/backup, state resolution, HTTP-flow, SDK
binding, or client UI APIs above. Keeping this gap explicit prevents an SDK
from treating ordinary room-v12 behavior as full Cygnus support.
