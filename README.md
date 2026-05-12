# identity-attributes

A small Motoko library for consuming **Internet Identity certified attribute
bundles** (verified email, name, OpenID provider attributes) from a
relying-party (RP) canister.

Pairs with `@icp-sdk/auth` v7+ on the frontend (the `AttributesIdentity` /
`requestAttributes` flow). Both halves of the contract — encoding on the FE,
decoding on the BE — are versioned together so an Internet Identity bundle
format change is a coordinated lib bump rather than a per-project rewrite.

## What it does

Internet Identity's `AttributesIdentity` flow delivers a Candid-encoded,
ICRC-3-shaped attribute bundle alongside each ingress call. Every RP canister
otherwise has to reinvent five things:

1. Candid-decode the bundle into an ICRC-3 `Value` tree.
2. Look up attribute keys, including OpenID-scoped variants like
   `openid:https://accounts.google.com:verified_email`.
3. Validate the three `implicit:*` fields the bundle carries —
   `origin`, `issued_at_timestamp_ns`, `nonce`.
4. Mint and verify single-use, action-bound nonces.
5. Surface a typed view that doesn't confuse `email` with `verified_email`
   (the former is whatever the user typed into II; only the latter is
   provider-verified).

`verify` does all five in one call.

The signer check (the bundle was signed by Internet Identity, not some other
canister) is handled by `mo:core/CallerAttributes` via the canister's
`trusted_attribute_signers` environment variable, set in `icp.yaml`.

## Install

```toml
# mops.toml
[dependencies]
identity-attributes = "0.2.0"
core                = "2.5.0"
```

In `icp.yaml`, list the Internet Identity backend principal as a trusted
signer:

```yaml
canisters:
  - name: backend
    settings:
      environment_variables:
        # Mainnet II backend. Add your local II principal too if your
        # tests run against a locally deployed II.
        trusted_attribute_signers: "rdmx6-jaaaa-aaaaa-aaadq-cai"
```

Without this, `verify` traps with `"trusted_attribute_signers environment
variable is not set"` — the right behaviour: an unconfigured canister
should not trust attribute bundles.

## Quick start

A two-call flow (`begin` issues a nonce; `finish` verifies the bundle):

```motoko
import II         "mo:identity-attributes";
import Challenges "mo:identity-attributes/Challenges";
import Principal  "mo:core/Principal";
import Runtime    "mo:core/Runtime";

persistent actor {
  stable var nonces = Challenges.empty();

  // 1. Frontend calls this on an anonymous agent (before II sign-in) to
  //    get a canister-issued nonce for the registration flow.
  public shared func registerBegin() : async Blob {
    await Challenges.issue<system>(nonces, "registerEmail")
  };

  // 2. After II sign-in + requestAttributes, the frontend calls this on
  //    an AttributesIdentity-wrapped (authenticated) agent. `verify`
  //    enforces signer (via mo:core), origin allow-list, freshness,
  //    nonce match (action-bound), and returns a typed Verified view.
  public shared ({ caller }) func registerFinish() : async Text {
    if (Principal.isAnonymous(caller)) Runtime.trap("anonymous caller");

    let result = switch (II.verify<system>({
      origins        = ["https://your-app.icp0.io"];
      maxAgeNs       = null;          // null = 5 min default
      nonces;
      action         = "registerEmail";
      openIdProvider = ?#Google;       // FE used scopedKeys({ openIdProvider: 'google' })
    })) {
      case (#ok r)  r;
      case (#err e) Runtime.trap("verify failed: " # debug_show e);
    };

    let ?email = result.email else Runtime.trap("email not provider-verified");
    "Registered " # Principal.toText(caller) # " with " # email
  };
};
```

For the passkey (non-OpenID) flow, set `openIdProvider = null`. The FE
calls `requestAttributes({ keys: ['name', 'email', 'verified_email'], nonce })`
without going through `scopedKeys`, and the BE reads unscoped attribute
keys.

## Verified

`verify` returns `Result.Result<Verified, Error>` on success. `Verified`:

```motoko
public type Verified = {
  name       : ?Text;     // user's name under the chosen scope
  email      : ?Text;     // sourced ONLY from verified_email (or scoped)
  attributes : Attributes;
};
```

`email` is `verified_email` only — the value the user's OpenID provider
asserted as verified. The unverified `email` (whatever the user typed
into Internet Identity, never checked) is reachable only via the explicit
escape hatch `result.attributes.getText("email")`. This forces a
deliberate "I'm using unverified input" choice at the call site; the
typed surface cannot be tricked into gating on an unverified address.

The `attributes` field is a class with the read-only methods
`getText`, `getNat`, `getBlob`, `has`. The underlying ICRC-3 representation
is not exposed.

## Concepts

### Action binding

Every nonce is tagged with an `action : Text` at issue and verify. A
nonce issued for `"registerEmail"` cannot be consumed against
`"linkAccount"` — flow confusion attacks fail at lookup. A typo on
either side produces `#UnknownNonce`, surfaced immediately on the first
test run.

### Origin allow-list

`Config.origins` is a non-empty list of frontend origins the bundle is
allowed to come from. The bundle's `implicit:origin` must equal one
exactly. List your production origin, staging origin, and canister-id
URL as appropriate — Internet Identity emits the canonical `.icp0.io`
form by default.

### Single-use nonces

`Challenges.issue` returns a fresh 32-byte nonce and stores it under
the given action. `verify` looks it up by `(action, bundle.nonce)` and
removes the entry on success. Replay → `#UnknownNonce`. Cross-flow
presentation → `#UnknownNonce`. Stale beyond `maxAgeNs` → `#NonceExpired`.

The store is bounded by a global FIFO cap of 4096 entries. Successful
consumes free their entries, so the steady-state size only reflects
abandoned-but-legitimate flows (users who got a nonce and walked away).
The cap doesn't replace cycle-cost-based DoS resistance — sustained
ingress costs the canister cycles, which is the real backpressure.

### OpenID providers

Match the frontend's `openIdProvider` argument 1:1:

```motoko
public type OpenIdProvider = {
  #Google;        // openid:https://accounts.google.com:
  #Apple;         // openid:https://appleid.apple.com:
  #Microsoft;     // openid:https://login.microsoftonline.com/{tid}/v2.0:
  #OpenId : Text; // custom provider URL — prefix becomes "openid:<url>:"
};
```

`null` (= passkey flow) reads unscoped keys. The Microsoft URL contains a
literal `{tid}` — Internet Identity emits it that way, do not substitute
a tenant ID into it.

For mixed-key bundles (the FE requested both scoped and unscoped keys),
re-scope the result:

```motoko
let google = II.asProvider(result.attributes, ?#Google);
let apple  = II.asProvider(result.attributes, ?#Apple);
```

### Single timing knob

`Config.maxAgeNs` (default 5 minutes) bounds both the bundle's
`implicit:issued_at_timestamp_ns` and the nonce's age in the store. The
developer sets one number; the lib applies it to both defence-in-depth
checks.

## API

| Module               | Surface                                                  |
|----------------------|----------------------------------------------------------|
| umbrella (`II`)      | `verify`, `asProvider`, `defaultMaxAgeNs`, type re-exports |
| `Verify`             | `verify<system>`, `Config`, `Error`                      |
| `Attributes`         | `Attributes` class, `Verified`, `OpenIdProvider`, `asProvider`, `fromValue` |
| `Challenges`         | `empty`, `issue<system>`, `consume`, `Store`, `maxTotal` |
| `Value` (internal)   | ICRC-3 `Value` type + `decode`                           |

### Error variants

```motoko
public type Error = {
  #NoAttributes;                                     // no bundle attached
  #MalformedCandid;                                  // bundle didn't decode
  #MissingField        : Text;                       // implicit field absent
  #OriginMismatch      : { expected : [Text]; got : Text };
  #Stale               : { ageNs : Nat };            // bundle's issued_at too old
  #UnknownNonce;                                     // nonce not in store for action
  #NonceExpired;                                     // nonce in store but stale
  #NoOriginsConfigured;                              // origins list was empty
};
```

## Compatibility

This is the second design generation of the library — paired with
Internet Identity's `AttributesIdentity` flow as it landed in
`@icp-sdk/auth` v7. The pairing matrix:

| `mo:identity-attributes` | `@icp-sdk/auth` | `@icp-sdk/core` | II bundle format |
|---|---|---|---|
| `^0.2`                   | `^7`            | `^5.3`          | v1 (ICRC-3 `Map`, three implicit fields) |

If Internet Identity changes the bundle format, both halves cut a
coordinated major — consumers update by bumping both sides, not by
rewriting decode/check code.

## Demos

- [`demos/bagel/`](demos/bagel/) — pair-for-coffee canister gated to
  `@dfinity.org` users via Internet Identity certified attributes.
- [`demos/dfinsight/`](demos/dfinsight/) — feedback board with
  user-side posting and an attribute-gated admin role.

Both use the v0.2 API end-to-end and demonstrate the action-tagged
nonce flow alongside the `verify` + `Verified` shape.

## Test vectors

`test/vectors/icrc3-test-vectors.json` is copied from the Internet
Identity monorepo (`docs/icrc3-test-vectors.json`) — 10 golden
`message_hex` + expected map vectors produced by the II backend. The II
repo's integration test guards the file against drift in CI; that repo
is the source of truth.

## License

Apache-2.0.
