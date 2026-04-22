# ii-attributes

A small, auditable Motoko library for consuming **Internet Identity
certified attribute bundles** (email, name, …) from a relying-party (RP)
canister.

Built on top of `mo:core/CallerAttributes` (which already handles the
trusted-signer check using the `trusted_attribute_signers` canister env
var), this library adds the four things every RP canister otherwise has to
reinvent:

1. Candid-decode the `info` blob into a typed ICRC-3 `Value`.
2. Attribute lookup by key, with scope-fallback (requesting `email` matches
   `email` or any `<scope>:email`).
3. Verification of the three `implicit:*` fields — `origin`,
   `issued_at_timestamp_ns`, `nonce` — tiered to the security needs of
   the use case.
4. A canister-issued single-use nonce store, required for the
   Authorization tier of the II design.

## Install

```toml
# mops.toml
[dependencies]
ii-attributes = "0.1.0"
core          = "2.5.0"
```

Also set the trusted signer via the `trusted_attribute_signers` env var
(comma-separated principal texts, e.g. the II production canister ID).

## Quick start

### Informational — display a name

```motoko
import II "mo:ii-attributes";

actor {
  public shared ({ caller }) func greet() : async Text {
    let attrs = switch (II.verify<system>({
      policy = #Informational;
      caller;
      nonces = null;
    })) {
      case (#ok a)  a;
      case (#err _) return "Hello!";
    };
    switch (II.getText(attrs, "name")) {
      case (?n) "Hello, " # n # "!";
      case null "Hello!";
    };
  };
}
```

### Authorization — link email to an account

The Authorization tier binds attributes to *this* canister (origin check),
*this* request (nonce check), and a fresh time window.

```motoko
import II       "mo:ii-attributes";
import Challenges "mo:ii-attributes/Challenges";

actor {
  stable var nonces = Challenges.empty();

  public shared ({ caller }) func generateNonce() : async Blob {
    await Challenges.issue<system>(nonces, caller, 5 * 60 * 1_000_000_000)
  };

  public shared ({ caller }) func linkEmail() : async Text {
    let attrs = switch (II.verify<system>({
      policy = #Authorization {
        expectedOrigin = "https://app.example.com";
        maxAgeNs       = 5 * 60 * 1_000_000_000;
      };
      caller;
      nonces = ?nonces;
    })) {
      case (#ok a)   a;
      case (#err e)  { /* log + reject */ return "denied"; };
    };
    switch (II.getText(attrs, "email")) {
      case (?email) email;
      case null     "no email shared";
    };
  };
}
```

## Security tiers

The `Policy` variant forces the right checks at the type level — an
Authorization consumer cannot forget to verify origin or nonce.

| Tier              | Signer | Freshness | Origin | Nonce |
|-------------------|--------|-----------|--------|-------|
| `#Informational`  | ✓      |           |        |       |
| `#Functional`     | ✓      | ✓         |        |       |
| `#Authorization`  | ✓      | ✓         | ✓      | ✓     |

The signer check (that `sender_info.signer` equals the expected II
principal) is handled by `mo:core/CallerAttributes` via the
`trusted_attribute_signers` canister env var — this library doesn't
duplicate it.

## Module map

| Module        | What it does                                   |
|---------------|------------------------------------------------|
| `Value`       | ICRC-3 `Value` type + Candid `decode`          |
| `Attributes`  | Lookup, scope fallback, typed accessors        |
| `Implicit`    | Typed access to `implicit:*` fields            |
| `Challenges`  | Canister-issued single-use nonce store         |
| `Verify`      | `Policy` + one-shot `verify`                   |

## Test vectors

`test/vectors/icrc3-test-vectors.json` is copied from the Internet
Identity monorepo (`docs/icrc3-test-vectors.json`). It contains 10 golden
`message_hex` + expected map vectors produced by the II backend. The II
repo's integration test guards the file against drift in CI — that repo
is the source of truth. Re-sync when II updates it.

## License

Apache-2.0.
