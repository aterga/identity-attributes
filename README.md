# identity-attributes

Motoko library for verifying Internet Identity attribute bundles in
relying-party canisters. Pairs with `@icp-sdk/auth` v7's
`requestAttributes` / `AttributesIdentity` flow.

## Install

`mops.toml`:

```toml
[dependencies]
identity-attributes = "0.3.0"
core                = "2.5.0"
```

`icp.yaml` — list the Internet Identity backend as a trusted signer
and set the frontend origin every bundle must match:

```yaml
canisters:
  - name: backend
    settings:
      environment_variables:
        trusted_attribute_signers: "rdmx6-jaaaa-aaaaa-aaadq-cai"
        origin: "https://your-app.icp0.io"
```

## Usage

The library is a mixin — `include` it inside your `persistent actor`
and it injects the two canister methods the frontend talks to. Your
only job is the `onVerified` callback that runs once the bundle has
been verified.

```motoko
import IdentityAttributes "mo:identity-attributes";
import Map        "mo:core/Map";
import Principal  "mo:core/Principal";

persistent actor {
  // User profiles keyed by principal. Populated from verified II
  // attribute bundles by the callback below.
  let profiles = Map.empty<Principal, { name : ?Text; email : ?Text }>();

  include IdentityAttributes({
    onVerified = func(caller, attrs) {
      Map.add(profiles, Principal.compare, caller, attrs)
    };
  });

  public query func getProfile(p : Principal) : async ?{ name : ?Text; email : ?Text } {
    Map.get(profiles, Principal.compare, p)
  };
};
```

The `include` call adds two `public shared` methods to your actor:

```
_internet_identity_sign_in_start()  : async Blob
_internet_identity_sign_in_finish() : async Result<(), IdentityAttributesError>
```

Frontend flow:

1. Call `_internet_identity_sign_in_start` anonymously before sign-in to get a 32-byte
   nonce.
2. Pass it to `authClient.requestAttributes({ nonce, keys: ["name", "verified_email"] })`.
3. Wrap the resulting `SignedAttributes` into an `AttributesIdentity`
   and call `_internet_identity_sign_in_finish`. On `#ok` the actor's `onVerified`
   callback has already run; the FE can now call your other methods.

## API

```motoko
include IdentityAttributes({
  onVerified : (Principal, { name : ?Text; email : ?Text }) -> ()
});

// Injected on the consumer actor:
_internet_identity_sign_in_start()  : async Blob
_internet_identity_sign_in_finish() : async Result<(), IdentityAttributesError>

type IdentityAttributesError = {
  #NoAttributes;
  #MalformedCandid;
  #MissingField        : Text;
  #OriginNotConfigured;
  #OriginMismatch      : { expected : Text; got : Text };
  #Stale               : { ageNs : Nat };
  #UnknownNonce;
  #AmbiguousAttribute  : { field : Text; sources : [Text] };
};
```

`name` and `email` are each sourced from at most one key in the
bundle — the unscoped key (`name` / `verified_email`) or exactly one
OpenID-provider-scoped key (`openid:<provider>:name` /
`openid:<provider>:verified_email`). If the bundle contains two or
more candidates for the same field, `_internet_identity_sign_in_finish` returns
`#AmbiguousAttribute` rather than silently picking one. `email` only
sources from `verified_email`-suffixed keys; the unverified `email`
key is never exposed.

## Compatibility

| `mo:identity-attributes` | `@icp-sdk/auth` |
|---|---|
| `^0.3` | `^7` |

## Demos

- [`demos/bagel/`](demos/bagel/) — pair-for-coffee canister, gated by Internet Identity attributes.
- [`demos/dfinsight/`](demos/dfinsight/) — feedback board with an attribute-gated admin role.

## License

Apache-2.0.
