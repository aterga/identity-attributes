# identity-attributes

Motoko library for verifying Internet Identity attribute bundles in
relying-party canisters. Pairs with `@icp-sdk/auth` v7's
`requestAttributes` / `AttributesIdentity` flow.

## Install

`mops.toml`:

```toml
[dependencies]
identity-attributes = "0.2.0"
core                = "2.5.0"
```

`icp.yaml` — list the Internet Identity backend as a trusted signer:

```yaml
canisters:
  - name: backend
    settings:
      environment_variables:
        trusted_attribute_signers: "rdmx6-jaaaa-aaaaa-aaadq-cai"
```

## Usage

```motoko
import II        "mo:identity-attributes";
import Principal "mo:core/Principal";
import Runtime   "mo:core/Runtime";

persistent actor {
  stable var nonces = II.newStore();

  // Called anonymously by the frontend before II sign-in.
  public shared func registerBegin() : async Blob {
    await II.issueNonce<system>(nonces, "register")
  };

  // Called authenticated (AttributesIdentity-wrapped) after sign-in.
  public shared ({ caller }) func registerFinish() : async Text {
    if (Principal.isAnonymous(caller)) Runtime.trap("anonymous");

    let result = switch (II.verify<system>({
      origin         = "https://your-app.icp0.io";
      maxAgeNs       = null;                // null = 5 min default
      nonces;
      action         = "register";          // must match the issue call
      openIdProvider = ?#Google;            // ?#Apple, ?#Microsoft, ?#OpenId url, or null
    })) {
      case (#ok r)  r;
      case (#err e) Runtime.trap(debug_show e);
    };

    let ?email = result.email else Runtime.trap("no verified email");
    "Hi " # email
  };
};
```

## API

```motoko
II.newStore()                            : Store
II.issueNonce<system>(store, action)     : async Blob
II.verify<system>(config)                : Result<Verified, Error>

type Config = {
  origin         : Text;
  maxAgeNs       : ?Nat;            // null = II.defaultMaxAgeNs (5 min)
  nonces         : Store;
  action         : Text;
  openIdProvider : ?OpenIdProvider; // null = passkey / unscoped keys
};

type Verified = {
  name       : ?Text;
  email      : ?Text;
  attributes : Attributes;          // for non-standard keys: attributes.getText(key)
};

type OpenIdProvider = { #Google; #Apple; #Microsoft; #OpenId : Text };

type Error = {
  #NoAttributes;
  #MalformedCandid;
  #MissingField   : Text;
  #OriginMismatch : { expected : Text; got : Text };
  #Stale          : { ageNs : Nat };
  #UnknownNonce;
  #NonceExpired;
};
```

`result.attributes` has `getText(key)`, `getNat(key)`, `getBlob(key)`,
`has(key)` for keys outside the typed surface.

## Compatibility

| `mo:identity-attributes` | `@icp-sdk/auth` |
|---|---|
| `^0.2` | `^7` |

## Demos

- [`demos/bagel/`](demos/bagel/) — pair-for-coffee canister, gated by II attributes.
- [`demos/dfinsight/`](demos/dfinsight/) — feedback board with an attribute-gated admin role.

## License

Apache-2.0.
