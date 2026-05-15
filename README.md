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
import { IdentityAttributesProvider } "mo:identity-attributes";
import List "mo:core/List";

persistent actor {
  let nonces = List.empty<Blob>();

  transient let identityAttributesProvider = IdentityAttributesProvider({
    origin = "https://your-app.icp0.io";
    nonces;
  });

  // Pre-fetched anonymously by the frontend before II sign-in.
  public shared func authStart() : async Blob {
    await identityAttributesProvider.createNonce<system>()
  };

  // Called authenticated (AttributesIdentity-wrapped) after sign-in.
  public shared func authFinish() : async () {
    let #ok verifiedAttributes = identityAttributesProvider.getVerifiedIdentityAttributes<system>() else return;
    // e.g. update the caller's profile with verifiedAttributes.name and verifiedAttributes.verified_email.
  };
};
```

## API

```motoko
IdentityAttributesProvider(config)       : IdentityAttributesProvider

// Methods on the IdentityAttributesProvider instance:
identityAttributesProvider.createNonce<system>()           : async Blob
identityAttributesProvider.getVerifiedIdentityAttributes<system>() : Result<VerifiedIdentityAttributes, IdentityAttributesError>

type Nonces = List.List<Blob>;

type Config = {
  origin : Text;
  nonces : Nonces;
};

type VerifiedIdentityAttributes = {
  name                     : ?Text;
  verified_email           : ?Text;
  google_name              : ?Text;
  google_verified_email    : ?Text;
  apple_name               : ?Text;
  apple_verified_email     : ?Text;
  microsoft_name           : ?Text;
  microsoft_verified_email : ?Text;
  attributes               : Attributes;
};

type IdentityAttributesError = {
  #NoAttributes;
  #MalformedCandid;
  #MissingField   : Text;
  #OriginMismatch : { expected : Text; got : Text };
  #Stale          : { ageNs : Nat };
  #UnknownNonce;
};
```

`verifiedAttributes.attributes` has `getText(key)`, `getNat(key)`,
`getBlob(key)`, `has(key)` for keys outside the typed surface —
implicit fields, enterprise SSO (`sso:<domain>:*`), the raw `email`.

## Compatibility

| `mo:identity-attributes` | `@icp-sdk/auth` |
|---|---|
| `^0.3` | `^7` |

## Demos

- [`demos/bagel/`](demos/bagel/) — pair-for-coffee canister, gated by II attributes.
- [`demos/dfinsight/`](demos/dfinsight/) — feedback board with an attribute-gated admin role.

## License

Apache-2.0.
