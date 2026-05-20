import CallerAttributes "mo:core/CallerAttributes";
import Runtime "mo:core/Runtime";
import Time   "mo:core/Time";
import Int    "mo:core/Int";
import Result "mo:core/Result";
import Value      "./Value";
import Attributes "./Attributes";
import Challenges "./Challenges";

/// Walks a single attribute bundle through every invariant the canister
/// can check, *given* that the IC has already enforced "the bundle is
/// signed by someone we trust" via `mo:core/CallerAttributes`.
///
///   1. A bundle is actually attached to the call (`#NoAttributes`).
///   2. The bundle's Candid payload decodes to an ICRC-3 `Value::Map`
///      (`#MalformedCandid`).
///   3. The `origin` canister env var is set (`#OriginNotConfigured`).
///   4. `implicit:origin` matches the `origin` env var.
///   5. `implicit:issued_at_timestamp_ns` is within the freshness window.
///   6. `implicit:nonce` is one this canister issued, not yet consumed.
///   7. `name` and `email` are each sourced from at most one bundle key
///      (`#AmbiguousAttribute` if more than one matches).
module {

  public type IdentityAttributes = Attributes.IdentityAttributes;

  public type Error = {
    /// No bundle is attached to this call. Either the frontend forgot
    /// to wrap the identity with `AttributesIdentity`, or it wrapped
    /// against a signer this canister doesn't trust.
    #NoAttributes;
    /// The bundle is trusted-signed but its payload isn't a well-formed
    /// ICRC-3 `Value::Map`. Treat as a protocol mismatch — either Internet Identity
    /// has rev'd its wire format and this library is out of date, or
    /// someone is hand-crafting garbage payloads.
    #MalformedCandid;
    /// A required implicit field is missing.
    #MissingField : Text;
    /// The canister's `origin` environment variable isn't set. Configure
    /// it under `canisters[].settings.environment_variables.origin` in
    /// `icp.yaml`, or set it on a deployed canister with
    /// `icp canister settings update <name> --add-environment-variable origin=<url>`.
    #OriginNotConfigured;
    /// `implicit:origin` doesn't match the `origin` env var.
    /// Usually means the FE call went to the wrong backend, or someone
    /// is trying to launder a bundle minted for a different dapp.
    #OriginMismatch : { expected : Text; got : Text };
    /// `implicit:issued_at_timestamp_ns` is older than the freshness
    /// window. The FE should fetch a fresh nonce and try again.
    #Stale : { ageNs : Nat };
    /// The bundle's nonce was never issued by this canister, or was
    /// issued and already consumed. Stale-but-stored nonces are caught
    /// by `#Stale` (the bundle freshness check) before we get here.
    #UnknownNonce;
    /// A logical field on `IdentityAttributes` (`"name"` or `"email"`)
    /// is sourced from more than one key in the bundle — e.g. both the
    /// unscoped `name` and `openid:https://accounts.google.com:name`
    /// are present. `sources` lists the conflicting keys. The lib
    /// refuses to silently pick one; the frontend should request a
    /// narrower attribute set.
    #AmbiguousAttribute : { field : Text; sources : [Text] };
  };

  /// Five minutes in nanoseconds. Applied to the bundle's
  /// `implicit:issued_at_timestamp_ns` freshness check.
  let maxAgeNs : Nat = 300_000_000_000;

  public func verify<system>(store : Challenges.Store) : Result.Result<IdentityAttributes, Error> {

    let ?rawBundle = CallerAttributes.getAttributes<system>() else return #err(#NoAttributes);
    let ?decoded   = Value.decode(rawBundle)                  else return #err(#MalformedCandid);
    let ?attrs     = Attributes.fromValue(decoded)            else return #err(#MalformedCandid);

    let nowNs = Int.abs(Time.now());

    let ?expectedOrigin = Runtime.envVar<system>("origin") else return #err(#OriginNotConfigured);
    let ?gotOrigin = attrs.getText("implicit:origin") else return #err(#MissingField "implicit:origin");
    if (gotOrigin != expectedOrigin) return #err(#OriginMismatch { expected = expectedOrigin; got = gotOrigin });

    let ?issuedAt = attrs.getNat("implicit:issued_at_timestamp_ns") else return #err(#MissingField "implicit:issued_at_timestamp_ns");
    if (nowNs >= issuedAt) {
      let age = nowNs - issuedAt : Nat;
      if (age > maxAgeNs) return #err(#Stale { ageNs = age });
    };

    let ?bundleNonce = attrs.getBlob("implicit:nonce") else return #err(#MissingField "implicit:nonce");
    switch (Challenges.consume(store, bundleNonce)) {
      case (#err(#UnknownNonce)) return #err(#UnknownNonce);
      case (#ok) {};
    };

    switch (Attributes.asIdentityAttributes(attrs)) {
      case (#err e) #err(#AmbiguousAttribute e);
      case (#ok r)  #ok r;
    }
  };

};
