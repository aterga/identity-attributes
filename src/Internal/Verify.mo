import CallerAttributes "mo:core/CallerAttributes";
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
///   3. `implicit:origin` matches the configured frontend origin.
///   4. `implicit:issued_at_timestamp_ns` is within the freshness window.
///   5. `implicit:nonce` is one this canister issued, not yet consumed.
module {

  public type VerifiedIdentityAttributes = Attributes.VerifiedIdentityAttributes;

  public type Config = {
    origin : Text;
    store  : Challenges.Store;
  };

  public type Error = {
    /// No bundle is attached to this call. Either the frontend forgot
    /// to wrap the identity with `AttributesIdentity`, or it wrapped
    /// against a signer this canister doesn't trust.
    #NoAttributes;
    /// The bundle is trusted-signed but its payload isn't a well-formed
    /// ICRC-3 `Value::Map`. Treat as a protocol mismatch — either II
    /// has rev'd its wire format and this library is out of date, or
    /// someone is hand-crafting garbage payloads.
    #MalformedCandid;
    /// A required implicit field is missing.
    #MissingField : Text;
    /// `implicit:origin` doesn't match the configured frontend origin.
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
  };

  /// Five minutes in nanoseconds. Applied to the bundle's
  /// `implicit:issued_at_timestamp_ns` freshness check.
  let maxAgeNs : Nat = 300_000_000_000;

  public func verify<system>(config : Config) : Result.Result<VerifiedIdentityAttributes, Error> {

    let ?rawBundle = CallerAttributes.getAttributes<system>() else return #err(#NoAttributes);
    let ?decoded   = Value.decode(rawBundle)                  else return #err(#MalformedCandid);
    let ?attrs     = Attributes.fromValue(decoded)            else return #err(#MalformedCandid);

    let nowNs = Int.abs(Time.now());

    let ?gotOrigin = attrs.getText("implicit:origin") else return #err(#MissingField "implicit:origin");
    if (gotOrigin != config.origin) return #err(#OriginMismatch { expected = config.origin; got = gotOrigin });

    let ?issuedAt = attrs.getNat("implicit:issued_at_timestamp_ns") else return #err(#MissingField "implicit:issued_at_timestamp_ns");
    if (nowNs >= issuedAt) {
      let age = nowNs - issuedAt : Nat;
      if (age > maxAgeNs) return #err(#Stale { ageNs = age });
    };

    let ?bundleNonce = attrs.getBlob("implicit:nonce") else return #err(#MissingField "implicit:nonce");
    switch (Challenges.consume(config.store, bundleNonce)) {
      case (#err(#UnknownNonce)) return #err(#UnknownNonce);
      case (#ok) {};
    };

    #ok(Attributes.asVerifiedIdentityAttributes(attrs))
  };

};
