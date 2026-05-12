import CallerAttributes "mo:core/CallerAttributes";
import Time "mo:core/Time";
import Int "mo:core/Int";
import Result "mo:core/Result";
import Value "./Value";
import Attributes "./Attributes";
import Challenges "./Challenges";

/// One-shot verification of a certified Internet Identity attribute bundle.
///
/// `verify` always enforces every check the bundle needs to be trusted:
///
///   1. Signer — handled by `mo:core/CallerAttributes`, which traps unless
///      the bundle's `sender_info.signer` is listed in the canister's
///      `trusted_attribute_signers` environment variable. Set this to
///      `rdmx6-jaaaa-aaaaa-aaadq-cai` (mainnet Internet Identity) in your
///      `icp.yaml`.
///   2. Origin — bundle's `implicit:origin` must be in `Config.origins`.
///   3. Freshness — `implicit:issued_at_timestamp_ns` must be within
///      `Config.maxAgeNs` of now (default: 5 minutes).
///   4. Nonce — bundle's `implicit:nonce` must match an unconsumed entry
///      in `Config.nonces` for `Config.action`, also within `maxAgeNs`.
///      The matching entry is removed (single-use).
///
/// On success, returns a `Verified` view typed under the chosen
/// `openIdProvider` scope (or default-scope if `null`).
module {
  public type Verified = Attributes.Verified;
  public type OpenIdProvider = Attributes.OpenIdProvider;

  public type Config = {
    /// Allowed frontend origins. Must be non-empty. The bundle's
    /// `implicit:origin` must equal one of these strings exactly.
    origins        : [Text];

    /// Maximum bundle/nonce age. `null` uses `defaultMaxAgeNs` (5 minutes).
    /// Applied to both the bundle's `implicit:issued_at_timestamp_ns` and
    /// to the nonce's age in the store.
    maxAgeNs       : ?Nat;

    /// Nonce store, written to by `Challenges.issue` in the matching
    /// begin endpoint. `verify` looks up `implicit:nonce` here and
    /// removes the entry on success.
    nonces         : Challenges.Store;

    /// Action label binding this verify call to a specific flow. Must
    /// match the action used at `Challenges.issue` time. Prevents a
    /// nonce issued for one flow being redeemed against another.
    action         : Text;

    /// Which OpenID provider's scope to read attributes from. `null` for
    /// the passkey/default flow (unscoped attribute keys).
    openIdProvider : ?OpenIdProvider;
  };

  public type Error = {
    #NoAttributes;
    #MalformedCandid;
    #MissingField        : Text;
    #OriginMismatch      : { expected : [Text]; got : Text };
    #Stale               : { ageNs : Nat };
    #UnknownNonce;
    #NonceExpired;
    #NoOriginsConfigured;
  };

  // 5 minutes in nanoseconds.
  public let defaultMaxAgeNs : Nat = 300_000_000_000;

  public func verify<system>(c : Config) : Result.Result<Verified, Error> {
    if (c.origins.size() == 0) return #err(#NoOriginsConfigured);

    let ?raw   = CallerAttributes.getAttributes<system>() else return #err(#NoAttributes);
    let ?value = Value.decode(raw)                         else return #err(#MalformedCandid);
    let ?attrs = Attributes.fromValue(value)               else return #err(#MalformedCandid);

    let nowNs  = Int.abs(Time.now());
    let maxAge = switch (c.maxAgeNs) { case (?n) n; case null defaultMaxAgeNs };

    // Origin
    let ?got = attrs.getText("implicit:origin") else return #err(#MissingField "implicit:origin");
    var matched = false;
    for (o in c.origins.vals()) { if (o == got) matched := true };
    if (not matched) return #err(#OriginMismatch { expected = c.origins; got });

    // Bundle freshness — positive clock skew (now < issued) treated as fresh.
    let ?issued = attrs.getNat("implicit:issued_at_timestamp_ns") else return #err(#MissingField "implicit:issued_at_timestamp_ns");
    if (nowNs >= issued) {
      let age = nowNs - issued : Nat;
      if (age > maxAge) return #err(#Stale { ageNs = age });
    };

    // Nonce (action-scoped, single-use, also age-bounded by maxAge)
    let ?bundleNonce = attrs.getBlob("implicit:nonce") else return #err(#MissingField "implicit:nonce");
    switch (Challenges.consume(c.nonces, c.action, bundleNonce, nowNs, maxAge)) {
      case (#err(#UnknownNonce)) return #err(#UnknownNonce);
      case (#err(#Expired))      return #err(#NonceExpired);
      case (#ok) {};
    };

    #ok(Attributes.asProvider(attrs, c.openIdProvider))
  };
};
