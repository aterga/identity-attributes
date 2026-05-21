import CallerAttributes "mo:core/CallerAttributes";
import Runtime "mo:core/Runtime";
import Time "mo:core/Time";
import Int "mo:core/Int";
import Result "mo:core/Result";
import Text "mo:core/Text";
import Iter "mo:core/Iter";
import Array "mo:core/Array";
import Value "./Value";
import Attributes "./Attributes";
import Challenges "./Challenges";

/// Walks a single attribute bundle through every invariant the canister
/// can check, *given* that the IC has already enforced "the bundle is
/// signed by someone we trust" via `mo:core/CallerAttributes`.
///
///   1. A bundle is actually attached to the call (`#NoAttributes`).
///   2. The bundle's Candid payload decodes to an ICRC-3 `Value::Map`
///      (`#MalformedCandid`).
///   3. The `frontend_origins` canister env var is set
///      (`#FrontendOriginsNotConfigured`).
///   4. `implicit:origin` is one of the configured `frontend_origins`.
///   5. `implicit:issued_at_timestamp_ns` is within the freshness window.
///   6. `implicit:nonce` is one this canister issued, not yet consumed.
///   7. `name`/`email` are sourced uniformly (see `Attributes`).
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
    /// The canister's `frontend_origins` environment variable isn't
    /// set, or parses to an empty list. Configure it under
    /// `canisters[].settings.environment_variables.frontend_origins`
    /// in `icp.yaml`, or set it on a deployed canister with
    /// `icp canister settings update <name> --add-environment-variable frontend_origins=<url>[,<url>...]`.
    #FrontendOriginsNotConfigured;
    /// `implicit:origin` doesn't match any value in `frontend_origins`.
    /// Usually means the FE call went to the wrong backend, or someone
    /// is trying to launder a bundle minted for a different dapp.
    #FrontendOriginMismatch : { expected : [Text]; got : Text };
    /// `implicit:issued_at_timestamp_ns` is older than the freshness
    /// window. The FE should fetch a fresh nonce and try again.
    #Stale : { ageNs : Nat };
    /// The bundle's nonce was never issued by this canister, or was
    /// issued and already consumed. Stale-but-stored nonces are caught
    /// by `#Stale` (the bundle freshness check) before we get here.
    #UnknownNonce;
    /// A logical field on `IdentityAttributes` (`"name"`, `"email"`,
    /// or `"sso"` when name+email come from different SSO domains) is
    /// sourced from more than one key in the bundle.
    #AmbiguousAttribute : { field : Text; sources : [Text] };
    /// The bundle contains an `sso:<domain>:*` key whose `<domain>`
    /// is not listed in `trusted_sso_domains`. The whole bundle is
    /// rejected — we don't silently strip untrusted SSO claims.
    #UntrustedSsoSource : { domain : Text };
    /// The bundle mixes SSO and non-SSO sources for name/email. A
    /// bundle is either fully SSO (all keys `sso:<trusted-domain>:*`,
    /// same domain) or fully non-SSO (unscoped/openid). `ssoKeys` and
    /// `otherKeys` list the offending entries.
    #MixedSsoSources : { ssoKeys : [Text]; otherKeys : [Text] }
  };

  /// Five minutes in nanoseconds. Applied to the bundle's
  /// `implicit:issued_at_timestamp_ns` freshness check.
  let maxAgeNs : Nat = 300_000_000_000;

  // Parse a comma-separated env var value. Empty entries are dropped,
  // so trailing commas and accidental whitespace-only entries don't
  // turn into bogus list members. Surrounding whitespace on each entry
  // is left intact — env values are operator-controlled and we'd
  // rather mismatch loudly than silently normalize a typo.
  func parseList(raw : Text) : [Text] {
    let parts = Iter.toArray(Text.split(raw, #char ','));
    Array.filter<Text>(parts, func t = Text.size(t) > 0)
  };

  public func verify<system>(store : Challenges.Store) : Result.Result<IdentityAttributes, Error> {

    let ?rawBundle = CallerAttributes.getAttributes<system>() else return #err(#NoAttributes);
    let ?decoded = Value.decode(rawBundle) else return #err(#MalformedCandid);
    let ?attrs = Attributes.fromValue(decoded) else return #err(#MalformedCandid);

    let nowNs = Int.abs(Time.now());

    let ?rawFrontendOrigins = Runtime.envVar<system>("frontend_origins") else return #err(#FrontendOriginsNotConfigured);
    let frontendOrigins = parseList(rawFrontendOrigins);
    if (frontendOrigins.size() == 0) return #err(#FrontendOriginsNotConfigured);

    let ?gotOrigin = attrs.getText("implicit:origin") else return #err(#MissingField "implicit:origin");
    if (Array.find<Text>(frontendOrigins, func o = o == gotOrigin) == null) {
      return #err(#FrontendOriginMismatch { expected = frontendOrigins; got = gotOrigin })
    };

    let ?issuedAt = attrs.getNat("implicit:issued_at_timestamp_ns") else return #err(#MissingField "implicit:issued_at_timestamp_ns");
    if (nowNs >= issuedAt) {
      let age = nowNs - issuedAt : Nat;
      if (age > maxAgeNs) return #err(#Stale { ageNs = age })
    };

    let ?bundleNonce = attrs.getBlob("implicit:nonce") else return #err(#MissingField "implicit:nonce");
    switch (Challenges.consume(store, bundleNonce)) {
      case (#err(#UnknownNonce)) return #err(#UnknownNonce);
      case (#ok) {}
    };

    // Optional — when unset, asIdentityAttributes treats every sso:*
    // key in the bundle as untrusted, which surfaces the bundle as
    // #UntrustedSsoSource. This is the safe default: a canister
    // author opts in to SSO domains explicitly.
    let trustedSsoDomains = switch (Runtime.envVar<system>("trusted_sso_domains")) {
      case null [];
      case (?raw) parseList(raw)
    };

    switch (Attributes.asIdentityAttributes(attrs, trustedSsoDomains)) {
      case (#err(#AmbiguousAttribute e)) #err(#AmbiguousAttribute e);
      case (#err(#UntrustedSsoSource e)) #err(#UntrustedSsoSource e);
      case (#err(#MixedSsoSources e)) #err(#MixedSsoSources e);
      case (#ok r) #ok r
    }
  };

}
