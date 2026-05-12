import CallerAttributes "mo:core/CallerAttributes";
import Time "mo:core/Time";
import Int "mo:core/Int";
import Result "mo:core/Result";
import Value "./Value";
import Attributes "./Attributes";
import Challenges "./Challenges";

module {
  public type Verified = Attributes.Verified;
  public type OpenIdProvider = Attributes.OpenIdProvider;

  public type Config = {
    origin         : Text;
    nonces         : Challenges.Store;
    action         : Text;
    // Provider-scoped reads. Set to the provider when the FE used a
    // 1-click OpenID flow (e.g. `?#Google` for Google 1-click) — the
    // bundle's attribute keys are prefixed with that provider's scope.
    // `null` for the default Internet Identity flow (passkey or
    // user-picked OpenID provider) — keys arrive unscoped.
    openIdProvider : ?OpenIdProvider;
  };

  public type Error = {
    #NoAttributes;
    #MalformedCandid;
    #MissingField   : Text;
    #OriginMismatch : { expected : Text; got : Text };
    #Stale          : { ageNs : Nat };
    #UnknownNonce;
    #NonceExpired;
  };

  // 5 minutes in nanoseconds.
  let maxAgeNs : Nat = 300_000_000_000;

  public func verify<system>(c : Config) : Result.Result<Verified, Error> {
    let ?raw   = CallerAttributes.getAttributes<system>() else return #err(#NoAttributes);
    let ?value = Value.decode(raw)                         else return #err(#MalformedCandid);
    let ?attrs = Attributes.fromValue(value)               else return #err(#MalformedCandid);

    let nowNs = Int.abs(Time.now());

    let ?got = attrs.getText("implicit:origin") else return #err(#MissingField "implicit:origin");
    if (got != c.origin) return #err(#OriginMismatch { expected = c.origin; got });

    let ?issued = attrs.getNat("implicit:issued_at_timestamp_ns") else return #err(#MissingField "implicit:issued_at_timestamp_ns");
    if (nowNs >= issued) {
      let age = nowNs - issued : Nat;
      if (age > maxAgeNs) return #err(#Stale { ageNs = age });
    };

    let ?bundleNonce = attrs.getBlob("implicit:nonce") else return #err(#MissingField "implicit:nonce");
    switch (Challenges.consume(c.nonces, c.action, bundleNonce, nowNs, maxAgeNs)) {
      case (#err(#UnknownNonce)) return #err(#UnknownNonce);
      case (#err(#Expired))      return #err(#NonceExpired);
      case (#ok) {};
    };

    #ok(Attributes.asProvider(attrs, c.openIdProvider))
  };
};
