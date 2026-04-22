import CallerAttributes "mo:core/CallerAttributes";
import Time "mo:core/Time";
import Int "mo:core/Int";
import Result "mo:core/Result";
import Value "./Value";
import Attributes "./Attributes";
import Implicit "./Implicit";
import Challenges "./Challenges";

/// One-shot verification of a certified attribute bundle, parameterised
/// by a security policy. Wraps the low-level pipeline:
///
///   1. `CallerAttributes.getAttributes<system>()` (signer check done by core)
///   2. Candid-decode into `Value`
///   3. `Attributes.fromValue`
///   4. Policy-specific implicit-field checks (origin / freshness / nonce)
module {
  public type Attributes = Attributes.Attributes;

  public type Policy = {
    #Informational;
    #Functional    : { maxAgeNs : Nat };
    #Authorization : { expectedOrigin : Text; maxAgeNs : Nat };
  };

  public type Config = {
    policy : Policy;
    caller : Principal;
    nonces : ?Challenges.Store;
  };

  public type Error = {
    #NoAttributes;
    #MalformedCandid;
    #MissingField    : Text;
    #OriginMismatch  : { expected : Text; got : Text };
    #Stale           : { ageNs : Nat };
    #UnknownNonce;
    #NonceExpired;
    #MissingNonceStore;
  };

  public func verify<system>(c : Config) : Result.Result<Attributes, Error> {
    let ?raw = CallerAttributes.getAttributes<system>() else return #err(#NoAttributes);
    let ?value = Value.decode(raw) else return #err(#MalformedCandid);
    let ?attrs = Attributes.fromValue(value) else return #err(#MalformedCandid);

    let nowNs = Int.abs(Time.now());

    switch (c.policy) {
      case (#Informational) { #ok attrs };

      case (#Functional { maxAgeNs }) {
        switch (checkFreshness(attrs, maxAgeNs, nowNs)) {
          case (#err e) #err e;
          case _ #ok attrs;
        };
      };

      case (#Authorization { expectedOrigin; maxAgeNs }) {
        let ?store = c.nonces else return #err(#MissingNonceStore);
        switch (checkOrigin(attrs, expectedOrigin)) {
          case (#err e) return #err e; case _ {};
        };
        switch (checkFreshness(attrs, maxAgeNs, nowNs)) {
          case (#err e) return #err e; case _ {};
        };
        switch (checkNonce(attrs, store, c.caller, nowNs)) {
          case (#err e) return #err e; case _ {};
        };
        #ok attrs
      };
    };
  };

  func checkOrigin(a : Attributes, expected : Text) : Result.Result<(), Error> {
    switch (Implicit.origin(a)) {
      case null #err(#MissingField "implicit:origin");
      case (?got) {
        if (got == expected) #ok else #err(#OriginMismatch { expected; got })
      };
    };
  };

  func checkFreshness(a : Attributes, maxAgeNs : Nat, nowNs : Nat) : Result.Result<(), Error> {
    switch (Implicit.issuedAtNs(a)) {
      case null #err(#MissingField "implicit:issued_at_timestamp_ns");
      case (?issued) {
        if (nowNs < issued) { #ok }              // clock skew: treat as fresh
        else {
          let age = nowNs - issued : Nat;
          if (age <= maxAgeNs) #ok else #err(#Stale { ageNs = age })
        }
      };
    };
  };

  func checkNonce(a : Attributes, store : Challenges.Store, caller : Principal, nowNs : Nat) : Result.Result<(), Error> {
    switch (Implicit.nonce(a)) {
      case null #err(#MissingField "implicit:nonce");
      case (?n) {
        switch (Challenges.consume(store, caller, n, nowNs)) {
          case (#ok) #ok;
          case (#err(#UnknownNonce)) #err(#UnknownNonce);
          case (#err(#Expired))      #err(#NonceExpired);
        }
      };
    };
  };
};
