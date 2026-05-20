import Challenges "./Internal/Challenges";
import Verify     "./Internal/Verify";
import Principal  "mo:core/Principal";
import Result     "mo:core/Result";

/// Mixin that injects the two canister methods needed to verify
/// Internet Identity attribute bundles into your actor. Pairs with
/// `@icp-sdk/auth` v7's `requestAttributes` / `AttributesIdentity` flow.
///
/// Usage:
///
/// ```motoko
/// import IdentityAttributes "mo:identity-attributes";
///
/// persistent actor {
///   transient let profiles = Map.empty<Principal, { name : ?Text; email : ?Text; sso : ?Text }>();
///
///   include IdentityAttributes({
///     onVerified = func(caller, attrs) {
///       Map.add(profiles, Principal.compare, caller, attrs)
///     };
///   });
/// };
/// ```
///
/// Injected methods:
///   - `_internet_identity_sign_in_start() : async Blob` — frontend calls this
///     anonymously before sign-in to get a fresh nonce.
///   - `_internet_identity_sign_in_finish() : async Result<(), IdentityAttributesError>` —
///     frontend calls this `AttributesIdentity`-wrapped after sign-in.
///     On success, `config.onVerified(caller, attrs)` runs with the
///     verified principal and `{ name; email; sso }`. `sso` is the
///     matched trusted SSO domain when the bundle's name/email came
///     from `sso:<domain>:*` keys, otherwise `null`.
///
/// The nonce store lives inside the mixin as a `transient` field;
/// Motoko's `persistent actor` requires class-like state to be
/// transient, so the store is recreated empty on every upgrade.
/// In-flight authentications will retry — nothing older than the
/// 5-minute freshness window would have been redeemable anyway.
mixin (config : {
  onVerified : (Principal, { name : ?Text; email : ?Text; sso : ?Text }) -> ()
}) {

  transient let challenges = Challenges.empty();

  public shared func _internet_identity_sign_in_start() : async Blob {
    await Challenges.issue<system>(challenges)
  };

  public shared ({ caller }) func _internet_identity_sign_in_finish()
    : async Result.Result<(), Verify.Error>
  {
    switch (Verify.verify<system>(challenges)) {
      case (#err e) #err e;
      case (#ok attrs) {
        config.onVerified(caller, attrs);
        #ok
      };
    }
  };
}
