import A "./Internal/Attributes";
import C "./Internal/Challenges";
import V "./Internal/Verify";
import Result "mo:core/Result";

/// Verify Internet Identity attribute bundles in relying-party canisters.
/// Pairs with `@icp-sdk/auth` v7's `requestAttributes` / `AttributesIdentity`.
///
/// ```motoko
/// import II "mo:identity-attributes";
///
/// persistent actor {
///   // State (persists across upgrades) + transient wrapper (rebuilt on
///   // upgrade against the preserved state).
///   let          store = II.newStore();
///   transient let ii   = II.Verifier(store);
///
///   public shared func begin() : async Blob {
///     await ii.issueNonce<system>("register")
///   };
///
///   public shared func finish() : async ?Text {
///     switch (ii.verify<system>({
///       origin         = "https://your-app.icp0.io";
///       maxAgeNs       = null;
///       action         = "register";
///       openIdProvider = ?#Google;
///     })) {
///       case (#ok r)  r.email;
///       case (#err _) null;
///     };
///   };
/// };
/// ```
module {
  public type OpenIdProvider = A.OpenIdProvider;
  public type Verified       = A.Verified;
  public type Attributes     = A.Attributes;
  public type Error          = V.Error;
  public type Store          = C.Store;

  public type Config = {
    origin         : Text;
    maxAgeNs       : ?Nat;
    action         : Text;
    openIdProvider : ?OpenIdProvider;
  };

  public let defaultMaxAgeNs = V.defaultMaxAgeNs;

  /// Create a fresh nonce store. Holds this in a stable `let` of your
  /// `persistent actor` so it survives upgrades.
  public func newStore() : Store = C.empty();

  /// Wraps a `Store` and exposes the issue/verify operations against it.
  /// Hold this in a `transient let` of your `persistent actor`; it will
  /// be rebuilt on upgrade against the preserved `Store`.
  public class Verifier(store : Store) {
    public func issueNonce<system>(action : Text) : async Blob {
      await C.issue<system>(store, action)
    };

    public func verify<system>(c : Config) : Result.Result<Verified, Error> {
      V.verify<system>({
        origin         = c.origin;
        maxAgeNs       = c.maxAgeNs;
        nonces         = store;
        action         = c.action;
        openIdProvider = c.openIdProvider;
      })
    };
  };
};
