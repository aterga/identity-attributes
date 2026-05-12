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
///   transient let ii = II.Verifier("https://your-app.icp0.io");
///
///   public shared func begin() : async Blob {
///     await ii.issueNonce<system>("register")
///   };
///
///   public shared func finish() : async ?Text {
///     switch (ii.verify<system>({
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

  public type Config = {
    action         : Text;
    openIdProvider : ?OpenIdProvider;
  };

  /// Bound to a single frontend `origin`. Owns a nonce store internally
  /// — declare as `transient let` in a `persistent actor`. Nonces are
  /// throwaway across upgrades (5-min ephemeral; in-flight users retry).
  public class Verifier(origin : Text) {
    let store : C.Store = C.empty();

    public func issueNonce<system>(action : Text) : async Blob {
      await C.issue<system>(store, action)
    };

    public func verify<system>(c : Config) : Result.Result<Verified, Error> {
      V.verify<system>({
        origin;
        nonces         = store;
        action         = c.action;
        openIdProvider = c.openIdProvider;
      })
    };
  };
};
