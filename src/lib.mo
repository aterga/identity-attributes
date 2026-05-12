import A "./Internal/Attributes";
import C "./Internal/Challenges";
import V "./Internal/Verify";

/// Verify Internet Identity attribute bundles in relying-party canisters.
/// Pairs with `@icp-sdk/auth` v7's `requestAttributes` / `AttributesIdentity`.
///
/// ```motoko
/// import II "mo:identity-attributes";
///
/// stable var nonces = II.newStore();
///
/// public shared func begin() : async Blob {
///   await II.issueNonce<system>(nonces, "register")
/// };
///
/// public shared func finish() : async ?Text {
///   switch (II.verify<system>({
///     origin         = "https://your-app.icp0.io";
///     maxAgeNs       = null;
///     nonces;
///     action         = "register";
///     openIdProvider = ?#Google;
///   })) {
///     case (#ok r)  r.email;
///     case (#err _) null;
///   };
/// };
/// ```
module {
  public type Store          = C.Store;
  public type Attributes     = A.Attributes;
  public type OpenIdProvider = A.OpenIdProvider;
  public type Verified       = A.Verified;
  public type Config         = V.Config;
  public type Error          = V.Error;

  public let verify          = V.verify;
  public let newStore        = C.empty;
  public let issueNonce      = C.issue;
  public let defaultMaxAgeNs = V.defaultMaxAgeNs;
};
