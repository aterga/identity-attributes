import Attributes "./Internal/Attributes";
import Challenges "./Internal/Challenges";
import Verify     "./Internal/Verify";
import Result     "mo:core/Result";

/// Verify Internet Identity attribute bundles in relying-party canisters.
/// Pairs with `@icp-sdk/auth` v7's `requestAttributes` / `AttributesIdentity`.
///
/// The provider owns no state of its own — nonces live in a `Nonces`
/// value you declare in your actor and pass in by reference. In a
/// `persistent actor` that value is stable by default, so in-flight
/// users survive upgrades. See README for setup.
module {

  public type Nonces             = Challenges.Store;
  public type VerifiedAttributes = Attributes.VerifiedAttributes;
  public type Attributes         = Attributes.Attributes;
  public type Error              = Verify.Error;

  /// A fresh, empty nonce store. Declare once in your actor with
  /// `let nonces = emptyNonces();` and pass to
  /// `IdentityAttributesProvider`. `let` in a `persistent actor` is
  /// stable by default, so the store survives upgrades.
  public func emptyNonces() : Nonces = Challenges.empty();

  public type Config = {

    /// The frontend origin every bundle must claim in `implicit:origin`.
    /// Mismatch → `#OriginMismatch`. Typically the exact `.icp0.io` URL
    /// of your asset canister (no trailing slash). Internet Identity
    /// rewrites `.ic0.app` loads to the canonical `.icp0.io` form before
    /// signing, so list the `.icp0.io` form here even if users arrive
    /// on `.ic0.app`.
    origin : Text;

    /// The nonce store. Passed by reference — the provider mutates it
    /// in place when issuing or consuming nonces.
    nonces : Nonces;
  };

  /// Stateless façade over the nonce store and the verify pipeline.
  /// Declare as `transient let` in a `persistent actor` — it gets
  /// rebuilt every upgrade and re-binds to the same `Nonces` value.
  public class IdentityAttributesProvider(config : Config) {

    /// Mint a fresh single-use nonce. Call from your anonymous "start"
    /// method (the FE pre-fetches the nonce before sign-in) and return
    /// the blob so the FE can pass it to
    /// `authClient.requestAttributes({ nonce, keys })`.
    public func createNonce<system>() : async Blob {
      await Challenges.issue<system>(config.nonces)
    };

    /// Verify the attribute bundle attached to the current call. On
    /// `#ok` you can trust:
    ///
    ///   1. The bundle was signed by a principal in your
    ///      `trusted_attribute_signers` env var (enforced by
    ///      `mo:core/CallerAttributes`; this layer traps if not).
    ///   2. `implicit:origin` matches the configured `origin`.
    ///   3. `implicit:nonce` is one *this canister* issued, single-use,
    ///      not yet redeemed.
    ///   4. `implicit:issued_at_timestamp_ns` is within 5 minutes of now.
    ///
    /// On `#err`, nothing about the bundle is trustworthy.
    public func getVerifiedAttributes<system>()
      : Result.Result<VerifiedAttributes, Error>
    {
      Verify.verify<system>({ origin = config.origin; store = config.nonces })
    };
  };

};
