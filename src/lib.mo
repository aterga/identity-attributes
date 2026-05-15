import Attributes "./Internal/Attributes";
import Challenges "./Internal/Challenges";
import Verify     "./Internal/Verify";
import Result     "mo:core/Result";

/// Verify Internet Identity attribute bundles in relying-party canisters.
/// Pairs with `@icp-sdk/auth` v7's `requestAttributes` / `AttributesIdentity`.
///
/// `IdentityAttributesProvider` captures `origin` and a reference to
/// your `Nonces` record at construction time. The provider holds no
/// state of its own — it just mutates the nonces you passed in.
///
/// Motoko requires class instances be declared `transient` in a
/// `persistent actor`, which is fine here: the provider is rebuilt on
/// every upgrade and re-binds to the same `nonces` record (the nonces
/// themselves survive because they're a stable `let`).
module {

  /// Backing record for canister-issued nonces. Declare inline:
  ///
  /// ```motoko
  /// let nonces : IdentityAttributesProvider.Nonces = { var entries = [] };
  /// ```
  public type Nonces             = Challenges.Store;
  public type VerifiedAttributes = Attributes.VerifiedAttributes;
  public type Attributes         = Attributes.Attributes;
  public type Error              = Verify.Error;

  public type Config = {

    /// The frontend origin every bundle must claim in `implicit:origin`.
    /// Mismatch → `#OriginMismatch`. Typically the exact `.icp0.io` URL
    /// of your asset canister (no trailing slash). Internet Identity
    /// rewrites `.ic0.app` loads to the canonical `.icp0.io` form before
    /// signing, so list the `.icp0.io` form here even if users arrive
    /// on `.ic0.app`.
    origin : Text;

    /// The nonce store the provider should mutate.
    nonces : Nonces;
  };

  public class IdentityAttributesProvider(config : Config) {

    /// Mint a fresh single-use nonce, append it to the captured
    /// `nonces`, return the blob. The frontend pre-fetches this before
    /// sign-in and passes it to
    /// `authClient.requestAttributes({ nonce, keys })`.
    public func createNonce<system>() : async Blob {
      await Challenges.issue<system>(config.nonces)
    };

    /// Verify the attribute bundle attached to the current call,
    /// consuming the matching nonce on success.
    ///
    /// On `#ok` you can trust:
    ///
    ///   1. The bundle was signed by a principal in your
    ///      `trusted_attribute_signers` env var (enforced by
    ///      `mo:core/CallerAttributes`; this layer traps if not).
    ///   2. `implicit:origin` matches the configured `origin`.
    ///   3. `implicit:nonce` is one *this canister* issued via
    ///      `createNonce`, single-use, not yet redeemed.
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
