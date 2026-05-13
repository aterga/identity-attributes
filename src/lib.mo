import Attributes "./Internal/Attributes";
import Challenges "./Internal/Challenges";
import Verify     "./Internal/Verify";
import Result     "mo:core/Result";

/// Verify Internet Identity attribute bundles in relying-party canisters.
/// Pairs with `@icp-sdk/auth` v7's `requestAttributes` / `AttributesIdentity`.
///
/// One `Verifier` per canister. `nonce` mints a single-use nonce;
/// `verify` walks the bundle's invariants (origin, nonce, freshness)
/// and returns a `Verified` record with every known provider's `name`
/// and `verified_email` surfaced as optional fields — pick the ones you
/// asked the FE to request.
///
/// The signer check (is this bundle really from II?) happens one level
/// down in `mo:core/CallerAttributes`, which reads your
/// `trusted_attribute_signers` env var. See README.md for setup.
module {

  public type Verified   = Attributes.Verified;
  public type Attributes = Attributes.Attributes;
  public type Error      = Verify.Error;

  public type Config = {

    /// The frontend origin every bundle must claim in `implicit:origin`.
    /// Mismatch → `#OriginMismatch`. Typically the exact `.icp0.io` URL
    /// of your asset canister (no trailing slash). Internet Identity
    /// rewrites `.ic0.app` loads to the canonical `.icp0.io` form before
    /// signing, so list the `.icp0.io` form here even if users arrive on
    /// `.ic0.app`.
    origin : Text;
  };

  /// Owns a transient nonce store internally — declare as `transient let`
  /// in a `persistent actor`. Nonces are intentionally dropped on
  /// upgrade: any user mid-flow simply retries inside the 5-minute
  /// freshness window.
  public class Verifier(config : Config) {

    let store : Challenges.Store = Challenges.empty();

    /// Mint a fresh single-use nonce. Call from your anonymous "begin"
    /// method (the FE pre-fetches the nonce before sign-in) and return
    /// the blob so the FE can pass it to
    /// `authClient.requestAttributes({ nonce, keys })`.
    public func nonce<system>() : async Blob {
      await Challenges.issue<system>(store)
    };

    /// Verify the attribute bundle attached to the current call. On
    /// `#ok` you can trust:
    ///
    ///   1. The bundle was signed by a principal in your
    ///      `trusted_attribute_signers` env var (enforced by
    ///      `mo:core/CallerAttributes`; this layer traps if not).
    ///   2. `implicit:origin` matches the configured `origin`.
    ///   3. `implicit:nonce` is one *this verifier* issued, single-use,
    ///      not yet redeemed.
    ///   4. `implicit:issued_at_timestamp_ns` is within 5 minutes of now.
    ///
    /// On `#err`, nothing about the bundle is trustworthy.
    public func verify<system>() : Result.Result<Verified, Error> {
      Verify.verify<system>({ origin = config.origin; store })
    };
  };

};
