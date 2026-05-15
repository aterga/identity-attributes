import Random "mo:core/Random";
import Array  "mo:core/Array";
import Result "mo:core/Result";

/// Single-use canister-issued nonces. A flat list of blobs.
///
/// ## Why nonces are canister-issued
///
/// Internet Identity's attribute-bundle protocol bakes the nonce into
/// the signed bundle so the relying-party canister can prove "I started
/// this flow". A frontend-generated nonce gives the canister no way to
/// distinguish a fresh user flow from an attacker replaying or
/// laundering an old bundle. Mint here, store here, consume here.
///
/// ## No per-entry expiry
///
/// We don't track when each nonce was minted — the bundle's own
/// `implicit:issued_at_timestamp_ns` field gives the verifier a
/// 5-minute freshness window, so stale nonces can't be redeemed even
/// if they're still sitting in the store. The cap (`maxTotal`) plus
/// FIFO eviction is all the bookkeeping we need.
///
/// ## Memory bounds
///
/// Capped at `maxTotal` entries. On overflow the oldest is evicted —
/// in legitimate use that's an abandoned flow. Successful `consume`
/// removes the matched entry. With 4096 entries × 32 bytes ≈ 128 KB
/// worst case.
///
/// ## Why we don't key by `Principal`
///
/// In the canonical flow the begin endpoint is called anonymously
/// (before II sign-in) and the finish endpoint is called authenticated,
/// so the two callers differ. Cross-user replay is handled by the
/// bundle signature itself: the IC binds the bundle to the caller of
/// the finish endpoint, so an attacker who steals a nonce only manages
/// to register themselves.
module {

  /// Upper bound on store size. FIFO eviction once we hit this.
  public let maxTotal : Nat = 4096;

  public type Store = { var entries : [Blob] };

  public type ConsumeError = { #UnknownNonce };

  public func empty() : Store { { var entries = [] } };

  /// Mint a fresh 32-byte random nonce, remember it, return it.
  public func issue<system>(store : Store) : async Blob {
    let nonce = await Random.blob();
    let trimmed = if (store.entries.size() >= maxTotal) {
      Array.sliceToArray<Blob>(store.entries, 1, store.entries.size())
    } else store.entries;
    store.entries := Array.concat(trimmed, [nonce]);
    nonce
  };

  /// Find and remove the entry matching `nonce`.
  public func consume(store : Store, nonce : Blob) : Result.Result<(), ConsumeError> {
    var found = false;
    store.entries := Array.filter<Blob>(store.entries, func entry {
      if (not found and entry == nonce) { found := true; false } else true
    });
    if (found) #ok else #err(#UnknownNonce)
  };

};
