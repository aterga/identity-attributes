import Random "mo:core/Random";
import List   "mo:core/List";
import Result "mo:core/Result";

/// Single-use canister-issued nonces, held in a `List<Blob>`.
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
/// if they're still sitting in the store.
///
/// ## Memory bounds
///
/// Capped at `maxTotal` entries. On overflow the oldest is evicted —
/// in legitimate use that's an abandoned flow. Successful `consume`
/// removes the matched entry.
///
/// ## Why we don't key by `Principal`
///
/// In the canonical flow the begin endpoint is called anonymously
/// (before Internet Identity sign-in) and the finish endpoint is called authenticated,
/// so the two callers differ. Cross-user replay is handled by the
/// bundle signature itself: the IC binds the bundle to the caller of
/// the finish endpoint, so an attacker who steals a nonce only manages
/// to register themselves.
module {

  /// Upper bound on store size. FIFO eviction once we hit this.
  public let maxTotal : Nat = 4096;

  public type Store = List.List<Blob>;

  public type ConsumeError = { #UnknownNonce };

  /// Mint a fresh 32-byte random nonce, remember it, return it.
  public func issue<system>(store : Store) : async Blob {
    let nonce = await Random.blob();
    if (List.size(store) >= maxTotal) {
      // FIFO: drop the oldest before adding the newest. `List` has no
      // pop-front, so we rebuild without index 0.
      let rest = List.sliceToArray(store, 1, List.size(store));
      List.clear(store);
      for (entry in rest.vals()) { List.add(store, entry) };
    };
    List.add(store, nonce);
    nonce
  };

  /// Find and remove the entry matching `nonce`. List has no
  /// remove-at-index, so we rebuild via filter.
  public func consume(store : Store, nonce : Blob) : Result.Result<(), ConsumeError> {
    var found = false;
    let kept = List.filter<Blob>(store, func entry {
      if (not found and entry == nonce) { found := true; false } else true
    });
    if (found) {
      List.clear(store);
      for (entry in List.values(kept)) { List.add(store, entry) };
      #ok
    } else #err(#UnknownNonce)
  };

};
