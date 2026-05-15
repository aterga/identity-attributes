import Random "mo:core/Random";
import Queue  "mo:core/Queue";
import Result "mo:core/Result";

/// Single-use canister-issued nonces, held in a FIFO `Queue<Blob>`.
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
/// Capped at `maxTotal` entries. On overflow the oldest is evicted via
/// `Queue.popFront` (O(1)). In legitimate use that's an abandoned
/// flow. Successful `consume` removes the matched entry.
///
/// ## Why we don't key by `Principal`
///
/// In the canonical flow the begin endpoint is called anonymously
/// (before Internet Identity sign-in) and the finish endpoint is called
/// authenticated, so the two callers differ. Cross-user replay is
/// handled by the bundle signature itself: the IC binds the bundle to
/// the caller of the finish endpoint, so an attacker who steals a
/// nonce only manages to register themselves.
module {

  /// Upper bound on store size. FIFO eviction once we hit this.
  public let maxTotal : Nat = 4096;

  public type Store = Queue.Queue<Blob>;

  public type ConsumeError = { #UnknownNonce };

  /// Mint a fresh 32-byte random nonce, remember it, return it.
  public func issue<system>(store : Store) : async Blob {
    let nonce = await Random.blob();
    if (Queue.size(store) >= maxTotal) {
      ignore Queue.popFront(store);
    };
    Queue.pushBack(store, nonce);
    nonce
  };

  /// Find and remove the entry matching `nonce`. Queue has no
  /// remove-at-position; rebuild via filter + clear + push.
  public func consume(store : Store, nonce : Blob) : Result.Result<(), ConsumeError> {
    var found = false;
    let kept = Queue.filter<Blob>(store, func entry {
      if (not found and entry == nonce) { found := true; false } else true
    });
    if (not found) return #err(#UnknownNonce);
    Queue.clear(store);
    Queue.forEach<Blob>(kept, func entry = Queue.pushBack(store, entry));
    #ok
  };

};
