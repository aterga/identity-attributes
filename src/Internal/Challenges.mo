import Random "mo:core/Random";
import Time   "mo:core/Time";
import Int    "mo:core/Int";
import Array  "mo:core/Array";
import Result "mo:core/Result";

/// Single-use canister-issued nonces.
///
/// ## Why nonces are canister-issued
///
/// Internet Identity's attribute-bundle protocol bakes the nonce into
/// the signed bundle so the relying-party canister can prove "I started
/// this flow". A frontend-generated nonce gives the canister no way to
/// distinguish a fresh user flow from an attacker replaying or
/// laundering an old bundle. Mint here, store here, consume here.
///
/// ## Memory bounds
///
/// Flat FIFO of `Entry`, capped at `maxTotal`. On overflow the oldest
/// entry is evicted — in legitimate use that's an abandoned flow
/// (someone got a nonce and walked away). Successful `consume` removes
/// the matched entry, so steady-state size tracks abandonment rate.
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

  type Entry = { nonce : Blob; createdAtNs : Nat };

  public type Store = { var entries : [Entry] };

  public type ConsumeError = { #UnknownNonce; #Expired };

  public func empty() : Store { { var entries = [] } };

  /// Mint a fresh 32-byte random nonce, remember it, return it.
  public func issue<system>(store : Store) : async Blob {
    let nonce = await Random.blob();
    let entry = { nonce; createdAtNs = Int.abs(Time.now()) };
    let trimmed = if (store.entries.size() >= maxTotal) {
      Array.sliceToArray<Entry>(store.entries, 1, store.entries.size())
    } else store.entries;
    store.entries := Array.concat(trimmed, [entry]);
    nonce
  };

  /// Find and remove the entry matching `nonce`. Returns `#Expired`
  /// when a match was found but was created more than `maxAgeNs` ago —
  /// the entry is removed in that case too, so a second probe for the
  /// same expired nonce returns `#UnknownNonce` (no oracle).
  public func consume(
    store    : Store,
    nonce    : Blob,
    nowNs    : Nat,
    maxAgeNs : Nat,
  ) : Result.Result<(), ConsumeError> {
    var matchedAtNs : ?Nat = null;
    store.entries := Array.filter<Entry>(store.entries, func entry {
      if (matchedAtNs == null and entry.nonce == nonce) {
        matchedAtNs := ?entry.createdAtNs; false
      } else true
    });
    switch matchedAtNs {
      case null #err(#UnknownNonce);
      case (?createdAt) {
        let age = if (nowNs >= createdAt) (nowNs - createdAt : Nat) else 0;
        if (age > maxAgeNs) #err(#Expired) else #ok
      };
    };
  };

};
