import Random "mo:core/Random";
import Map    "mo:core/Map";
import Blob   "mo:core/Blob";
import Time   "mo:core/Time";
import Int    "mo:core/Int";
import Iter   "mo:core/Iter";
import Result "mo:core/Result";

/// Single-use canister-issued nonces, held in a `Map<Blob, Int>` keyed
/// by nonce bytes with the issue timestamp as the value.
///
/// ## Why nonces are canister-issued
///
/// Internet Identity's attribute-bundle protocol bakes the nonce into
/// the signed bundle so the relying-party canister can prove "I started
/// this flow". A frontend-generated nonce gives the canister no way to
/// distinguish a fresh user flow from an attacker replaying or
/// laundering an old bundle. Mint here, store here, consume here.
///
/// ## Pruning
///
/// `issue` and `consume` both drop entries older than `expiryNs` before
/// touching the store, so memory stays bounded even if no one calls
/// `consume`. On top of that, `issue` evicts the oldest entry when the
/// store is already at `maxTotal` — protects against a runaway frontend
/// minting nonces but never using them.
///
/// The lib doesn't refuse a `consume` on an expired entry — the entry
/// is gone by then and the call returns `#UnknownNonce`, which is what
/// the consumer wants anyway. The bundle's own
/// `implicit:issued_at_timestamp_ns` freshness check in `Verify` is
/// the authoritative stale-bundle gate.
///
/// ## Upgrade behavior
///
/// The store lives inside the `transient` `IdentityAttributesProvider`,
/// so it's recreated empty on every upgrade. In-flight authentications
/// will just need to retry — the `expiryNs` window means anything that
/// would have been redeemable was about to time out anyway.
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

  /// Upper bound on store size before `issue` starts evicting.
  public let maxTotal : Nat = 4096;

  /// Per-entry lifetime. Matches `Verify`'s bundle freshness window —
  /// nothing older than this could be redeemed anyway.
  public let expiryNs : Nat = 300_000_000_000;

  public type Store = Map.Map<Blob, Int>;

  public type ConsumeError = { #UnknownNonce };

  /// Fresh empty store. Use this when constructing the provider.
  public func empty() : Store = Map.empty<Blob, Int>();

  /// Mint a fresh 32-byte random nonce, prune expired entries, evict
  /// the oldest entry if the store is already at capacity, then add
  /// the new nonce with the current timestamp. Returns the nonce.
  public func issue<system>(store : Store) : async Blob {
    let nonce = await Random.blob();
    let nowNs = Int.abs(Time.now());
    pruneExpired(store, nowNs);
    if (Map.size(store) >= maxTotal) {
      evictOldest(store);
    };
    Map.add(store, Blob.compare, nonce, nowNs);
    nonce
  };

  /// Prune expired entries, then look up `nonce` and remove it in one
  /// shot. Returns `#err(#UnknownNonce)` if the entry isn't present —
  /// either it was never issued by this canister, was already
  /// consumed, or expired and got pruned.
  public func consume(store : Store, nonce : Blob) : Result.Result<(), ConsumeError> {
    let nowNs = Int.abs(Time.now());
    pruneExpired(store, nowNs);
    switch (Map.take(store, Blob.compare, nonce)) {
      case (?_) #ok;
      case null #err(#UnknownNonce);
    }
  };

  // Drop every entry whose age exceeds `expiryNs`. Two-pass because
  // `mo:core/Map` doesn't expose an in-place filter — collect the
  // expired keys first, then remove them.
  func pruneExpired(store : Store, nowNs : Int) {
    let expired = Iter.toArray(
      Iter.map<(Blob, Int), Blob>(
        Iter.filter<(Blob, Int)>(
          Map.entries(store),
          func((_, issuedAt)) = nowNs - issuedAt > expiryNs,
        ),
        func((nonce, _)) = nonce,
      )
    );
    for (nonce in expired.vals()) {
      Map.remove(store, Blob.compare, nonce);
    };
  };

  // Remove the entry with the smallest `issuedAt`. Linear scan — only
  // happens on `issue` when the store is at `maxTotal`, so the cost is
  // bounded by `maxTotal` and only hit in degenerate cases.
  func evictOldest(store : Store) {
    var oldest : ?(Blob, Int) = null;
    for (entry in Map.entries(store)) {
      switch oldest {
        case null oldest := ?entry;
        case (?(_, oldT)) if (entry.1 < oldT) oldest := ?entry;
      };
    };
    switch oldest {
      case (?(nonce, _)) Map.remove(store, Blob.compare, nonce);
      case null {};
    };
  };

};
