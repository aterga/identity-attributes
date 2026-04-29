import II         "mo:identity-attributes";
import Challenges "mo:identity-attributes/Challenges";
import Map        "mo:core/Map";
import Principal  "mo:core/Principal";
import Text       "mo:core/Text";
import Iter       "mo:core/Iter";
import Result     "mo:core/Result";
import Origin     "./Origin";

/// Bagel — a pairs-you-for-coffee demo, gated to @dfinity.org users via
/// Internet Identity certified attributes.
///
/// Protocol sketch (see the demo README for the full story):
///   1. Frontend calls `generate_nonce()` (anonymously, on page load) →
///      32-byte nonce.
///   2. Frontend opens II with `requestAttributes({ keys: [...], nonce })`.
///   3. Frontend wraps the returned `SignedAttributes` into an
///      `AttributesIdentity` and calls `register()`. The canister verifies
///      the bundle (Authorization tier — origin + freshness + nonce),
///      reads `email`, checks the @dfinity.org suffix, and remembers the
///      caller's principal in `registered`. From that point on the caller
///      is a known DFINITY employee — subsequent calls don't need the
///      bundle attached, the principal alone is sufficient.
///   4. Frontend uses a *plain* DelegationIdentity (no AttributesIdentity
///      wrap, no `sender_info` on the wire) to call `join_round()`. The
///      canister just looks the caller up in `registered` and either
///      pairs them with someone already waiting or puts them on the pool.
///   5. Caller polls `my_match()` to discover their coffee partner's email.
///
/// Nonce principal note:
/// `Challenges.Store` is keyed by `Principal`, but we don't want the nonce
/// to be tied to a specific caller — the frontend pre-fetches it on page
/// load (before sign-in, so with an anonymous agent), then the *authenticated*
/// agent consumes it via `register`. To make lookup symmetric we issue
/// *and* consume under `Principal.anonymous()` — see `anonNonceKey` below.
/// Replay is still prevented because:
///   (a) the nonce is single-use (`Challenges.consume` removes on match),
///   (b) the II signature binds the nonce to the delegated user, so an
///       attacker can't reuse someone else's bundle.
persistent actor Bagel {

  // The canonical origin where this app is hosted — the new `.icp0.io`
  // domain. Both `<id>.icp0.io` and the legacy `<id>.ic0.app` URLs
  // serve the same asset canister, but II's `remapToLegacyDomain`
  // rewrites `.icp0.io` → `.ic0.app` for principal stability. Whatever
  // URL the user actually loaded the page from, II will attest to the
  // `.ic0.app` form in the bundle's `implicit:origin`. We feed our
  // canonical origin through the same remap so `expectedOrigin`
  // matches what II actually puts in the bundle.
  //
  // `transient` is critical here — in a `persistent actor`, regular
  // `let` bindings are evaluated on the *initial* install only, and
  // their values are preserved across upgrades. We changed the
  // expected-origin form after the canister was first deployed, but
  // the upgrade kept the original `icp0.io` value, which is why earlier
  // attempts kept failing with `OriginMismatch`. `transient` re-evaluates
  // the right-hand side on every upgrade, so source-level changes
  // actually take effect.
  transient let rpOriginCanonical : Text = "https://ufh7l-hiaaa-aaaad-agnza-cai.icp0.io";
  transient let rpOrigin : Text          = Origin.remapToLegacyDomain(rpOriginCanonical);
  transient let nonceTtlNs : Nat         = 5 * 60 * 1_000_000_000;      // 5 min
  transient let maxAttrAgeNs : Nat       = 5 * 60 * 1_000_000_000;      // 5 min
  transient let allowedDomain : Text     = "dfinity.org";

  // Nonces are canister-global (see module doc) — stored under and
  // consumed against the anonymous principal, regardless of who's calling.
  let anonNonceKey = Principal.anonymous();

  let nonces     = Challenges.empty();
  // Principals known to belong to DFINITY employees, populated by
  // `register()` after the bundle has been fully verified. Subsequent
  // calls (join_round, reset) just look up against this map — no
  // sender_info on the wire required, just the delegation principal.
  let registered = Map.empty<Principal, Text>();
  let pool       = Map.empty<Principal, Text>();
  let matches    = Map.empty<Principal, (Principal, Text)>();

  public type JoinOutcome = {
    #Waiting;
    #Paired : { email : Text };
  };

  public type RegisterError = {
    #Verify       : II.Error;
    #NoEmail;
    #WrongDomain  : { email : Text };
  };

  public type JoinError = {
    #NotRegistered;
  };

  /// Step 1: give the frontend a canister-issued nonce that will later
  /// be matched against `implicit:nonce` in the attribute bundle. Safe
  /// to call anonymously — the frontend fetches this on page load,
  /// before the user signs in with II. The nonce is stored globally
  /// (see module doc) so the authenticated consumer can still find it.
  public func generate_nonce() : async Blob {
    await Challenges.issue<system>(nonces, anonNonceKey, nonceTtlNs)
  };

  /// Step 3: verify the attribute bundle and register the caller as a
  /// known DFINITY employee. The frontend calls this *immediately* after
  /// sign-in (with an `AttributesIdentity`-wrapped agent so `sender_info`
  /// rides on the ingress message). On success the caller's principal
  /// is added to `registered` and `join_round()` will accept them; on
  /// failure the canister won't remember the principal and `join_round`
  /// responds with `#NotRegistered`.
  ///
  /// Idempotent: re-registering with a fresh bundle just overwrites the
  /// stored email (e.g. the user signed in to a different II anchor).
  public shared ({ caller }) func register() : async Result.Result<{ email : Text }, RegisterError> {
    let attrs = switch (II.verify<system>({
      policy = #Authorization {
        // `rpOrigin` is the legacy-domain form (see remapToLegacyDomain
        // above) — matches what II actually attests to in the bundle.
        expectedOrigin = rpOrigin;
        maxAgeNs       = maxAttrAgeNs;
      };
      // `caller` in the verify config is used *only* to look up the nonce
      // in the store; everything else (origin, freshness, attribute decode)
      // is caller-agnostic. We pass `anonNonceKey` to match how
      // `generate_nonce` issued it.
      caller = anonNonceKey;
      nonces = ?nonces;
    })) {
      case (#err e) { return #err(#Verify e) };
      case (#ok a)  a;
    };

    let ?email = II.getText(attrs, "email") else return #err(#NoEmail);
    if (not isAllowed(email)) return #err(#WrongDomain { email });

    Map.add(registered, Principal.compare, caller, email);
    #ok({ email })
  };

  /// Step 4: join (or re-join) the current round. The caller must have
  /// already called `register()` with a valid bundle in this canister's
  /// lifetime; otherwise `#NotRegistered`. No bundle re-verification —
  /// holding the delegation for a registered principal is sufficient
  /// proof that this is the same person we already vetted.
  public shared ({ caller }) func join_round() : async Result.Result<JoinOutcome, JoinError> {
    let ?email = Map.get(registered, Principal.compare, caller) else return #err(#NotRegistered);

    switch (Map.get(matches, Principal.compare, caller)) {
      case (?(_, partnerEmail)) { return #ok(#Paired { email = partnerEmail }) };
      case null {};
    };

    switch (pickPartner(caller)) {
      case (?(partner, partnerEmail)) {
        Map.remove(pool, Principal.compare, partner);
        Map.add(matches, Principal.compare, caller,  (partner, partnerEmail));
        Map.add(matches, Principal.compare, partner, (caller,  email));
        #ok(#Paired { email = partnerEmail })
      };
      case null {
        Map.add(pool, Principal.compare, caller, email);
        #ok(#Waiting)
      };
    };
  };

  /// Step 5: look up the caller's match (if any).
  public shared query ({ caller }) func my_match() : async ?Text {
    switch (Map.get(matches, Principal.compare, caller)) {
      case (?(_, email)) ?email;
      case null          null;
    };
  };

  /// Leave the waiting pool and drop any existing pairing. Doesn't
  /// un-register — the principal stays known until the canister is
  /// reset, so the caller can re-join without going through II again.
  public shared ({ caller }) func reset() : async () {
    Map.remove(pool, Principal.compare, caller);
    switch (Map.take(matches, Principal.compare, caller)) {
      case null {};
      case (?(partner, _)) {
        Map.remove(matches, Principal.compare, partner);
      };
    };
  };

  /// Size of the current waiting pool — handy for a dashboard.
  public query func pool_size() : async Nat {
    Map.size(pool)
  };

  // ---------------------------------------------------------------------- //
  // Internals
  // ---------------------------------------------------------------------- //

  func isAllowed(email : Text) : Bool {
    let parts = Iter.toArray(Text.split(email, #char '@'));
    parts.size() == 2 and parts[1] == allowedDomain
  };

  func pickPartner(excluding : Principal) : ?(Principal, Text) {
    for ((p, e) in Map.entries(pool)) {
      if (p != excluding) { return ?(p, e) };
    };
    null
  };
};
