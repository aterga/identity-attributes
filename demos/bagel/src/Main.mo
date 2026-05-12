import II         "mo:identity-attributes";
import Map        "mo:core/Map";
import Principal  "mo:core/Principal";
import Text       "mo:core/Text";
import Iter       "mo:core/Iter";
import Result     "mo:core/Result";

/// Bagel — a pairs-you-for-coffee demo, gated to @dfinity.org users via
/// Internet Identity certified attributes.
///
/// Protocol sketch (see the demo README for the full story):
///   1. Frontend calls `generate_nonce()` (anonymously, on page load) →
///      32-byte nonce.
///   2. Frontend opens II with `requestAttributes({ keys: [...], nonce })`.
///   3. Frontend wraps the returned `SignedAttributes` into an
///      `AttributesIdentity` and calls `register()`. The canister verifies
///      the bundle (origin + freshness + nonce, all enforced by
///      `mo:identity-attributes/verify`), reads `email`, checks the
///      @dfinity.org suffix, and remembers the caller's principal in
///      `registered`. From that point on the caller is a known DFINITY
///      employee — subsequent calls don't need the bundle attached, the
///      principal alone is sufficient.
///   4. Frontend uses a *plain* DelegationIdentity (no AttributesIdentity
///      wrap, no `sender_info` on the wire) to call `join_round()`. The
///      canister just looks the caller up in `registered` and either
///      pairs them with someone already waiting or puts them on the pool.
///   5. Caller polls `my_match()` to discover their coffee partner's email.
///
/// Nonces are tagged with the `"register"` action label. The lib's nonce
/// store is shared across actions but lookups are scoped by tag, so a
/// nonce issued under one action cannot be redeemed against another.
/// Cross-user replay is prevented by the II signature in the bundle:
/// a stolen nonce only works alongside a bundle signed *for the caller*
/// of register — an attacker who steals one ends up registering themselves.
persistent actor Bagel {

  // The origin where this app is hosted. As of the latest II release,
  // II puts this canonical `.icp0.io` form into the bundle's
  // `implicit:origin` regardless of which domain the user actually
  // loaded the page from.
  //
  // `transient` is critical — in a `persistent actor`, regular `let`
  // bindings are evaluated on the *initial* install only, and their
  // values are preserved across upgrades. `transient` re-evaluates the
  // right-hand side on every upgrade so source-level changes actually
  // take effect.
  transient let rpOrigin : Text       = "https://ufh7l-hiaaa-aaaad-agnza-cai.icp0.io";
  transient let allowedDomain : Text  = "dfinity.org";
  transient let registerAction : Text = "register";

  transient let ii = II.Verifier();
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
  /// before the user signs in with II.
  public func generate_nonce() : async Blob {
    await ii.issueNonce<system>(registerAction)
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
    let result = switch (ii.verify<system>({
      origin         = rpOrigin;
      action         = registerAction;
      // The frontend requests the custom-scoped `sso:dfinity.org:email`
      // key, which is outside the lib's typed `OpenIdProvider` surface.
      // Leave the typed slot empty and read the email via the escape
      // hatch below.
      openIdProvider = null;
    })) {
      case (#err e) { return #err(#Verify e) };
      case (#ok r)  r;
    };

    let ?email = result.attributes.getText("sso:dfinity.org:email") else return #err(#NoEmail);
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
  ///
  /// When the caller is currently paired, the *partner* gets returned
  /// to `pool` (with their email re-attached) instead of being stranded
  /// in a "floating" state where they're neither paired nor waiting.
  /// They didn't choose to leave, so we let them be picked up by the
  /// next arrival without requiring any action on their end. Their UI
  /// may continue to show a stale "Paired with <caller>" until they
  /// navigate away or re-Join, but the canister state is consistent
  /// and a re-arriving caller (or any other DFINITY human) will
  /// re-pair with them seamlessly.
  public shared ({ caller }) func reset() : async () {
    Map.remove(pool, Principal.compare, caller);
    switch (Map.take(matches, Principal.compare, caller)) {
      case null {};
      case (?(partner, partnerEmail)) {
        Map.remove(matches, Principal.compare, partner);
        Map.add(pool, Principal.compare, partner, partnerEmail);
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
