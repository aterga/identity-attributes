import II         "mo:identity-attributes";
import Challenges "mo:identity-attributes/Challenges";
import Map        "mo:core/Map";
import Principal  "mo:core/Principal";
import Text       "mo:core/Text";
import Iter       "mo:core/Iter";
import Result     "mo:core/Result";

/// Bagel — a pairs-you-for-coffee demo, gated to @dfinity.org users via
/// Internet Identity certified attributes.
///
/// Protocol sketch (see the demo README for the full story):
///   1. Frontend calls `generate_nonce()` → 32-byte nonce.
///   2. Frontend opens II with `requestAttributes({ keys: ["email"], nonce })`.
///   3. Frontend wraps the returned `SignedAttributes` into an
///      `AttributesIdentity` and calls `join_round()`.
///   4. Canister verifies (Authorization tier — origin + freshness + nonce),
///      reads `email`, checks the @dfinity.org suffix, and either pairs the
///      caller with someone already waiting or puts them on the pool.
///   5. Caller polls `my_match()` to discover their coffee partner's email.
persistent actor Bagel {

  let rpOrigin : Text        = "https://ufh7l-hiaaa-aaaad-agnza-cai.icp0.io";
  let nonceTtlNs : Nat       = 5 * 60 * 1_000_000_000;      // 5 min
  let maxAttrAgeNs : Nat     = 5 * 60 * 1_000_000_000;      // 5 min
  let allowedDomain : Text   = "dfinity.org";

  let nonces  = Challenges.empty();
  let pool    = Map.empty<Principal, Text>();
  let matches = Map.empty<Principal, (Principal, Text)>();

  public type JoinOutcome = {
    #Waiting;
    #Paired : { email : Text };
  };

  public type JoinError = {
    #Verify       : II.Error;
    #NoEmail;
    #WrongDomain  : { email : Text };
  };

  /// Step 1 of every round: give the frontend a canister-issued nonce that
  /// will later be matched against `implicit:nonce` in the attribute bundle.
  public shared ({ caller }) func generate_nonce() : async Blob {
    await Challenges.issue<system>(nonces, caller, nonceTtlNs)
  };

  /// Step 3: join (or re-join) the current round. Returns `#Paired` if a
  /// match was made on the spot, `#Waiting` if the caller was added to the
  /// pool.
  public shared ({ caller }) func join_round() : async Result.Result<JoinOutcome, JoinError> {
    let attrs = switch (II.verify<system>({
      policy = #Authorization {
        expectedOrigin = rpOrigin;
        maxAgeNs       = maxAttrAgeNs;
      };
      caller;
      nonces = ?nonces;
    })) {
      case (#err e) { return #err(#Verify e) };
      case (#ok a)  a;
    };

    let ?email = II.getText(attrs, "email") else return #err(#NoEmail);
    if (not isAllowed(email)) return #err(#WrongDomain { email });

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

  /// Leave the waiting pool and drop any existing pairing.
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
