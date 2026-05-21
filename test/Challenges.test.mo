import Challenges "../src/Internal/Challenges";
import Map "mo:core/Map";
import Blob "mo:core/Blob";
import Time "mo:core/Time";
import Debug "mo:core/Debug";

do {
  let store = Challenges.empty();

  // Empty store: unknown.
  switch (Challenges.consume(store, "alpha" : Blob)) {
    case (#err(#UnknownNonce)) {};
    case _ assert false
  };

  // Pre-load with the runtime clock so `pruneExpired` (inside
  // `consume`) leaves them alone — anything dated within the last
  // 5 minutes survives.
  let now = Time.now();
  Map.add(store, Blob.compare, ("n1" : Blob), now);
  Map.add(store, Blob.compare, ("n2" : Blob), now);
  assert Map.size(store) == 2;

  // Wrong nonce → no match; entries unchanged.
  switch (Challenges.consume(store, "missing" : Blob)) {
    case (#err(#UnknownNonce)) {};
    case _ assert false
  };
  assert Map.size(store) == 2;

  // Right nonce → ok; entry removed.
  switch (Challenges.consume(store, "n1" : Blob)) {
    case (#ok) {};
    case _ assert false
  };
  assert Map.size(store) == 1;

  // Same nonce again → unknown (already consumed).
  switch (Challenges.consume(store, "n1" : Blob)) {
    case (#err(#UnknownNonce)) {};
    case _ assert false
  };

  // Stale entry (issued well before the 5-minute window) gets pruned
  // on the next `consume`, regardless of whether the nonce being
  // consumed matches it.
  let stale = Challenges.empty();
  let stalePast : Int = now - 10 * 60 * 1_000_000_000; // 10 minutes ago
  Map.add(stale, Blob.compare, ("old" : Blob), stalePast);
  Map.add(stale, Blob.compare, ("fresh" : Blob), now);
  switch (Challenges.consume(stale, "fresh" : Blob)) {
    case (#ok) {};
    case _ assert false
  };
  // "fresh" was just consumed; "old" was pruned. Store is empty.
  assert Map.size(stale) == 0;

  Debug.print("Challenges.test.mo ok")
}
