import Challenges "../src/Internal/Challenges";
import Debug "mo:core/Debug";

do {
  let store = Challenges.empty();

  // `consume` against an empty store: unknown.
  switch (Challenges.consume(store, "alpha" : Blob)) {
    case (#err(#UnknownNonce)) {};
    case _                     assert false;
  };

  // Pre-load entries (mirroring what `issue` does internally).
  store.entries := ["n1" : Blob, "n2" : Blob];

  // Wrong nonce → no match; entries unchanged.
  switch (Challenges.consume(store, "missing" : Blob)) {
    case (#err(#UnknownNonce)) {};
    case _                     assert false;
  };
  assert store.entries.size() == 2;

  // Right nonce → ok; entry removed.
  switch (Challenges.consume(store, "n1" : Blob)) {
    case (#ok) {};
    case _     assert false;
  };
  assert store.entries.size() == 1;

  // Same nonce again → unknown (already consumed).
  switch (Challenges.consume(store, "n1" : Blob)) {
    case (#err(#UnknownNonce)) {};
    case _                     assert false;
  };

  Debug.print("Challenges.test.mo ok");
};
