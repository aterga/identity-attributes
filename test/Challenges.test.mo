import Challenges "../src/Internal/Challenges";
import List "mo:core/List";
import Debug "mo:core/Debug";

do {
  let store = List.empty<Blob>();

  // Empty store: unknown.
  switch (Challenges.consume(store, "alpha" : Blob)) {
    case (#err(#UnknownNonce)) {};
    case _                     assert false;
  };

  // Pre-load entries.
  List.add(store, "n1" : Blob);
  List.add(store, "n2" : Blob);

  // Wrong nonce → no match; entries unchanged.
  switch (Challenges.consume(store, "missing" : Blob)) {
    case (#err(#UnknownNonce)) {};
    case _                     assert false;
  };
  assert List.size(store) == 2;

  // Right nonce → ok; entry removed.
  switch (Challenges.consume(store, "n1" : Blob)) {
    case (#ok) {};
    case _     assert false;
  };
  assert List.size(store) == 1;

  // Same nonce again → unknown (already consumed).
  switch (Challenges.consume(store, "n1" : Blob)) {
    case (#err(#UnknownNonce)) {};
    case _                     assert false;
  };

  Debug.print("Challenges.test.mo ok");
};
