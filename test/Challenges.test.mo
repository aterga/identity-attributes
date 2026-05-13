import Challenges "../src/Internal/Challenges";
import Debug "mo:core/Debug";

do {
  let s = Challenges.empty();

  // We can't call `issue` directly here (it needs `<system>` and is
  // async). Drive `consume` via the public API and pre-load the store
  // to exercise the match path synchronously.

  // Empty store: unknown.
  switch (Challenges.consume(s, "alpha" : Blob, 0, 1_000_000)) {
    case (#err(#UnknownNonce)) {};
    case _                     assert false;
  };

  // Pre-load entries (mirroring what `issue` does internally).
  s.entries := [
    { nonce = "n1" : Blob; createdAtNs = 1_000 },
    { nonce = "n2" : Blob; createdAtNs = 1_000 },
  ];

  // Wrong nonce → no match; entries unchanged.
  switch (Challenges.consume(s, "missing" : Blob, 2_000, 10_000)) {
    case (#err(#UnknownNonce)) {};
    case _                     assert false;
  };
  assert s.entries.size() == 2;

  // Right nonce → ok; entry removed.
  switch (Challenges.consume(s, "n1" : Blob, 2_000, 10_000)) {
    case (#ok) {};
    case _     assert false;
  };
  assert s.entries.size() == 1;

  // Same nonce again → unknown (already consumed).
  switch (Challenges.consume(s, "n1" : Blob, 2_000, 10_000)) {
    case (#err(#UnknownNonce)) {};
    case _                     assert false;
  };

  // Stale: re-inject and consume past `maxAgeNs`. Expired entries are
  // removed too — probing again returns `#UnknownNonce`.
  s.entries := [{ nonce = "n3" : Blob; createdAtNs = 1_000 }];
  switch (Challenges.consume(s, "n3" : Blob, 100_000, 10_000)) {
    case (#err(#Expired)) {};
    case _                assert false;
  };
  assert s.entries.size() == 0;
  switch (Challenges.consume(s, "n3" : Blob, 100_000, 10_000)) {
    case (#err(#UnknownNonce)) {};
    case _                     assert false;
  };

  Debug.print("Challenges.test.mo ok");
};
