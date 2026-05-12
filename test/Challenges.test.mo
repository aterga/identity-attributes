import Challenges "../src/Internal/Challenges";
import Debug "mo:core/Debug";

do {
  let s = Challenges.empty();

  // We can't call `issue` directly here (it needs `<system>` and is
  // async). Drive consume via the public API and inject store rows
  // directly to exercise lookup/match/expiry.

  // `consume` against an empty store: unknown.
  switch (Challenges.consume(s, "register", "alpha" : Blob, 0, 1_000_000)) {
    case (#err(#UnknownNonce)) {};
    case (_)                   assert false;
  };

  // The intern table fills as actions are seen.
  ignore Challenges.consume(s, "linkAccount", "alpha" : Blob, 0, 1_000_000);
  assert s.actions.size() == 2;

  // Pre-load entries (mirror what `issue` does) so we can exercise the
  // match path synchronously.
  s.entries := [
    { actionId = 0; nonce = "n1" : Blob; createdAtNs = 1_000 },
    { actionId = 1; nonce = "n2" : Blob; createdAtNs = 1_000 },
  ];

  // Wrong action → no match; entries unchanged.
  switch (Challenges.consume(s, "register", "n2" : Blob, 2_000, 10_000)) {
    case (#err(#UnknownNonce)) {};
    case _                     assert false;
  };
  assert s.entries.size() == 2;

  // Right (action, nonce) → ok; entry removed.
  switch (Challenges.consume(s, "register", "n1" : Blob, 2_000, 10_000)) {
    case (#ok) {};
    case _     assert false;
  };
  assert s.entries.size() == 1;

  // Same nonce again → unknown (already consumed).
  switch (Challenges.consume(s, "register", "n1" : Blob, 2_000, 10_000)) {
    case (#err(#UnknownNonce)) {};
    case _                     assert false;
  };

  // Stale: re-inject and consume past `maxAgeNs`. Expired entries are
  // removed too — probing again returns `#UnknownNonce`.
  s.entries := [{ actionId = 0; nonce = "n3" : Blob; createdAtNs = 1_000 }];
  switch (Challenges.consume(s, "register", "n3" : Blob, 100_000, 10_000)) {
    case (#err(#Expired)) {};
    case _                assert false;
  };
  assert s.entries.size() == 0;
  switch (Challenges.consume(s, "register", "n3" : Blob, 100_000, 10_000)) {
    case (#err(#UnknownNonce)) {};
    case _                     assert false;
  };

  Debug.print("Challenges.test.mo ok");
};
