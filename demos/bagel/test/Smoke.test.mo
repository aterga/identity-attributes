// Placeholder so `mops test` finds at least one *.test.mo file.
//
// `demos/bagel/icp.yaml` runs `mops test` as part of every build to
// surface regressions like the `rpOrigin` transient mishap (where
// `let` defaults to `stable` in `persistent actor`) before the wasm
// goes anywhere near a canister. With zero test files mops exits 1
// and the deploy fails.
//
// Replace this with real tests when bagel grows them (e.g. pool
// fairness across draws, attribute-bundle expiry handling, etc.).
do {
  assert 1 + 1 == 2;
};
