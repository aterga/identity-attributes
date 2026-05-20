// Workaround for `mops test` failing with "No test files found" when a
// package has zero `*.test.mo` files.
//
// `demos/bagel/icp.yaml` runs `mops test` as part of every build. If
// the directory is empty, mops exits 1 and the build fails. This file
// exists solely to give mops something to find — it does not exercise
// any bagel canister code (no import of `Main.mo`, no actor
// instantiation), so a regression in the backend wouldn't be caught
// here. Replace it with real tests when bagel grows them (pool
// fairness across draws, attribute-bundle expiry handling, etc.).
do {
  assert 1 + 1 == 2;
};
