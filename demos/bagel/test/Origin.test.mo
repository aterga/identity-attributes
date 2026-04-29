import Origin "../src/Origin";
import Debug  "mo:core/Debug";

/// Unit tests for `Origin.remapToLegacyDomain` — the canister-side
/// mirror of II's `remapToLegacyDomain` (in
/// `dfinity/internet-identity:src/frontend/src/lib/utils/iiConnection.ts`).
///
/// Run with `mops test` from `demos/bagel/`.

func assertEq(name : Text, got : Text, expected : Text) {
  if (got != expected) {
    Debug.print("FAIL: " # name);
    Debug.print("  got     : " # got);
    Debug.print("  expected: " # expected);
    assert false;
  };
};

do {
  // The actual production case — bagel's frontend on icp0.io. This is
  // exactly the input the deployed canister has to remap.
  assertEq(
    "remap bagel_frontend canister id from icp0.io",
    Origin.remapToLegacyDomain("https://ufh7l-hiaaa-aaaad-agnza-cai.icp0.io"),
    "https://ufh7l-hiaaa-aaaad-agnza-cai.ic0.app",
  );

  // Generic canister id form.
  assertEq(
    "remap a different canister id",
    Origin.remapToLegacyDomain("https://aaaaa-aa.icp0.io"),
    "https://aaaaa-aa.ic0.app",
  );

  // The `.raw` subdomain — the regex in iiConnection.ts allows it.
  assertEq(
    "remap with .raw subdomain",
    Origin.remapToLegacyDomain("https://ufh7l-hiaaa-aaaad-agnza-cai.raw.icp0.io"),
    "https://ufh7l-hiaaa-aaaad-agnza-cai.raw.ic0.app",
  );

  // Already on the legacy domain — pass through unchanged.
  assertEq(
    "passthrough already-legacy ic0.app",
    Origin.remapToLegacyDomain("https://ufh7l-hiaaa-aaaad-agnza-cai.ic0.app"),
    "https://ufh7l-hiaaa-aaaad-agnza-cai.ic0.app",
  );

  // Custom domain — no remap.
  assertEq(
    "passthrough custom domain",
    Origin.remapToLegacyDomain("https://app.example.com"),
    "https://app.example.com",
  );

  // Wrong scheme — pass through (II's own remap requires https).
  assertEq(
    "passthrough http (not https)",
    Origin.remapToLegacyDomain("http://ufh7l-hiaaa-aaaad-agnza-cai.icp0.io"),
    "http://ufh7l-hiaaa-aaaad-agnza-cai.icp0.io",
  );

  // Different TLD that just happens to contain `.icp0.io` as a suffix —
  // valid match per the regex shape, gets remapped. (Mirrors II.)
  assertEq(
    "remap with all numerals + dashes",
    Origin.remapToLegacyDomain("https://r7inp-6aaaa-aaaaa-aaabq-cai.icp0.io"),
    "https://r7inp-6aaaa-aaaaa-aaabq-cai.ic0.app",
  );

  Debug.print("✓ Origin.remapToLegacyDomain — all cases pass");
};
