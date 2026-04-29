import Text "mo:core/Text";

/// Helpers for resolving the relying-party origin we expect to see in
/// the bundle's `implicit:origin`. II rewrites the new `<id>.icp0.io`
/// domain to the legacy `<id>.ic0.app` for principal-derivation
/// stability across the two domains, so the canister has to do the
/// same remap on its expected origin to compare apples to apples.
module {

  /// Mirror of II's `remapToLegacyDomain` from
  /// dfinity/internet-identity:src/frontend/src/lib/utils/iiConnection.ts:998.
  /// Rewrites `https://<sub>.icp0.io` → `https://<sub>.ic0.app` (with
  /// optional `.raw`). Anything that doesn't match the icp0.io shape
  /// passes through unchanged.
  public func remapToLegacyDomain(origin : Text) : Text {
    let prefix = "https://";
    let suffix = ".icp0.io";
    if (not Text.startsWith(origin, #text prefix)) { return origin };
    if (not Text.endsWith(origin, #text suffix))   { return origin };
    let withoutPrefix = Text.trimStart(origin, #text prefix);
    let subdomain     = Text.trimEnd(withoutPrefix, #text suffix);
    if (subdomain == "") { return origin };
    prefix # subdomain # ".ic0.app"
  };
}
