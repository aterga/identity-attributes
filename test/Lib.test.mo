import II "../src/lib";
import Debug "mo:core/Debug";

do {
  // Type-check the public surface in one place so a regression in any
  // internal module is caught at the umbrella level.
  let store : II.Store = II.newStore();
  ignore store;
  ignore II.verify;
  ignore II.issueNonce;
  ignore II.defaultMaxAgeNs;

  let _p : II.OpenIdProvider = #Google;
  ignore _p;

  let _c : II.Config = {
    origin         = "https://example.com";
    maxAgeNs       = null;
    nonces         = store;
    action         = "test";
    openIdProvider = null;
  };
  ignore _c;

  Debug.print("Lib.test.mo ok");
};
