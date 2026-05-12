import II "../src/lib";
import Debug "mo:core/Debug";

do {
  let store = II.newStore();
  let ii    = II.Verifier(store);
  ignore ii.verify;
  ignore ii.issueNonce;
  ignore II.defaultMaxAgeNs;

  let _p : II.OpenIdProvider = #Google;
  ignore _p;

  let _c : II.Config = {
    origin         = "https://example.com";
    maxAgeNs       = null;
    action         = "test";
    openIdProvider = null;
  };
  ignore _c;

  Debug.print("Lib.test.mo ok");
};
