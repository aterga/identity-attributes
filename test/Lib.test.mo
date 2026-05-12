import II "../src/lib";
import Debug "mo:core/Debug";

do {
  let ii = II.Verifier("https://example.com");
  ignore ii.verify;
  ignore ii.issueNonce;

  let _p : II.OpenIdProvider = #Google;
  ignore _p;

  let _c : II.Config = {
    action         = "test";
    openIdProvider = null;
  };
  ignore _c;

  Debug.print("Lib.test.mo ok");
};
