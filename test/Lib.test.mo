// Imports the umbrella lib.mo to force type-checking of every module
// (Value, Attributes, Challenges, Verify). Without this, `mops test`
// would only exercise what the explicit test files happen to import,
// and a type error in e.g. Verify.mo could ship.
import II "../src/lib";
import Attributes "../src/Attributes";
import Challenges "../src/Challenges";
import Debug "mo:core/Debug";

do {
  let store : II.Store = Challenges.empty();
  ignore store;
  ignore II.verify;
  ignore II.asProvider;
  ignore II.defaultMaxAgeNs;

  // Verified type shape
  let _v : II.Verified = {
    name       = ?"Alice";
    email      = ?"alice@gmail.com";
    attributes = Attributes.Attributes([]);
  };

  // OpenIdProvider type shape
  let _p : II.OpenIdProvider = #Google;
  ignore _p;

  // Config type shape
  let _c : II.Config = {
    origins        = ["https://example.com"];
    maxAgeNs       = null;
    nonces         = store;
    action         = "test";
    openIdProvider = null;
  };
  ignore _c;

  Debug.print("Lib.test.mo ok");
};
