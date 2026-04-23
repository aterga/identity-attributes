// Imports the umbrella lib.mo to force type-checking of every module
// (Value, Attributes, Implicit, Challenges, Verify). Without this,
// `mops test` only exercises what the explicit test files happen to
// import, and an unrelated type error in e.g. Verify.mo would ship.
import II "../src/lib";
import Debug "mo:core/Debug";

do {
  let store : II.Store = II.emptyStore();
  ignore store;
  ignore II.verify;
  ignore II.origin;
  ignore II.issuedAtNs;
  ignore II.nonce;
  ignore II.decode;
  ignore II.fromValue;
  Debug.print("Lib.test.mo ok");
};
