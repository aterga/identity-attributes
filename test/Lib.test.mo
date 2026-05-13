import II "../src/lib";
import Debug "mo:core/Debug";

do {
  let verifier = II.Verifier({ origin = "https://example.com" });

  ignore verifier.verify;
  ignore verifier.nonce;

  let _e : II.Error = #NoAttributes;
  ignore _e;

  Debug.print("Lib.test.mo ok");
};
