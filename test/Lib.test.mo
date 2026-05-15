import II "../src/lib";
import Debug "mo:core/Debug";

do {
  let nonces = II.emptyNonces();
  let provider = II.IdentityAttributesProvider({
    origin = "https://example.com";
    nonces;
  });

  ignore provider.createNonce;
  ignore provider.getVerifiedAttributes;

  let _e : II.Error = #NoAttributes;
  ignore _e;

  Debug.print("Lib.test.mo ok");
};
