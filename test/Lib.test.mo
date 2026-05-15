import IdentityAttributesProvider "../src/lib";
import Debug "mo:core/Debug";

do {
  let nonces : IdentityAttributesProvider.Nonces = { var entries = [] };
  let provider = IdentityAttributesProvider.IdentityAttributesProvider({
    origin = "https://example.com";
    nonces;
  });

  ignore provider.createNonce;
  ignore provider.getVerifiedAttributes;

  let _e : IdentityAttributesProvider.Error = #NoAttributes;
  ignore _e;

  Debug.print("Lib.test.mo ok");
};
