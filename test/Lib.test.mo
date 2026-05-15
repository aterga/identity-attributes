import { IdentityAttributesProvider } "../src/lib";
import IIType "../src/lib";
import List "mo:core/List";
import Debug "mo:core/Debug";

do {
  let nonces = List.empty<Blob>();
  let identityAttributesProvider = IdentityAttributesProvider({
    origin = "https://example.com";
    nonces;
  });

  ignore identityAttributesProvider.createNonce;
  ignore identityAttributesProvider.getVerifiedAttributes;

  let _e : IIType.Error = #NoAttributes;
  ignore _e;

  Debug.print("Lib.test.mo ok");
};
