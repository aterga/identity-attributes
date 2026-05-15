import IdentityAttributesProvider "../src/lib";
import Debug "mo:core/Debug";

do {
  let nonces = IdentityAttributesProvider.emptyNonces();
  ignore nonces;
  ignore IdentityAttributesProvider.createNonce;
  ignore IdentityAttributesProvider.getVerifiedAttributes;

  let _e : IdentityAttributesProvider.Error = #NoAttributes;
  ignore _e;

  Debug.print("Lib.test.mo ok");
};
