import { IdentityAttributesProvider; type IdentityAttributesError } "../src/lib";
import Queue "mo:core/Queue";
import Debug "mo:core/Debug";

do {
  let nonces = Queue.empty<Blob>();
  let identityAttributesProvider = IdentityAttributesProvider({
    origin = "https://example.com";
    nonces;
  });

  ignore identityAttributesProvider.nonce;
  ignore identityAttributesProvider.get;

  let _e : IdentityAttributesError = #NoAttributes;
  ignore _e;

  Debug.print("Lib.test.mo ok");
};
