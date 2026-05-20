import Attributes "../src/Internal/Attributes";
import Debug "mo:core/Debug";
import Runtime "mo:core/Runtime";

do {
  // ---- Case 1: unscoped `name` only; `verified_email` only ----

  let unscoped = Attributes.Attributes([
    ("name",           #Text "Alice"),
    ("email",          #Text "alice@example.com"),    // unverified, ignored
    ("verified_email", #Text "alice@verified.com"),
  ]);

  let #ok v1 = Attributes.asIdentityAttributes(unscoped, []) else Runtime.trap("expected ok");
  assert v1.name  == ?"Alice";
  assert v1.email == ?"alice@verified.com";
  assert v1.sso   == null;

  // ---- Case 2: one openid scope only ----

  let googleOnly = Attributes.Attributes([
    ("openid:https://accounts.google.com:name",           #Text "Alice G"),
    ("openid:https://accounts.google.com:email",          #Text "alice@gmail.com"),     // ignored
    ("openid:https://accounts.google.com:verified_email", #Text "alice@gmail.com"),
  ]);

  let #ok v2 = Attributes.asIdentityAttributes(googleOnly, []) else Runtime.trap("expected ok");
  assert v2.name  == ?"Alice G";
  assert v2.email == ?"alice@gmail.com";
  assert v2.sso   == null;

  // ---- Case 3: no source for either field → nulls ----

  let neither = Attributes.Attributes([
    ("email", #Text "alice@example.com"),  // unverified-only doesn't count
  ]);

  let #ok v3 = Attributes.asIdentityAttributes(neither, []) else Runtime.trap("expected ok");
  assert v3.name  == null;
  assert v3.email == null;
  assert v3.sso   == null;

  // ---- Case 4: ambiguous `name` (unscoped + google) ----

  let ambiguousName = Attributes.Attributes([
    ("name",                                    #Text "Alice"),
    ("openid:https://accounts.google.com:name", #Text "Alice G"),
    ("verified_email",                          #Text "alice@verified.com"),
  ]);

  switch (Attributes.asIdentityAttributes(ambiguousName, [])) {
    case (#err(#AmbiguousAttribute { field; sources })) {
      assert field == "name";
      assert sources == ["name", "openid:https://accounts.google.com:name"];
    };
    case _ Runtime.trap("expected #AmbiguousAttribute for ambiguous name");
  };

  // ---- Case 5: ambiguous `email` across two providers ----

  let ambiguousEmail = Attributes.Attributes([
    ("openid:https://accounts.google.com:verified_email", #Text "alice@gmail.com"),
    ("openid:https://appleid.apple.com:verified_email",   #Text "alice@icloud.com"),
  ]);

  switch (Attributes.asIdentityAttributes(ambiguousEmail, [])) {
    case (#err(#AmbiguousAttribute { field; sources })) {
      assert field == "email";
      assert sources == [
        "openid:https://accounts.google.com:verified_email",
        "openid:https://appleid.apple.com:verified_email",
      ];
    };
    case _ Runtime.trap("expected #AmbiguousAttribute for ambiguous email");
  };

  // ---- Case 6: bundle with only apple `email` (unverified) → email = null ----

  let appleUnverified = Attributes.Attributes([
    ("openid:https://appleid.apple.com:email", #Text "alice@icloud.com"),
  ]);

  let #ok v6 = Attributes.asIdentityAttributes(appleUnverified, []) else Runtime.trap("expected ok");
  assert v6.name  == null;
  assert v6.email == null;
  assert v6.sso   == null;

  // ---- Case 7: SSO name + email from a trusted domain ----

  let ssoDfinity = Attributes.Attributes([
    ("sso:dfinity.org:name",  #Text "Alice D"),
    ("sso:dfinity.org:email", #Text "alice@dfinity.org"),
  ]);

  let #ok v7 = Attributes.asIdentityAttributes(ssoDfinity, ["dfinity.org"]) else Runtime.trap("expected ok");
  assert v7.name  == ?"Alice D";
  assert v7.email == ?"alice@dfinity.org";
  assert v7.sso   == ?"dfinity.org";

  // ---- Case 8: SSO email's own domain may be anything — IdP attests it ----

  let ssoForeignEmail = Attributes.Attributes([
    ("sso:dfinity.org:name",  #Text "Bob"),
    ("sso:dfinity.org:email", #Text "bob@externalcontractor.com"),
  ]);

  let #ok v8 = Attributes.asIdentityAttributes(ssoForeignEmail, ["dfinity.org"]) else Runtime.trap("expected ok");
  assert v8.email == ?"bob@externalcontractor.com";
  assert v8.sso   == ?"dfinity.org";

  // ---- Case 9: SSO key with untrusted domain → reject whole bundle ----

  let untrustedSso = Attributes.Attributes([
    ("sso:evil.com:name",  #Text "Mallory"),
    ("sso:evil.com:email", #Text "m@evil.com"),
  ]);

  switch (Attributes.asIdentityAttributes(untrustedSso, ["dfinity.org"])) {
    case (#err(#UntrustedSsoSource { domain })) assert domain == "evil.com";
    case _ Runtime.trap("expected #UntrustedSsoSource for evil.com");
  };

  // ---- Case 10: trusted SSO + unscoped → MixedSsoSources ----

  let mixed = Attributes.Attributes([
    ("sso:dfinity.org:name", #Text "Alice"),
    ("verified_email",       #Text "alice@elsewhere.com"),
  ]);

  switch (Attributes.asIdentityAttributes(mixed, ["dfinity.org"])) {
    case (#err(#MixedSsoSources { ssoKeys; otherKeys })) {
      assert ssoKeys   == ["sso:dfinity.org:name"];
      assert otherKeys == ["verified_email"];
    };
    case _ Runtime.trap("expected #MixedSsoSources for sso+unscoped");
  };

  // ---- Case 11: trusted SSO + openid → MixedSsoSources ----

  let mixedOpenid = Attributes.Attributes([
    ("sso:dfinity.org:name",                              #Text "Alice"),
    ("openid:https://accounts.google.com:verified_email", #Text "alice@gmail.com"),
  ]);

  switch (Attributes.asIdentityAttributes(mixedOpenid, ["dfinity.org"])) {
    case (#err(#MixedSsoSources { ssoKeys; otherKeys })) {
      assert ssoKeys   == ["sso:dfinity.org:name"];
      assert otherKeys == ["openid:https://accounts.google.com:verified_email"];
    };
    case _ Runtime.trap("expected #MixedSsoSources for sso+openid");
  };

  // ---- Case 12: two SSO domains in one bundle → AmbiguousAttribute on "sso" ----

  let twoDomains = Attributes.Attributes([
    ("sso:dfinity.org:name",  #Text "Alice"),
    ("sso:acme.com:email",    #Text "alice@acme.com"),
  ]);

  switch (Attributes.asIdentityAttributes(twoDomains, ["dfinity.org", "acme.com"])) {
    case (#err(#AmbiguousAttribute { field; sources })) {
      assert field == "sso";
      assert sources == ["sso:dfinity.org:name", "sso:acme.com:email"];
    };
    case _ Runtime.trap("expected #AmbiguousAttribute on sso for two domains");
  };

  // ---- Case 13: two SSO name keys for same domain → AmbiguousAttribute on "name" ----
  //
  // Pathological: should never appear in a well-formed bundle, but the
  // verify path must still reject it rather than silently pick one.

  let dupName = Attributes.Attributes([
    ("sso:dfinity.org:name", #Text "Alice"),
    ("sso:dfinity.org:name", #Text "Bob"),
  ]);

  switch (Attributes.asIdentityAttributes(dupName, ["dfinity.org"])) {
    case (#err(#AmbiguousAttribute { field; sources })) {
      assert field == "name";
      assert sources == ["sso:dfinity.org:name", "sso:dfinity.org:name"];
    };
    case _ Runtime.trap("expected #AmbiguousAttribute on name for duplicate sso name");
  };

  // ---- Case 14: SSO name only, no email → email is null ----

  let ssoNameOnly = Attributes.Attributes([
    ("sso:dfinity.org:name", #Text "Alice"),
  ]);

  let #ok v14 = Attributes.asIdentityAttributes(ssoNameOnly, ["dfinity.org"]) else Runtime.trap("expected ok");
  assert v14.name  == ?"Alice";
  assert v14.email == null;
  assert v14.sso   == ?"dfinity.org";

  // ---- Case 15: trustedSsoDomains = [] rejects any sso:* key ----

  let ssoButNoneTrusted = Attributes.Attributes([
    ("sso:dfinity.org:name", #Text "Alice"),
  ]);

  switch (Attributes.asIdentityAttributes(ssoButNoneTrusted, [])) {
    case (#err(#UntrustedSsoSource { domain })) assert domain == "dfinity.org";
    case _ Runtime.trap("expected #UntrustedSsoSource when no domains trusted");
  };

  Debug.print("Attributes.test.mo ok");
};
