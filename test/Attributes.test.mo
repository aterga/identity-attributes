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

  let #ok v1 = Attributes.asIdentityAttributes(unscoped) else Runtime.trap("expected ok");
  assert v1.name  == ?"Alice";
  assert v1.email == ?"alice@verified.com";

  // ---- Case 2: one openid scope only ----

  let googleOnly = Attributes.Attributes([
    ("openid:https://accounts.google.com:name",           #Text "Alice G"),
    ("openid:https://accounts.google.com:email",          #Text "alice@gmail.com"),     // ignored
    ("openid:https://accounts.google.com:verified_email", #Text "alice@gmail.com"),
  ]);

  let #ok v2 = Attributes.asIdentityAttributes(googleOnly) else Runtime.trap("expected ok");
  assert v2.name  == ?"Alice G";
  assert v2.email == ?"alice@gmail.com";

  // ---- Case 3: no source for either field → nulls ----

  let neither = Attributes.Attributes([
    ("email", #Text "alice@example.com"),  // unverified-only doesn't count
  ]);

  let #ok v3 = Attributes.asIdentityAttributes(neither) else Runtime.trap("expected ok");
  assert v3.name  == null;
  assert v3.email == null;

  // ---- Case 4: ambiguous `name` (unscoped + google) ----

  let ambiguousName = Attributes.Attributes([
    ("name",                                    #Text "Alice"),
    ("openid:https://accounts.google.com:name", #Text "Alice G"),
    ("verified_email",                          #Text "alice@verified.com"),
  ]);

  switch (Attributes.asIdentityAttributes(ambiguousName)) {
    case (#err { field; sources }) {
      assert field == "name";
      assert sources == ["name", "openid:https://accounts.google.com:name"];
    };
    case (#ok _) Runtime.trap("expected #err for ambiguous name");
  };

  // ---- Case 5: ambiguous `email` across two providers ----

  let ambiguousEmail = Attributes.Attributes([
    ("openid:https://accounts.google.com:verified_email", #Text "alice@gmail.com"),
    ("openid:https://appleid.apple.com:verified_email",   #Text "alice@icloud.com"),
  ]);

  switch (Attributes.asIdentityAttributes(ambiguousEmail)) {
    case (#err { field; sources }) {
      assert field == "email";
      assert sources == [
        "openid:https://accounts.google.com:verified_email",
        "openid:https://appleid.apple.com:verified_email",
      ];
    };
    case (#ok _) Runtime.trap("expected #err for ambiguous email");
  };

  // ---- Case 6: bundle with only apple `email` (unverified) → email = null ----

  let appleUnverified = Attributes.Attributes([
    ("openid:https://appleid.apple.com:email", #Text "alice@icloud.com"),
  ]);

  let #ok v6 = Attributes.asIdentityAttributes(appleUnverified) else Runtime.trap("expected ok");
  assert v6.name  == null;
  assert v6.email == null;

  Debug.print("Attributes.test.mo ok");
};
