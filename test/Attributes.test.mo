import Attributes "../src/Attributes";
import Debug "mo:core/Debug";

do {
  // Build an Attributes class directly so we don't have to go through
  // `from_candid`. Exercises both the exact-match getters on the class
  // and the typed scoped extraction via `asProvider`.
  let attrs = Attributes.Attributes([
    ("name",                                                        #Text "Alice"),
    ("email",                                                       #Text "alice@example.com"),
    ("openid:https://accounts.google.com:name",                     #Text "Alice G"),
    ("openid:https://accounts.google.com:email",                    #Text "alice@gmail.com"),
    ("openid:https://accounts.google.com:verified_email",           #Text "alice@gmail.com"),
    ("openid:https://appleid.apple.com:email",                      #Text "alice@icloud.com"),
    ("implicit:origin",                                             #Text "https://app.example.com"),
    ("implicit:issued_at_timestamp_ns",                             #Nat 1_700_000_000_000_000_000),
    ("implicit:nonce",                                              #Blob "\de\ad\be\ef"),
  ]);

  // ---- Class methods: exact match, typed ----

  assert attrs.getText("name") == ?"Alice";
  assert attrs.getText("openid:https://accounts.google.com:name") == ?"Alice G";
  assert attrs.getText("missing") == null;

  // No scope-fallback — an unscoped key does NOT match a scoped entry and vice versa.
  assert attrs.getText("openid:other.com:email") == null;

  assert attrs.getNat("implicit:issued_at_timestamp_ns") == ?1_700_000_000_000_000_000;
  assert attrs.getNat("name") == null;   // wrong variant

  assert attrs.getBlob("implicit:nonce") == ?("\de\ad\be\ef" : Blob);
  assert attrs.getBlob("name") == null;

  assert attrs.has("implicit:origin");
  assert not attrs.has("phone_number");

  // ---- asProvider: default scope ----

  let def = Attributes.asProvider(attrs, null);
  assert def.name == ?"Alice";
  // No `verified_email` at default scope → email is null even though `email` exists.
  // (Reading the unverified `email` is the caller's explicit choice via
  // `def.attributes.getText("email")`.)
  assert def.email == null;
  assert def.attributes.getText("email") == ?"alice@example.com";

  // ---- asProvider: Google scope ----

  let google = Attributes.asProvider(attrs, ?#Google);
  assert google.name == ?"Alice G";
  assert google.email == ?"alice@gmail.com";   // from verified_email

  // ---- asProvider: Apple scope (no verified_email present) ----

  let apple = Attributes.asProvider(attrs, ?#Apple);
  // Apple has `email` but no `verified_email` → trusted email is null.
  assert apple.email == null;
  assert apple.attributes.getText("openid:https://appleid.apple.com:email") == ?"alice@icloud.com";

  // ---- asProvider: custom OpenID URL ----

  let attrsCustom = Attributes.Attributes([
    ("openid:https://accounts.example.com:verified_email", #Text "bob@example.com"),
  ]);
  let custom = Attributes.asProvider(attrsCustom, ?#OpenId "https://accounts.example.com");
  assert custom.email == ?"bob@example.com";

  Debug.print("Attributes.test.mo ok");
};
