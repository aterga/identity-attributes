import Attributes "../src/Internal/Attributes";
import Debug "mo:core/Debug";

do {
  // Build an Attributes class directly so we don't have to go through
  // `from_candid`. Exercises the exact-match getters AND `asVerified`.
  let attrs = Attributes.Attributes([
    ("name",                                                        #Text "Alice"),
    ("email",                                                       #Text "alice@example.com"),
    ("verified_email",                                              #Text "alice@verified.com"),
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

  assert attrs.getNat("implicit:issued_at_timestamp_ns") == ?1_700_000_000_000_000_000;
  assert attrs.getNat("name") == null;   // wrong variant

  assert attrs.getBlob("implicit:nonce") == ?("\de\ad\be\ef" : Blob);

  assert attrs.has("implicit:origin");
  assert not attrs.has("phone_number");

  // ---- asIdentityAttributes: every known provider populated independently ----

  let v = Attributes.asIdentityAttributes(attrs);

  assert v.name == ?"Alice";
  assert v.verified_email == ?"alice@verified.com";

  assert v.google_name == ?"Alice G";
  assert v.google_verified_email == ?"alice@gmail.com";

  // Apple has `email` but no `verified_email` → only the verified
  // variant lives on `Verified`. The raw email is reachable via the
  // escape hatch.
  assert v.apple_name == null;
  assert v.apple_verified_email == null;
  assert v.attributes.getText("openid:https://appleid.apple.com:email") == ?"alice@icloud.com";

  // Microsoft keys missing → all-null.
  assert v.microsoft_name == null;
  assert v.microsoft_verified_email == null;

  // Raw unverified email is NOT exposed on Verified — reach into
  // attributes if you knowingly want it.
  assert v.attributes.getText("email") == ?"alice@example.com";

  Debug.print("Attributes.test.mo ok");
};
