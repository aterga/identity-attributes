import Attributes "../src/Attributes";
import Debug "mo:core/Debug";

do {
  let attrs : Attributes.Attributes = {
    entries = [
      ("openid:https://accounts.google.com:email", #Text "alice@example.com"),
      ("name",                                     #Text "Alice"),
      ("implicit:origin",                          #Text "https://app.example.com"),
      ("implicit:issued_at_timestamp_ns",          #Nat 1_700_000_000_000_000_000),
      ("implicit:nonce",                           #Blob "\de\ad\be\ef"),
    ];
  };

  // Exact match
  assert Attributes.getText(attrs, "name") == ?"Alice";
  assert Attributes.getText(attrs, "openid:https://accounts.google.com:email") == ?"alice@example.com";

  // Unscoped fallback — `email` matches the scoped entry
  assert Attributes.getText(attrs, "email") == ?"alice@example.com";

  // Scoped key without a matching scope — no fallback
  assert Attributes.getText(attrs, "openid:other.com:email") == null;

  // Typed accessors reject wrong variants
  assert Attributes.getNat(attrs, "name") == null;
  assert Attributes.getBlob(attrs, "implicit:nonce") == ?("\de\ad\be\ef" : Blob);
  assert Attributes.getNat(attrs, "implicit:issued_at_timestamp_ns") == ?1_700_000_000_000_000_000;

  // Missing key
  assert Attributes.get(attrs, "age") == null;

  Debug.print("Attributes.test.mo ok");
};
