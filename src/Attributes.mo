import Value "./Value";
import KeyParse "./Internal/KeyParse";

/// Decoded attribute bundle: an ordered list of `(key, Value)` pairs.
/// Lookups apply scope-fallback: requesting `"email"` matches either a
/// bare `"email"` entry or any `"<scope>:email"` entry.
module {
  public type Value = Value.Value;

  public type Attributes = {
    entries : [(Text, Value)];
  };

  /// Construct an `Attributes` from a decoded top-level `#Map`. Returns
  /// `null` if the value isn't a map.
  public func fromValue(v : Value) : ?Attributes {
    switch v {
      case (#Map entries) ?{ entries };
      case _ null;
    };
  };

  /// Look up `key`. Exact match wins; for an unscoped `key`, fall back to
  /// any entry whose name matches.
  public func get(a : Attributes, key : Text) : ?Value {
    for ((k, v) in a.entries.vals()) {
      if (k == key) return ?v;
    };

    let (reqScope, reqName) = KeyParse.split(key);
    switch reqScope {
      case (?_) null;
      case null {
        for ((k, v) in a.entries.vals()) {
          if (KeyParse.name(k) == reqName) return ?v;
        };
        null
      };
    };
  };

  public func getText(a : Attributes, key : Text) : ?Text {
    switch (get(a, key)) { case (?#Text t) ?t; case _ null };
  };

  public func getNat(a : Attributes, key : Text) : ?Nat {
    switch (get(a, key)) { case (?#Nat n) ?n; case _ null };
  };

  public func getBlob(a : Attributes, key : Text) : ?Blob {
    switch (get(a, key)) { case (?#Blob b) ?b; case _ null };
  };
};
