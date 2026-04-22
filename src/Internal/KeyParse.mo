import Text "mo:core/Text";

/// Attribute-key parsing. Keys have the shape `<scope>:<name>` where the
/// scope itself may contain colons (e.g. `openid:https://accounts.google.com`).
/// Split on the LAST `:` to match the Rust `AttributeKey` parser in the II
/// interface crate.
module {
  /// Split `"scope:name"` into `(?scope, name)`. Unscoped keys return
  /// `(null, key)`.
  public func split(key : Text) : (?Text, Text) {
    var lastIdx : ?Nat = null;
    var i : Nat = 0;
    for (c in key.chars()) {
      if (c == ':') { lastIdx := ?i };
      i += 1;
    };

    switch lastIdx {
      case null { (null, key) };
      case (?idx) {
        var scope = "";
        var name = "";
        var j : Nat = 0;
        for (c in key.chars()) {
          if (j < idx) {
            scope #= Text.fromChar(c);
          } else if (j > idx) {
            name #= Text.fromChar(c);
          };
          j += 1;
        };
        (?scope, name)
      };
    };
  };

  /// Attribute name (the part after the last `:`, or the whole key if unscoped).
  public func name(key : Text) : Text {
    let (_, n) = split(key);
    n
  };
};
