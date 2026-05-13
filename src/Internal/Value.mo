/// ICRC-3 `Value` tree.
///
/// Mirrors the Candid type Internet Identity uses when it certifies attribute
/// bundles. Internal to the library — the public surface speaks `Verified`
/// and the typed accessors on `Attributes`, not raw `Value`.
///
/// See: https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md
module {
  public type Value = {
    #Nat   : Nat;
    #Int   : Int;
    #Blob  : Blob;
    #Text  : Text;
    #Array : [Value];
    #Map   : [(Text, Value)];
  };

  /// Candid-decode an ICRC-3 `Value` blob. Returns `null` if the bytes don't
  /// match the expected type.
  public func decode(blob : Blob) : ?Value {
    let decoded : ?Value = from_candid(blob);
    decoded
  };
};
