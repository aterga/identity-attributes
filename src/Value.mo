/// ICRC-3 `Value` tree.
///
/// Mirrors the Candid type used by Internet Identity when it certifies
/// attribute bundles (`prepare_icrc3_attributes` / `get_icrc3_attributes`).
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

  /// Decode a Candid-encoded `Value` blob. Returns `null` if the bytes
  /// don't match the expected type.
  public func decode(b : Blob) : ?Value {
    let v : ?Value = from_candid(b);
    v
  };
};
