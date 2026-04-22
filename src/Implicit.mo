import Attributes "./Attributes";

/// Typed access to the three `implicit:*` fields that II always embeds in
/// the certified bundle.
module {
  /// `implicit:origin` — origin of the relying-party frontend that
  /// requested the attributes (set by the II backend based on the
  /// authenticated caller origin).
  public func origin(a : Attributes.Attributes) : ?Text {
    Attributes.getText(a, "implicit:origin")
  };

  /// `implicit:issued_at_timestamp_ns` — certification timestamp, in IC
  /// nanoseconds since the Unix epoch.
  public func issuedAtNs(a : Attributes.Attributes) : ?Nat {
    Attributes.getNat(a, "implicit:issued_at_timestamp_ns")
  };

  /// `implicit:nonce` — 32-byte nonce supplied by the relying party.
  public func nonce(a : Attributes.Attributes) : ?Blob {
    Attributes.getBlob(a, "implicit:nonce")
  };
};
