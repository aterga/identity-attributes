import Value "./Value";

/// Decoded attribute bundle and the typed view consumers see.
///
/// `Attributes` is the bundle as an opaque class — read entries by
/// exact key via `getText`/`getNat`/`getBlob`/`has`. The raw ICRC-3
/// `Value` is internal and not exposed.
///
/// `VerifiedIdentityAttributes` is the typed result of `Verify.verify`: every known
/// provider's `name` and `verified_email` surfaced as optional fields,
/// plus the underlying `Attributes` for any custom-scoped keys (for
/// example, enterprise `sso:<domain>:*`) or the raw unverified `email`.
module {

  type Value = Value.Value;

  /// Decoded attribute bundle. Read with `attributes.getText("...")`
  /// etc. — exact-match only, no prefix or fuzzy matching.
  public class Attributes(initialEntries : [(Text, Value)]) {

    let entries = initialEntries;

    /// Whether `key` is present in the bundle, regardless of its value type.
    public func has(key : Text) : Bool {
      for ((entryKey, _) in entries.vals()) { if (entryKey == key) return true };
      false
    };

    /// Exact-match lookup for a `Text`-valued entry. Returns `null` if
    /// the key is missing OR if the entry exists but isn't `Text`.
    public func getText(key : Text) : ?Text {
      for ((entryKey, value) in entries.vals()) {
        if (entryKey == key) { switch value { case (#Text text) return ?text; case _ {} } };
      };
      null
    };

    /// Exact-match lookup for a `Nat`-valued entry.
    public func getNat(key : Text) : ?Nat {
      for ((entryKey, value) in entries.vals()) {
        if (entryKey == key) { switch value { case (#Nat nat) return ?nat; case _ {} } };
      };
      null
    };

    /// Exact-match lookup for a `Blob`-valued entry.
    public func getBlob(key : Text) : ?Blob {
      for ((entryKey, value) in entries.vals()) {
        if (entryKey == key) { switch value { case (#Blob blob) return ?blob; case _ {} } };
      };
      null
    };
  };

  /// What `Verify.verify` hands back on success.
  ///
  /// Each scope's `name` and `verified_email` come from the bundle's
  /// matching key (default scope = unscoped key; provider scopes =
  /// `openid:<provider-url>:<key>`). Fields are `null` when the FE
  /// didn't request that scope's keys or Internet Identity didn't surface them.
  ///
  /// **No raw `email` field by design.** The unverified `email` key
  /// is user-supplied — Internet Identity doesn't check it — so exposing it
  /// alongside the verified variants would make the unsafe choice as
  /// easy as the safe one. If you genuinely need it (mailing-list
  /// signup, contact display, never gating access), reach in
  /// explicitly via `attributes.getText("email")`.
  ///
  /// For Microsoft, the `{tid}` in the URL is *literal* — that's what
  /// Internet Identity actually emits, not a placeholder for a tenant GUID.
  ///
  /// For enterprise SSO keys outside the four named providers, read
  /// directly from `attributes` — for example,
  /// `attributes.getText("sso:dfinity.org:verified_email")`.
  public type VerifiedIdentityAttributes = {
    name                     : ?Text;
    verified_email           : ?Text;
    google_name              : ?Text;
    google_verified_email    : ?Text;
    apple_name               : ?Text;
    apple_verified_email     : ?Text;
    microsoft_name           : ?Text;
    microsoft_verified_email : ?Text;
    attributes               : Attributes;
  };

  /// Construct an `Attributes` from a decoded top-level `#Map`. Returns
  /// `null` if the value isn't a map.
  public func fromValue(value : Value) : ?Attributes {
    switch value { case (#Map entries) ?Attributes(entries); case _ null };
  };

  /// Populate `VerifiedIdentityAttributes` from a decoded bundle. Pulls each known
  /// provider's keys with exact-match — an unscoped `name` is *not* the
  /// same key as `openid:google:name`, so they end up in different
  /// fields.
  public func asVerifiedIdentityAttributes(attributes : Attributes) : VerifiedIdentityAttributes {
    let googlePrefix    = "openid:https://accounts.google.com:";
    let applePrefix     = "openid:https://appleid.apple.com:";
    // `{tid}` is a *literal* part of the URL Internet Identity emits.
    let microsoftPrefix = "openid:https://login.microsoftonline.com/{tid}/v2.0:";
    {
      name                     = attributes.getText("name");
      verified_email           = attributes.getText("verified_email");
      google_name              = attributes.getText(googlePrefix # "name");
      google_verified_email    = attributes.getText(googlePrefix # "verified_email");
      apple_name               = attributes.getText(applePrefix # "name");
      apple_verified_email     = attributes.getText(applePrefix # "verified_email");
      microsoft_name           = attributes.getText(microsoftPrefix # "name");
      microsoft_verified_email = attributes.getText(microsoftPrefix # "verified_email");
      attributes;
    }
  };

};
