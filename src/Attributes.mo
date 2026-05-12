import Value "./Value";

/// Decoded attribute bundle and the typed view consumers see.
///
/// `Attributes` is the bundle as an opaque class — only the public methods
/// (`getText`, `getNat`, `getBlob`, `has`) read it. The raw ICRC-3 `Value` is
/// internal.
///
/// `Verified` is the typed result of `Verify.verify`: typed name/email under
/// a chosen `OpenIdProvider` scope, plus the underlying `Attributes` for
/// implicit-field reads, unknown keys, or re-scoping via `asProvider`.
module {
  type Value = Value.Value;

  /// Which OpenID-provider scope to read attributes under. Matches the
  /// `openIdProvider` argument the frontend passes to AuthClient.
  /// `#OpenId : <url>` is the escape hatch for providers this library
  /// doesn't name explicitly.
  public type OpenIdProvider = {
    #Google;
    #Apple;
    #Microsoft;
    #OpenId : Text;
  };

  /// Decoded attribute bundle. Read with `attrs.getText("...")` /
  /// `attrs.getNat(...)` / `attrs.getBlob(...)` / `attrs.has(...)`.
  public class Attributes(entries_ : [(Text, Value)]) {
    let entries = entries_;

    /// Whether `key` is present in the bundle (regardless of its value type).
    public func has(key : Text) : Bool {
      for ((k, _) in entries.vals()) { if (k == key) return true };
      false
    };

    /// Exact-match lookup for a `Text`-valued entry.
    public func getText(key : Text) : ?Text {
      for ((k, v) in entries.vals()) {
        if (k == key) { switch v { case (#Text t) return ?t; case _ {} } };
      };
      null
    };

    /// Exact-match lookup for a `Nat`-valued entry.
    public func getNat(key : Text) : ?Nat {
      for ((k, v) in entries.vals()) {
        if (k == key) { switch v { case (#Nat n) return ?n; case _ {} } };
      };
      null
    };

    /// Exact-match lookup for a `Blob`-valued entry.
    public func getBlob(key : Text) : ?Blob {
      for ((k, v) in entries.vals()) {
        if (k == key) { switch v { case (#Blob b) return ?b; case _ {} } };
      };
      null
    };
  };

  /// Result of a successful `Verify.verify` call: typed name + email under
  /// the chosen `OpenIdProvider` scope, with the raw `Attributes` for any
  /// further reads.
  ///
  /// `email` is sourced from `verified_email` (or the scoped equivalent)
  /// only. The unverified `email` key is reachable via
  /// `attributes.getText("email")` for callers that knowingly want the
  /// user-supplied value.
  public type Verified = {
    name       : ?Text;
    email      : ?Text;
    attributes : Attributes;
  };

  /// Construct an `Attributes` from a decoded top-level `#Map`. Returns
  /// `null` if the value isn't a map.
  public func fromValue(v : Value) : ?Attributes {
    switch v { case (#Map entries) ?Attributes(entries); case _ null };
  };

  /// Provider key prefix, including the trailing colon. `null` produces an
  /// empty prefix for default-scope (unscoped) keys.
  func prefix(p : ?OpenIdProvider) : Text {
    switch p {
      case null            "";
      case (?#Google)      "openid:https://accounts.google.com:";
      case (?#Apple)       "openid:https://appleid.apple.com:";
      // `{tid}` is a literal part of the URL Internet Identity emits — not
      // a tenant-ID placeholder.
      case (?#Microsoft)   "openid:https://login.microsoftonline.com/{tid}/v2.0:";
      case (?#OpenId url)  "openid:" # url # ":";
    };
  };

  /// Produce a `Verified` view of `a` under `p`'s scope. Exact-match: an
  /// unscoped `name` is *not* the same key as `openid:google:name`, and
  /// asking for one doesn't fall back to the other.
  public func asProvider(a : Attributes, p : ?OpenIdProvider) : Verified {
    let pfx = prefix(p);
    {
      name       = a.getText(pfx # "name");
      email      = a.getText(pfx # "verified_email");
      attributes = a;
    }
  };
};
