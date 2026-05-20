import Value "./Value";
import Result "mo:core/Result";
import Array "mo:core/Array";

/// Decoded attribute bundle and the typed view consumers see.
///
/// `Attributes` is the bundle as an opaque internal class — used by
/// `Verify` to read `implicit:*` fields. It is not re-exported from
/// `lib.mo`; consumers only see the typed `IdentityAttributes`.
///
/// `IdentityAttributes` is the typed result of `Verify.verify`: a
/// single `name` and a single `email`, each sourced from the bundle's
/// unscoped key or one OpenID provider's scoped key. If more than one
/// source is present the verify fails with `#AmbiguousAttribute` rather
/// than picking one silently.
module {

  type Value = Value.Value;

  /// Decoded attribute bundle. Internal — used by `Verify` for the
  /// `implicit:*` reads. Not exposed to consumers.
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
  /// `name` and `email` are sourced from a single matching key in the
  /// bundle — either the unscoped variant (`name` / `verified_email`)
  /// or exactly one OpenID-provider-scoped variant
  /// (`openid:<provider>:name` / `openid:<provider>:verified_email`).
  /// If the bundle contains more than one source for the same field,
  /// `Verify.verify` returns `#AmbiguousAttribute` instead of choosing
  /// one. Either field is `null` when the bundle carries no source for
  /// it.
  ///
  /// **`email` only sources from `verified_email`-suffixed keys.** The
  /// unverified `email` key is user-supplied — Internet Identity
  /// doesn't check it — so it never lands here. There is no escape
  /// hatch; bundles that only carry an unverified `email` will yield
  /// `email = null`.
  public type IdentityAttributes = {
    name  : ?Text;
    email : ?Text;
  };

  /// The conflicting source keys when a single logical field has more
  /// than one source in the bundle.
  public type AmbiguousAttribute = {
    field   : Text;
    sources : [Text];
  };

  /// Construct an `Attributes` from a decoded top-level `#Map`. Returns
  /// `null` if the value isn't a map.
  public func fromValue(value : Value) : ?Attributes {
    switch value { case (#Map entries) ?Attributes(entries); case _ null };
  };

  // OpenID provider prefixes plus the empty unscoped prefix. `{tid}` in
  // the Microsoft URL is a *literal* part of the key Internet Identity
  // emits, not a placeholder for a tenant GUID.
  let openidPrefixes : [Text] = [
    "",
    "openid:https://accounts.google.com:",
    "openid:https://appleid.apple.com:",
    "openid:https://login.microsoftonline.com/{tid}/v2.0:",
  ];

  // Walk each prefix, collect the matching keys that have a value, and
  // either return `#ok null` (no source), `#ok (?value)` (one source),
  // or `#err { field; sources }` (two or more).
  func resolveField(attributes : Attributes, field : Text, suffix : Text)
    : Result.Result<?Text, AmbiguousAttribute>
  {
    var value : ?Text = null;
    var sources : [Text] = [];
    for (prefix in openidPrefixes.vals()) {
      let key = prefix # suffix;
      switch (attributes.getText(key)) {
        case null {};
        case (?v) {
          value := ?v;
          sources := Array.concat<Text>(sources, [key]);
        };
      };
    };
    if (sources.size() > 1) #err({ field; sources }) else #ok(value)
  };

  /// Populate `IdentityAttributes` from a decoded bundle. Returns
  /// `#err` if either `name` or `email` is sourced from more than one
  /// key in the bundle.
  public func asIdentityAttributes(attributes : Attributes)
    : Result.Result<IdentityAttributes, AmbiguousAttribute>
  {
    let name = switch (resolveField(attributes, "name", "name")) {
      case (#err e) return #err(e);
      case (#ok v)  v;
    };
    let email = switch (resolveField(attributes, "email", "verified_email")) {
      case (#err e) return #err(e);
      case (#ok v)  v;
    };
    #ok({ name; email })
  };

};
