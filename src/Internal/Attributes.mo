import Value "./Value";
import Result "mo:core/Result";
import Array "mo:core/Array";
import Text "mo:core/Text";
import Iter "mo:core/Iter";

/// Decoded attribute bundle and the typed view consumers see.
///
/// `Attributes` is the bundle as an opaque internal class — used by
/// `Verify` to read `implicit:*` fields. It is not re-exported from
/// `lib.mo`; consumers only see the typed `IdentityAttributes`.
///
/// `IdentityAttributes` is the typed result of `Verify.verify`: a
/// single `name`, a single `email`, and an optional `sso` domain.
/// `name` and `email` are each sourced from at most one key in the
/// bundle, drawn from a single category:
///
///   - **unscoped/openid** — `name` / `verified_email` or
///     `openid:<provider>:name` / `openid:<provider>:verified_email`.
///   - **sso** — `sso:<domain>:name` / `sso:<domain>:email`, where
///     `<domain>` is one of the canister's `trusted_sso_domains`.
///
/// The two categories can never mix in a single bundle. Mixing yields
/// `#MixedSsoSources`. An `sso:<domain>:*` key whose domain isn't
/// trusted rejects the bundle with `#UntrustedSsoSource` even if the
/// rest of the bundle is well-formed.
module {

  type Value = Value.Value;

  /// Decoded attribute bundle. Internal — used by `Verify` for the
  /// `implicit:*` reads. Not exposed to consumers.
  public class Attributes(initialEntries : [(Text, Value)]) {

    let entries = initialEntries;

    /// All entries — used by `asIdentityAttributes` to walk the bundle
    /// looking for `sso:<domain>:*` keys whose domains aren't known
    /// ahead of time.
    public func all() : [(Text, Value)] = entries;

    /// Whether `key` is present in the bundle, regardless of its value type.
    public func has(key : Text) : Bool {
      for ((entryKey, _) in entries.vals()) { if (entryKey == key) return true };
      false
    };

    /// Exact-match lookup for a `Text`-valued entry. Returns `null` if
    /// the key is missing OR if the entry exists but isn't `Text`.
    public func getText(key : Text) : ?Text {
      for ((entryKey, value) in entries.vals()) {
        if (entryKey == key) {
          switch value { case (#Text text) return ?text; case _ {} }
        }
      };
      null
    };

    /// Exact-match lookup for a `Nat`-valued entry.
    public func getNat(key : Text) : ?Nat {
      for ((entryKey, value) in entries.vals()) {
        if (entryKey == key) {
          switch value { case (#Nat nat) return ?nat; case _ {} }
        }
      };
      null
    };

    /// Exact-match lookup for a `Blob`-valued entry.
    public func getBlob(key : Text) : ?Blob {
      for ((entryKey, value) in entries.vals()) {
        if (entryKey == key) {
          switch value { case (#Blob blob) return ?blob; case _ {} }
        }
      };
      null
    }
  };

  /// What `Verify.verify` hands back on success.
  ///
  /// `name` and `email` are sourced from a single matching key in the
  /// bundle. `sso` is the matched SSO domain when the bundle's
  /// name/email came from `sso:<domain>:*` keys, otherwise `null`.
  ///
  /// **`email` semantics differ by category.** For unscoped and
  /// openid sources, only `verified_email`-suffixed keys count — the
  /// unverified `email` key is user-supplied and never lands here.
  /// For SSO sources the key is literally `sso:<domain>:email`: the
  /// IdP behind `<domain>` attests the value, so there is no separate
  /// verification flag. The email's own domain may be anything.
  public type IdentityAttributes = {
    name : ?Text;
    email : ?Text;
    sso : ?Text
  };

  /// A single logical field has more than one source in the bundle.
  /// `sources` lists the conflicting keys.
  public type AmbiguousAttribute = {
    field : Text;
    sources : [Text]
  };

  /// All ways `asIdentityAttributes` can reject the bundle.
  public type Error = {
    /// Two or more keys populate the same logical field (`name`,
    /// `email`, or `sso` when SSO sources span multiple domains).
    #AmbiguousAttribute : AmbiguousAttribute;
    /// The bundle contains an `sso:<domain>:*` key whose `<domain>`
    /// is not listed in `trusted_sso_domains`. The whole bundle is
    /// rejected — we don't silently strip untrusted SSO claims.
    #UntrustedSsoSource : { domain : Text };
    /// The bundle mixes SSO and non-SSO sources for name/email.
    /// Either the unscoped/openid keys are present alongside SSO
    /// keys, or vice versa. `ssoKeys` and `otherKeys` list the
    /// offending entries.
    #MixedSsoSources : { ssoKeys : [Text]; otherKeys : [Text] }
  };

  /// Construct an `Attributes` from a decoded top-level `#Map`. Returns
  /// `null` if the value isn't a map.
  public func fromValue(value : Value) : ?Attributes {
    switch value { case (#Map entries) ?Attributes(entries); case _ null }
  };

  // OpenID provider prefixes plus the empty unscoped prefix. `{tid}` in
  // the Microsoft URL is a *literal* part of the key Internet Identity
  // emits, not a placeholder for a tenant GUID.
  let openidPrefixes : [Text] = [
    "",
    "openid:https://accounts.google.com:",
    "openid:https://appleid.apple.com:",
    "openid:https://login.microsoftonline.com/{tid}/v2.0:"
  ];

  // Parse a key shaped `sso:<domain>:<suffix>`. Returns null if the
  // key doesn't have exactly three colon-separated parts or the first
  // part isn't `sso`. Email domains don't contain colons in practice,
  // so the three-part split is unambiguous.
  func parseSsoKey(key : Text) : ?(Text, Text) {
    let parts = Iter.toArray(Text.split(key, #char ':'));
    if (parts.size() != 3) return null;
    if (parts[0] != "sso") return null;
    ?(parts[1], parts[2])
  };

  // Resolve one field across the unscoped/openid prefixes. Returns
  // null/one/error mirroring the pre-SSO behavior.
  func resolveNonSsoField(attributes : Attributes, field : Text, suffix : Text) : Result.Result<?Text, AmbiguousAttribute> {
    var value : ?Text = null;
    var sources : [Text] = [];
    for (prefix in openidPrefixes.vals()) {
      let key = prefix # suffix;
      switch (attributes.getText(key)) {
        case null {};
        case (?v) {
          value := ?v;
          sources := Array.concat<Text>(sources, [key])
        }
      }
    };
    if (sources.size() > 1) #err({ field; sources }) else #ok(value)
  };

  // True iff the bundle has at least one non-SSO name/email source.
  func hasNonSsoNameOrEmail(attributes : Attributes) : [Text] {
    var keys : [Text] = [];
    for (prefix in openidPrefixes.vals()) {
      for (suffix in (["name", "verified_email"] : [Text]).vals()) {
        let key = prefix # suffix;
        if (attributes.has(key)) keys := Array.concat<Text>(keys, [key])
      }
    };
    keys
  };

  /// Populate `IdentityAttributes` from a decoded bundle.
  ///
  /// `trustedSsoDomains` is the canister's `trusted_sso_domains` env
  /// var, parsed. An empty list means "this canister doesn't accept
  /// SSO sources" — any `sso:*` key in the bundle rejects it via
  /// `#UntrustedSsoSource`.
  public func asIdentityAttributes(
    attributes : Attributes,
    trustedSsoDomains : [Text]
  ) : Result.Result<IdentityAttributes, Error> {

    // Scan for sso:<domain>:<suffix> keys, separating trusted from
    // untrusted and name from email. Any untrusted SSO source rejects
    // the bundle outright.
    var untrustedSsoDomain : ?Text = null;
    var ssoNameSources : [(Text, Text, Text)] = []; // (domain, key, value)
    var ssoEmailSources : [(Text, Text, Text)] = [];

    for ((key, value) in attributes.all().vals()) {
      switch (parseSsoKey(key)) {
        case null {};
        case (?(domain, suffix)) {
          switch value {
            case (#Text v) {
              if (Array.find<Text>(trustedSsoDomains, func d = d == domain) == null) {
                if (untrustedSsoDomain == null) untrustedSsoDomain := ?domain
              } else if (suffix == "name") {
                ssoNameSources := Array.concat<(Text, Text, Text)>(ssoNameSources, [(domain, key, v)])
              } else if (suffix == "email") {
                ssoEmailSources := Array.concat<(Text, Text, Text)>(ssoEmailSources, [(domain, key, v)])
              }
            };
            case _ {}
          }
        }
      }
    };

    switch (untrustedSsoDomain) {
      case (?d) return #err(#UntrustedSsoSource { domain = d });
      case null {}
    };

    let hasSso = ssoNameSources.size() > 0 or ssoEmailSources.size() > 0;

    if (hasSso) {
      // The bundle is SSO-flavored. Reject if any non-SSO name/email
      // source is also present — mixing the two categories is never
      // allowed (it would let an attacker who controls one IdP shadow
      // another).
      let otherKeys = hasNonSsoNameOrEmail(attributes);
      if (otherKeys.size() > 0) {
        var ssoKeys : [Text] = [];
        for ((_, k, _) in ssoNameSources.vals()) ssoKeys := Array.concat<Text>(ssoKeys, [k]);
        for ((_, k, _) in ssoEmailSources.vals()) ssoKeys := Array.concat<Text>(ssoKeys, [k]);
        return #err(#MixedSsoSources { ssoKeys; otherKeys })
      };

      // All SSO sources must share one domain. If name comes from
      // dfinity.org and email from acme.com, the bundle is asking us
      // to splice claims from two IdPs — reject.
      var domain : ?Text = null;
      var domainSources : [Text] = [];
      for (src in ssoNameSources.vals()) {
        domainSources := Array.concat<Text>(domainSources, [src.1]);
        switch (domain) {
          case null { domain := ?src.0 };
          case (?d0) if (src.0 != d0) return #err(#AmbiguousAttribute { field = "sso"; sources = domainSources })
        }
      };
      for (src in ssoEmailSources.vals()) {
        domainSources := Array.concat<Text>(domainSources, [src.1]);
        switch (domain) {
          case null { domain := ?src.0 };
          case (?d0) if (src.0 != d0) return #err(#AmbiguousAttribute { field = "sso"; sources = domainSources })
        }
      };

      // Within the single domain, name and email each must have ≤ 1
      // source. Two `sso:dfinity.org:name` entries is malformed.
      if (ssoNameSources.size() > 1) {
        var sources : [Text] = [];
        for (src in ssoNameSources.vals()) sources := Array.concat<Text>(sources, [src.1]);
        return #err(#AmbiguousAttribute { field = "name"; sources })
      };
      if (ssoEmailSources.size() > 1) {
        var sources : [Text] = [];
        for (src in ssoEmailSources.vals()) sources := Array.concat<Text>(sources, [src.1]);
        return #err(#AmbiguousAttribute { field = "email"; sources })
      };

      let nameVal = if (ssoNameSources.size() == 1) ?ssoNameSources[0].2 else null;
      let emailVal = if (ssoEmailSources.size() == 1) ?ssoEmailSources[0].2 else null;
      return #ok { name = nameVal; email = emailVal; sso = domain }
    };

    // No SSO sources — fall through to the unscoped/openid resolution.
    let name = switch (resolveNonSsoField(attributes, "name", "name")) {
      case (#err e) return #err(#AmbiguousAttribute e);
      case (#ok v) v
    };
    let email = switch (resolveNonSsoField(attributes, "email", "verified_email")) {
      case (#err e) return #err(#AmbiguousAttribute e);
      case (#ok v) v
    };
    #ok { name; email; sso = null }
  };

}
