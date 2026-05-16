/// Migration shim for the production dfinsight backend
/// (`lu3pu-iiaaa-aaaao-qpuhq-cai`).
///
/// Lu3pu was last installed on 2026-05-10 with the pre-`cb96a7e`
/// version of `mo:identity-attributes`. The deployed stable
/// signature (verified via `moc --stable-types` on commit `1de54ca`)
/// includes four fields that the current actor no longer declares:
///
///   - `nonces`         : Map<Principal, [{nonce; expiresAtNs}]>
///     The library's `Challenges.Store` used to be a Map; today it's
///     `Queue<Blob>` (commit `cb96a7e`, "refactor: nonces use
///     mo:core/Queue"). Bridged here to a fresh empty queue —
///     in-flight nonces are 5-minute-TTL transient state, so dropping
///     them just forces any admin sign-in mid-flight to retry, which
///     `AdminLanding.tsx`'s `refreshPreflight` handles.
///
///   - `anonNonceKey`   : Principal
///   - `maxAttrAgeNs`   : Nat
///   - `nonceTtlNs`     : Nat
///     The pre-refactor actor stored these as top-level `let`
///     bindings; the new caller-agnostic flow doesn't need any of
///     them. moc 1.6 refuses to implicitly discard stable fields
///     (M0169) so they have to be enumerated in the migration's
///     input record even though the migration just drops them.
///
/// Every other stable field (`issues`, `upvoters`, `lastPostAt`,
/// `admins`, `adminSessions`, `rpOrigin`, `nextIssueId`,
/// `adminSessionNs`, `dayNs`, `maxBodyChars`) keeps the same type
/// across versions and EOP auto-carries them.

import Map       "mo:core/Map";
import Principal "mo:core/Principal";
import Queue     "mo:core/Queue";

module {

  public func migration(_old : {
    var anonNonceKey : Principal;
    var maxAttrAgeNs : Nat;
    var nonceTtlNs : Nat;
    var nonces : Map.Map<Principal, [{ nonce : Blob; expiresAtNs : Nat }]>;
  }) : {
    var nonces : Queue.Queue<Blob>;
  } {
    { var nonces = Queue.empty<Blob>() };
  };

}
