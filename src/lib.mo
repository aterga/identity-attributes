import V "./Value";
import A "./Attributes";
import I "./Implicit";
import C "./Challenges";
import Vr "./Verify";

/// Umbrella module. `import II "mo:identity-attributes"` and reach for
/// `II.verify`, `II.Challenges.*`, `II.Attributes.*`, etc.
///
/// Submodules can also be imported individually:
///   `import Verify "mo:identity-attributes/Verify";`
module {
  public type Value      = V.Value;
  public type Attributes = A.Attributes;
  public type Policy     = Vr.Policy;
  public type Config     = Vr.Config;
  public type Error      = Vr.Error;
  public type Store      = C.Store;

  public let decode      = V.decode;
  public let fromValue   = A.fromValue;
  public let get         = A.get;
  public let getText     = A.getText;
  public let getNat      = A.getNat;
  public let getBlob     = A.getBlob;

  public let origin      = I.origin;
  public let issuedAtNs  = I.issuedAtNs;
  public let nonce       = I.nonce;

  public let verify      = Vr.verify;

  // Nonce-store helpers (see `Challenges` submodule for docs).
  public let emptyStore       = C.empty;
  public let issueChallenge   = C.issue;
  public let consumeChallenge = C.consume;
  public let pruneChallenges  = C.prune;
};

