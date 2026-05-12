import A "./Attributes";
import C "./Challenges";
import Vr "./Verify";

/// Umbrella module. `import II "mo:identity-attributes"` and reach for
/// `II.verify`, `II.Challenges.*`, etc.
///
/// Submodules can also be imported individually:
///   `import Verify "mo:identity-attributes/Verify";`
///   `import Challenges "mo:identity-attributes/Challenges";`
module {
  public type Attributes      = A.Attributes;
  public type OpenIdProvider  = A.OpenIdProvider;
  public type Verified        = A.Verified;
  public type Config          = Vr.Config;
  public type Error           = Vr.Error;
  public type Store           = C.Store;

  public let verify           = Vr.verify;
  public let defaultMaxAgeNs  = Vr.defaultMaxAgeNs;
  public let asProvider       = A.asProvider;
};
