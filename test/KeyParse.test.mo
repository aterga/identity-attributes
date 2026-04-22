import KeyParse "../src/Internal/KeyParse";
import Debug "mo:core/Debug";

do {
  let unscoped = KeyParse.split("email");
  assert unscoped.0 == null;
  assert unscoped.1 == "email";

  let simple = KeyParse.split("scope:email");
  assert simple.0 == ?"scope";
  assert simple.1 == "email";

  let nested = KeyParse.split("openid:https://accounts.google.com:email");
  assert nested.0 == ?"openid:https://accounts.google.com";
  assert nested.1 == "email";

  let implicit = KeyParse.split("implicit:origin");
  assert implicit.0 == ?"implicit";
  assert implicit.1 == "origin";

  let trailingColon = KeyParse.split("x:");
  assert trailingColon.0 == ?"x";
  assert trailingColon.1 == "";

  let emptyScope = KeyParse.split(":email");
  assert emptyScope.0 == ?"";
  assert emptyScope.1 == "email";

  let empty = KeyParse.split("");
  assert empty.0 == null;
  assert empty.1 == "";

  Debug.print("KeyParse.test.mo ok");
};
