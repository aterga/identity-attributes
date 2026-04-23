// Matches the canister's generated .did — see
// demos/bagel/.dfx/local/canisters/bagel/bagel.did
export type VerifyError =
  | { NoAttributes: null }
  | { MalformedCandid: null }
  | { MissingField: string }
  | { OriginMismatch: { expected: string; got: string } }
  | { Stale: { ageNs: bigint } }
  | { UnknownNonce: null }
  | { NonceExpired: null }
  | { MissingNonceStore: null };

export type JoinOutcome =
  | { Waiting: null }
  | { Paired: { email: string } };

export type JoinError =
  | { Verify: VerifyError }
  | { NoEmail: null }
  | { WrongDomain: { email: string } };

export type JoinResult =
  | { ok: JoinOutcome }
  | { err: JoinError };

export interface Bagel {
  generate_nonce: () => Promise<Uint8Array>;
  join_round: () => Promise<JoinResult>;
  my_match: () => Promise<[] | [string]>;
  reset: () => Promise<void>;
  pool_size: () => Promise<bigint>;
}

// Untyped factory — the IDL shape drifts between `@icp-sdk/core/candid`
// and the `@dfinity/candid` that `Actor.createActor` expects, and we
// don't want the demo to care. Runtime behaviour is identical.
export const idlFactory = ({ IDL }: { IDL: any }) => {
  const Error_ = IDL.Variant({
    NoAttributes: IDL.Null,
    MalformedCandid: IDL.Null,
    MissingField: IDL.Text,
    OriginMismatch: IDL.Record({ expected: IDL.Text, got: IDL.Text }),
    Stale: IDL.Record({ ageNs: IDL.Nat }),
    UnknownNonce: IDL.Null,
    NonceExpired: IDL.Null,
    MissingNonceStore: IDL.Null,
  });
  const JoinOutcome = IDL.Variant({
    Waiting: IDL.Null,
    Paired: IDL.Record({ email: IDL.Text }),
  });
  const JoinError = IDL.Variant({
    Verify: Error_,
    NoEmail: IDL.Null,
    WrongDomain: IDL.Record({ email: IDL.Text }),
  });
  const Result = IDL.Variant({ ok: JoinOutcome, err: JoinError });

  return IDL.Service({
    generate_nonce: IDL.Func([], [IDL.Vec(IDL.Nat8)], []),
    join_round: IDL.Func([], [Result], []),
    my_match: IDL.Func([], [IDL.Opt(IDL.Text)], ["query"]),
    reset: IDL.Func([], [], []),
    pool_size: IDL.Func([], [IDL.Nat], ["query"]),
  });
};
