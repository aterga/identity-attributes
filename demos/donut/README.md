# Donut demo

A tiny pair-for-coffee canister, like Slack's Donut app but gated on an
`@dfinity.org` email proven via Internet Identity's certified attributes.

Its purpose is to dogfood the `identity-attributes` Motoko library in a
realistic end-to-end scenario: a canister that takes an authorization
decision (allow-listing by email domain) based on an II-signed attribute
bundle.

## Flow

```
  Frontend (RP)              Donut canister             II frontend / backend
  ─────────────              ──────────────             ─────────────────────

  call generate_nonce() ───────────►
                                  │
                                  ├── Challenges.issue<system>(caller, 5 min)
                                  │
  ◄─────────────────── 32-byte nonce

  requestAttributes({
    keys:  ["email"],
    nonce
  }) ─────────────────────────────────────────────────► II consent + sign

  ◄─────────────────────────────── SignedAttributes { data, signature }

  wrap in AttributesIdentity
  call join_round() ───────────►
                                  │
                                  ├── II.verify<system>({
                                  │     policy = #Authorization {
                                  │       expectedOrigin = "https://donut.example.com";
                                  │       maxAgeNs       = 5 min;
                                  │     };
                                  │     nonces = ?nonces;
                                  │   })
                                  ├── II.getText(attrs, "email")
                                  ├── check suffix == "@dfinity.org"
                                  ├── pair with someone in the pool, or wait
                                  │
  ◄────────────────── #Paired { email } | #Waiting

  call my_match() ───────────►    (returns partner's email once paired)
  ◄─────────────────── ?Text
```

## Public API

| Method            | Type     | Description                                              |
|-------------------|----------|----------------------------------------------------------|
| `generate_nonce`  | update   | Issues a 32-byte nonce for the caller (TTL: 5 min).      |
| `join_round`      | update   | Verifies attributes, checks the email domain, pairs/waits. |
| `my_match`        | query    | Returns the email of the caller's match, if any.         |
| `reset`           | update   | Leaves the pool and drops any existing pairing.          |
| `pool_size`       | query    | Number of callers currently waiting for a partner.       |

## Security tier

`#Authorization` — this canister makes a *gating* decision, so it demands all
three implicit-field checks:

- `implicit:origin` must match `https://donut.example.com` (configured at
  the top of [`src/Main.mo`](src/Main.mo) — change it to your actual frontend
  origin before deploying).
- `implicit:issued_at_timestamp_ns` must be within 5 minutes.
- `implicit:nonce` must match an unconsumed, canister-issued nonce.

Every verification failure surfaces as `#Verify(<II.Error>)` so the frontend
can distinguish "user cancelled", "replay attempt", "stale bundle", etc.

## What's deliberately missing

This is a demo — it stops well short of production:

- No frontend. Wire up via the II SDK's `AuthClient.requestAttributes()` +
  `AttributesIdentity`. See the Identity Attributes design doc §"Using the
  signed attributes" for the exact JS shape.
- No round/cohort logic. First caller waits; second caller pairs with them
  immediately. A real Donut runs weekly rounds with shuffled matching.
- No rate limiting, no admin, no persistence of past pairings, no dedup
  across rounds.
- The email stored in `pool` / `matches` is treated as trusted once the
  `@dfinity.org` suffix passes — same email format check as the II
  integration tests.

## Running locally

Requires the full II + agent-js stack with ICRC-3 attribute support
(moc 1.6.0+, mo:core ≥ 2.5.0, II with the `prepare_icrc3_attributes` API,
agent-js with `AttributesIdentity`). Without those, `generate_nonce` works
but `join_round` will reject with `#Verify(#NoAttributes)` because no
`sender_info` is attached.

```bash
cd demos/donut
mops install
dfx start --clean --background
dfx deploy donut
# … then wire up the frontend against your local II.
```
