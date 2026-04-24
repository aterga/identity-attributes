# Bagel demo

A tiny pair-for-coffee canister, like Slack's Donut app but gated on an
`@dfinity.org` email proven via Internet Identity's certified attributes.

Its purpose is to dogfood the `identity-attributes` Motoko library in a
realistic end-to-end scenario: a canister that takes an authorization
decision (allow-listing by email domain) based on an II-signed attribute
bundle.

## Flow

```
  Frontend (RP)              Bagel canister             II frontend / backend
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
                                  │       expectedOrigin = "https://bagel.example.com";
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

- `implicit:origin` must match `https://bagel.example.com` (configured at
  the top of [`src/Main.mo`](src/Main.mo) — change it to your actual frontend
  origin before deploying).
- `implicit:issued_at_timestamp_ns` must be within 5 minutes.
- `implicit:nonce` must match an unconsumed, canister-issued nonce.

Every verification failure surfaces as `#Verify(<II.Error>)` so the frontend
can distinguish "user cancelled", "replay attempt", "stale bundle", etc.

## Frontend

A minimal Vite + TypeScript app lives in [`frontend/`](frontend/):

```bash
cd demos/bagel/frontend
npm install
npm run dev    # Vite serves on http://localhost:5173
```

It exposes three buttons — **Sign in with II**, **Join round**,
**My match** — and logs every step (nonce, decoded attributes, canister
response) to the page so you can watch the protocol execute.

## What's deliberately missing

This is a demo — it stops well short of production:

- No round/cohort logic. First caller waits; second caller pairs with them
  immediately. A real Donut/Bagel runs weekly rounds with shuffled matching.
- No rate limiting, no admin, no persistence of past pairings, no dedup
  across rounds.
- The email stored in `pool` / `matches` is treated as trusted once the
  `@dfinity.org` suffix passes — same email format check as the II
  integration tests.

## Running locally

Requires the full II + agent-js stack with ICRC-3 attribute support
(moc 1.6.0+, mo:core ≥ 2.5.0, II with the `prepare_icrc3_attributes` API,
and an agent-js build that attaches `sender_info` to ingress messages).
Without the last piece, `generate_nonce` works but `join_round` rejects
with `#Verify(#NoAttributes)`.

```bash
cd demos/bagel
mops install
dfx start --clean --background
dfx deploy bagel

# Point the canister at your locally-deployed II (see ../../../internet-identity
# for how to spin one up), then set the trusted signer:
dfx canister call aaaaa-aa update_settings "(record {
  canister_id = principal \"$(dfx canister id bagel)\";
  settings = record {
    environment_variables = opt vec {
      record {
        name  = \"trusted_attribute_signers\";
        value = \"rdmx6-jaaaa-aaaaa-aaadq-cai\";
      }
    };
  };
})"

cd frontend
cp .env.example .env.local
# edit .env.local — set VITE_BAGEL_CANISTER_ID to the id dfx just printed
npm install && npm run dev
```

## Deploying to mainnet

Everything here works today *except* the final ingress-attachment step —
`join_round` will reject with `#Verify(#NoAttributes)` until agent-js
ships a `sender_info` hook. All the deployment plumbing is in place so
that once it does, only the frontend needs a bump.

1. **Pick the frontend origin.** Edit [`src/Main.mo:23`](src/Main.mo:23)
   (`rpOrigin`) to whatever your deployed frontend will serve from —
   either `https://<bagel_frontend-id>.icp0.io` or your custom domain.
   This is checked against `implicit:origin` and has to match exactly.

2. **Create the canisters** (you'll need a cycles wallet — see
   [the dfx cycles docs](https://internetcomputer.org/docs/building-apps/getting-started/tokens-and-cycles)):

   ```bash
   dfx canister create --network ic --all
   ```

3. **Set the trusted signer env var on the bagel canister.** The IC
   management canister accepts `environment_variables` in its settings;
   dfx's `update-settings` subcommand doesn't expose that yet, so call
   the management canister directly:

   ```bash
   BAGEL=$(dfx canister --network ic id bagel)
   dfx canister --network ic call aaaaa-aa update_settings "(record {
     canister_id = principal \"$BAGEL\";
     settings = record {
       environment_variables = opt vec {
         record {
           name  = \"trusted_attribute_signers\";
           value = \"rdmx6-jaaaa-aaaaa-aaadq-cai\";
         }
       };
     };
   })"
   ```

   `rdmx6-…-aaadq-cai` is the Internet Identity production canister —
   the only signer `mo:core/CallerAttributes` will trust.

4. **Build the frontend against mainnet.** Create
   `frontend/.env.production` from `.env.example`, setting:

   ```
   VITE_BAGEL_CANISTER_ID=<what `dfx canister --network ic id bagel` printed>
   VITE_IC_HOST=https://icp0.io
   VITE_II_URL=https://id.ai
   ```

5. **Deploy.** `dfx deploy --network ic` builds both canisters and
   uploads the frontend assets.

6. **Smoke test.** Visit `https://<bagel_frontend-id>.icp0.io`.
   Sign-in opens II once and returns both a delegation and a signed
   `sso:dfinity.org:email` bundle. `join_round` rides on an
   `AttributesIdentity` wrapper (from `@icp-sdk/core/identity`), which
   attaches the signed bundle as `sender_info` on the outgoing ingress
   call; the canister then verifies origin + nonce + freshness and
   pairs you with another `@dfinity.org` human (or puts you on the
   pool). Open the page in two browsers to see the pairing.
