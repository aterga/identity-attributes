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

  on page load:
    call generate_nonce() ─────────►
                                  │
                                  ├── Challenges.issue<system>(
                                  │     anon, 5 min
                                  │   )
                                  │
    ◄─────────────── 32-byte nonce
    (pre-fetched, sits in memory)

  --- user clicks "Sign in with II" ---
  signer.openChannel()  ────────────────────────────► II opens popup
                                                      (window.open runs
                                                       *sync* inside the
                                                       click gesture)

  Promise.all([
    signer.requestDelegation({ publicKey, maxTTL }),   ─► icrc34_delegation
    signer.sendRequest({                               ─► ii-icrc3-attributes
      method: "ii-icrc3-attributes",
      params: { keys: ["sso:dfinity.org:email"],
                nonce }  // pre-fetched above
    }),
  ])                                                   II consent + sign
                                                       (both requests share
                                                        the same popup)
  ◄──── DelegationChain  +  SignedAttributes { data, signature }

  signer.closeChannel()    // explicit — autoClose is off so the popup
                           // doesn't close mid-flow after the delegation
                           // response.

  wrap in AttributesIdentity
  call join_round() ───────────►
                                  │
                                  ├── II.verify<system>({
                                  │     policy = #Authorization {
                                  │       expectedOrigin = "https://bagel.example.com";
                                  │       maxAgeNs       = 5 min;
                                  │     };
                                  │     caller = anon,   // nonce lookup key
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

> **Why the nonce is stored under `Principal.anonymous()`.** The frontend
> fetches the nonce on page load — before the user signs in — with an
> anonymous agent. `Challenges.Store` is keyed by `Principal`, so if we
> keyed on the caller we'd issue under `anonymous` and consume under
> the authenticated user, losing the nonce. Keying globally is safe:
> replay is still prevented because the nonce is single-use and the
> II signature binds the nonce to the delegated user.

## Public API

| Method            | Type     | Description                                                |
|-------------------|----------|------------------------------------------------------------|
| `generate_nonce`  | update   | Issues a 32-byte nonce (TTL: 5 min, canister-global).      |
| `join_round`      | update   | Verifies attributes, checks the email domain, pairs/waits. |
| `my_match`        | query    | Returns the email of the caller's match, if any.           |
| `reset`           | update   | Leaves the pool and drops any existing pairing.            |
| `pool_size`       | query    | Number of callers currently waiting for a partner.         |

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

It exposes:

- An **II-instance toggle** at the top (production `id.ai` vs beta
  `beta.id.ai`) — the choice is stored in `localStorage` and the page
  reloads when it changes, so the pre-built `Signer` always talks to
  the instance you selected.
- Three buttons — **Sign in with II**, **Join round**, **My match** —
  plus a **Reset** escape hatch.
- A live log that shows every step (pre-fetched nonce, decoded
  attributes, canister response) so you can watch the protocol execute.

On page load the frontend pre-builds the `Signer` (with
`PostMessageTransport` pointed at the selected II) and kicks off a
`generate_nonce()` fetch, so the click handler can call
`signer.openChannel()` with zero blocking awaits in front of it —
otherwise the browser treats the eventual `window.open` as
programmatically-initiated and blocks the popup.

We drive the `Signer` directly rather than going through
[`@icp-sdk/auth`](https://js.icp.build/auth/)'s `AuthClient`. Both
`icrc34_delegation` (sign in) and `ii-icrc3-attributes` (consent to
share the email bundle) have to share one popup, and `AuthClient`
leaves the Signer's default `autoCloseTransportChannel: true` in
place — which schedules a 200 ms channel-close timer after every
response. The delegation response arrives first; the user then takes
seconds to approve the attribute-consent screen; the 200 ms timer
closes the popup in between and the pending `ii-icrc3-attributes`
promise rejects with *"Channel was closed before a response was
received"*. Constructing the `Signer` ourselves with
`autoCloseTransportChannel: false` keeps the channel alive until we
explicitly call `closeChannel()` after both responses land.

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

This demo uses [icp-cli](https://cli.internetcomputer.org) (the new
unified CLI that replaces `dfx`). Install it with:

```bash
npm install -g @icp-sdk/icp-cli @icp-sdk/ic-wasm
```

Then:

```bash
cd demos/bagel
mops install
icp network start                # replaces `dfx start --clean --background`
icp deploy bagel                 # replaces `dfx deploy bagel`

cd frontend
cp .env.example .env.local
# edit .env.local — set VITE_BAGEL_CANISTER_ID to the id icp just printed
# (or run `icp canister status bagel --id-only` from demos/bagel/)
npm install && npm run dev
```

The trusted-signer env var is declared once in [`icp.yaml`](icp.yaml)
under `canisters[bagel].settings.environment_variables.trusted_attribute_signers`,
so `icp deploy` sets it for you — no separate management-canister call.

## Deploying to mainnet

1. **Pick the frontend origin.** Edit [`src/Main.mo:23`](src/Main.mo:23)
   (`rpOrigin`) to whatever your deployed frontend will serve from —
   either `https://<bagel_frontend-id>.icp0.io` or your custom domain.
   This is checked against `implicit:origin` and has to match exactly.

2. **Create the canisters** (you'll need a cycles wallet — see
   [the icp-cli tokens/cycles docs](https://internetcomputer.org/docs/building-apps/getting-started/tokens-and-cycles)).
   If you've already got the canisters created (e.g. ported from a
   dfx deployment), pin their IDs in
   [`.icp/data/mappings/ic.ids.json`](.icp/data/mappings/ic.ids.json)
   — this repo already does that:

   ```json
   {
     "bagel": "umeux-raaaa-aaaad-agnyq-cai",
     "bagel_frontend": "ufh7l-hiaaa-aaaad-agnza-cai"
   }
   ```

   For a fresh deploy, let `icp deploy -e ic` create them and then copy
   the printed IDs into that file (so the next `deploy` upgrades in
   place instead of re-creating).

3. **Trusted signer env var** is already declared in
   [`icp.yaml`](icp.yaml); `icp deploy -e ic` applies it during
   canister settings update. `rdmx6-…-aaadq-cai` is the Internet
   Identity production canister — the only signer
   `mo:core/CallerAttributes` will trust.

4. **Build the frontend against mainnet.** Create
   `frontend/.env.production` from `.env.example`, setting at minimum:

   ```
   VITE_BAGEL_CANISTER_ID=<what `icp canister status bagel -e ic --id-only` printed>
   VITE_IC_HOST=https://icp0.io
   ```

   `VITE_II_URL_PROD` / `VITE_II_URL_BETA` are optional — when unset
   the frontend's II-instance toggle picks `https://id.ai` or
   `https://beta.id.ai` automatically.

5. **Deploy.** `icp deploy -e ic` builds both canisters and uploads
   the frontend assets.

6. **Smoke test.** Visit `https://<bagel_frontend-id>.icp0.io`.
   Use the **II instance** dropdown at the top to pick production
   (`id.ai`, default) or beta (`beta.id.ai`) — the page reloads so the
   pre-built `Signer` talks to the right endpoint. Sign-in opens II
   once and returns both a delegation and a signed
   `sso:dfinity.org:email` bundle on the same popup channel.
   `join_round` rides on an `AttributesIdentity` wrapper (from
   `@icp-sdk/core/identity`), which attaches the signed bundle as
   `sender_info` on the outgoing ingress call; the canister then
   verifies origin + nonce + freshness and pairs you with another
   `@dfinity.org` human (or puts you on the pool). Open the page in
   two browsers to see the pairing.
