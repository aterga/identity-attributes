# Dfinsight

A "common matters of interest" board for DFINITY members. Users sign in
1-click via the DFINITY SSO at [id.ai](https://id.ai), post one
anonymous Issue per 24h, and upvote others — without ever seeing the
ranking. Admins (a fixed allowlist) can read scores, delete spam, and
post a public response that closes voting.

## How the auth works

| Role  | Sign-in URL                               | Attributes requested   | Backend gate                         |
| ----- | ----------------------------------------- | ---------------------- | ------------------------------------ |
| User  | `https://id.ai/authorize?sso=dfinity.org` | none                   | `Principal.isAnonymous == false`     |
| Admin | `https://id.ai/authorize?sso=dfinity.org` | `sso:dfinity.org:name` | `mo:identity-attributes` `II.verify` |

The user flow yields an SSO-scoped principal — stable per `(user, dapp)`
pair, but anonymous in the sense that the dapp never learns the user's
name or email. That's enough for the backend to dedupe upvotes and
enforce the rolling 24-hour post limit.

The admin flow additionally pulls a certified `name` attribute via
`AuthClient.requestAttributes`, wraps it into an `AttributesIdentity`,
and burns it once on `establishAdminSession`. After that, the canister
caches `(principal, name)` for 30 minutes so subsequent admin clicks
don't trigger fresh II popups.

## Layout

```
.
├── icp.yaml                              # icp-cli canister manifest
├── scripts/
│   └── build-backend.sh                  # mops install + moc
└── src/
    ├── dfinsight_backend/
    │   ├── main.mo                       # the canister
    │   └── mops.toml                     # core 2.5 + identity-attributes 0.1
    └── dfinsight_frontend/
        ├── index.html
        ├── package.json
        ├── tsconfig.json
        ├── vite.config.ts
        └── src/
            ├── App.tsx                   # router
            ├── main.tsx
            ├── styles.css
            ├── lib/
            │   ├── auth.ts               # signInAnonymous / signInAdmin
            │   ├── backend.ts            # actor factory
            │   ├── config.ts             # II URL, canister id, host
            │   ├── sessionStore.ts
            │   └── declarations/         # IDL + TS types (hand-rolled)
            └── pages/
                ├── Home.tsx              # landing
                ├── Issues.tsx            # signed-in user view
                ├── AdminLanding.tsx      # admin sign-in
                └── AdminPanel.tsx        # admin moderation
```

## Local development

You need:

- Node 22+
- [`icp-cli`](https://github.com/dfinity/icp-cli) v0.2.x — `npm i -g @icp-sdk/icp-cli @icp-sdk/ic-wasm`
- [`mops`](https://mops.one/) — `npm i -g ic-mops`, then `cd src/dfinsight_backend && mops toolchain use moc` once

```sh
# 1. Install JS + Motoko deps
npm install
(cd src/dfinsight_backend && mops install)

# 2. Spin up a local replica
icp network start

# 3. Build + deploy both canisters
icp deploy

# 4. Start the Vite dev server
npm run dev
```

The dev server runs on `http://localhost:5173` and talks to the local
replica on `http://127.0.0.1:4943`. Override either with the
`VITE_IC_HOST` / `VITE_DFINSIGHT_BACKEND_CANISTER_ID` env vars if your
setup differs.

## Deploying to mainnet

```sh
scripts/deploy.sh                          # default --environment ic
scripts/deploy.sh --identity arshavir      # pick a specific identity
```

The script does the two things a one-shot `icp deploy -e ic` can't:

1. **Mints both canister ids first**, then runs the actual deploy with
   `CANISTER_ID_DFINSIGHT_BACKEND` set in the env so vite bakes the
   right backend id into the frontend bundle. Without this, the bundle
   silently falls back to a local-replica id and every backend call
   fails on mainnet.
2. **Calls `setRpOrigin`** on the backend with
   `https://<frontend-id>.icp0.io` once both ids are known. `rpOrigin`
   is a stable `var` inside the actor — set once, persists across
   upgrades. Mismatch produces `#OriginMismatch` from
   `mo:identity-attributes` on every admin verify.

`trusted_attribute_signers` (II's production principal
`rdmx6-jaaaa-aaaaa-aaadq-cai`) is wired automatically via
`icp.yaml`'s `settings.environment_variables` — no extra step needed.

The admin allowlist is the actor-class init arg, declared as
`init_args` on the backend canister in `icp.yaml`:

```yaml
init_args: '(vec { "Arshavir Ter-Gabrielyan" })'
```

Edit it before the first deploy. Names must match the verified
`sso:dfinity.org:name` exactly. The list is stable, so on a running
canister you'd need `icp deploy --mode reinstall` (state-wiping) to
change it — or add a controller-gated `setAdmins` setter.

## Anti-bias design

Two things keep regular users from inferring rank:

- The list returned by `listIssuesForUser` is **shuffled** with
  on-chain entropy (`Random.blob`) on every call.
- **Scores are hidden** until an admin posts a response — only then
  does the issue surface its upvote count to everyone.

Once an admin responds, voting on that issue is locked
(`#VotesLocked`).

## What's where

| Concern                        | File                                           |
| ------------------------------ | ---------------------------------------------- |
| 24h post limit                 | `main.mo:createIssue` + `lastPostAt` map       |
| Hidden scores                  | `main.mo:listIssuesForUser` (`upvotes : ?Nat`) |
| Admin verify via `sender_info` | `main.mo:verifyAdminAttributes`                |
| 30-min admin session cache     | `main.mo:adminSessions`                        |
| 1-click SSO                    | `auth.ts:signInAnonymous`                      |
| 1-click SSO + name attribute   | `auth.ts:signInAdmin`                          |
| Shuffle                        | `main.mo:shuffle`                              |
