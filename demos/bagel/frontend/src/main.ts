import { Actor, AnonymousIdentity, HttpAgent } from "@icp-sdk/core/agent";
import { AttributesIdentity } from "@icp-sdk/core/identity";
import { Principal } from "@icp-sdk/core/principal";
import { AuthClient } from "@icp-sdk/auth/client";

import { idlFactory, type Bagel, type JoinResult } from "./bagel.did";

// ---------------------------------------------------------------- config --
// Internet Identity's canister — the principal whose signature sits on
// every attribute bundle. The bagel canister's `trusted_attribute_signers`
// env var must contain this same principal (see README → "Deploying to
// mainnet"), otherwise the IC's ingress layer will strip `sender_info`
// before it reaches our Motoko code.
const II_CANISTER_ID = "rdmx6-jaaaa-aaaaa-aaadq-cai";

const BAGEL_CANISTER_ID =
  (import.meta.env.VITE_BAGEL_CANISTER_ID as string | undefined) ??
  "uxrrr-q7777-77774-qaaaq-cai";
const IC_HOST =
  (import.meta.env.VITE_IC_HOST as string | undefined) ??
  "http://127.0.0.1:4943";
const II_URL =
  (import.meta.env.VITE_II_URL as string | undefined) ??
  "http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:4943";

const isLocal = IC_HOST.includes("127.0.0.1") || IC_HOST.includes("localhost");

// ---------------------------------------------------------------- DOM refs --
const $status    = document.getElementById("status")!;
const $principal = document.getElementById("principal")!;
const $log       = document.getElementById("log")!;
const $signIn    = document.getElementById("signIn") as HTMLButtonElement;
const $join      = document.getElementById("join")   as HTMLButtonElement;
const $match     = document.getElementById("match")  as HTMLButtonElement;
const $reset     = document.getElementById("reset")  as HTMLButtonElement;

function log(...xs: unknown[]) {
  const line = xs
    .map((x) =>
      typeof x === "string" ? x : JSON.stringify(x, replacer, 2),
    )
    .join(" ");
  $log.textContent += line + "\n";
  $log.scrollTop = $log.scrollHeight;
}

// JSON.stringify chokes on bigint + Uint8Array; show them readably instead.
function replacer(_key: string, value: unknown) {
  if (typeof value === "bigint") return value.toString() + "n";
  if (value instanceof Uint8Array)
    return "0x" + Array.from(value, (b) => b.toString(16).padStart(2, "0")).join("");
  return value;
}

// --------------------------------------------------------------- helpers --
async function makeAgent(identity: {
  getPrincipal: () => { toText: () => string };
}): Promise<HttpAgent> {
  const agent = await HttpAgent.create({
    host: IC_HOST,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- agent's
    //   Identity type drifts between sub-packages; runtime shape matches.
    identity: identity as any,
    shouldFetchRootKey: isLocal,
  });
  return agent;
}

function makeActor(agent: HttpAgent): Bagel {
  return Actor.createActor<Bagel>(idlFactory, {
    agent,
    canisterId: BAGEL_CANISTER_ID,
  });
}

// --------------------------------------------------------------- app state --
let authClient: AuthClient | null = null;
let bagel: Bagel | null = null;

function setSignedIn(principalText: string) {
  $status.textContent = "signed in";
  $principal.textContent = principalText.slice(0, 5) + "…" + principalText.slice(-5);
  $principal.hidden = false;
  $signIn.disabled = true;
  $join.disabled = false;
  $match.disabled = false;
  $reset.disabled = false;
}

// -------------------------------------------------------- II sign-in flow --
// This follows the official pattern from https://github.com/dfinity/icp-js-auth
// (see the "Requesting Identity Attributes" section), with one subtlety
// that the README example glosses over:
//
//   AuthClient.signIn() has to run *before* any `await`. Under the hood it
//   opens the II popup via window.open, which browsers only permit while
//   the user-activation gesture from the click is still live. Slip even a
//   quick HttpAgent.create() in first and Chrome throws
//     "Signer window should not be opened outside of click handler"
//   (the error bubbles up from @slide-computer/signer-web).
//
// So the order is:
//
//   1. AuthClient.signIn()                 — popup opens synchronously.
//   2. (in parallel) anon.generate_nonce() — canister commits to a nonce.
//   3. AuthClient.requestAttributes(nonce) — rides the same popup session.
//   4. Wrap the delegation in AttributesIdentity so the signed bundle is
//      attached as `sender_info` on every subsequent ingress message.
async function signIn() {
  log("→ init AuthClient (identityProvider = " + II_URL + ")");
  if (!authClient) {
    authClient = new AuthClient({ identityProvider: II_URL });
  }

  // 1. Open the II popup NOW, while we're still inside the user-activation
  //    window granted by the click handler. Any await before this and the
  //    browser blocks the window.open that signIn does internally.
  log("→ opening II for signIn (sync — inside the click-handler gesture)");
  const signInPromise = authClient.signIn();

  // 2. While the popup is open and the user is interacting with II, fetch
  //    a canister-issued nonce in parallel. The bundle's `implicit:nonce`
  //    is baked into the signature and must match something the canister
  //    has already committed to (Authorization tier of the
  //    identity-attributes design).
  log("→ calling generate_nonce() with an anonymous agent");
  const anonAgent = await makeAgent(new AnonymousIdentity());
  const bootstrap = makeActor(anonAgent);
  const nonce = await bootstrap.generate_nonce();
  log("  nonce:", nonce);

  // 3. Queue the attributes request on the already-open signer channel.
  //    Ordering: we only have a nonce to sign *now*, so this can't run in
  //    step 1. But the II UI takes seconds and generate_nonce takes
  //    hundreds of milliseconds, so this is queued well before the user
  //    completes the dance — both requests ride a single popup session.
  //
  //    We request `sso:dfinity.org:email` specifically (not bare `email`):
  //    it's the scoped key that's authoritatively verified by the
  //    @dfinity.org SSO provider, so the canister can trust the domain
  //    without a separate `isAllowed()` check. The Motoko library's
  //    scope-fallback lookup (`II.getText(attrs, "email")`) picks it up
  //    either way.
  log("→ requestAttributes(keys: [sso:dfinity.org:email])");
  const attributesPromise = authClient.requestAttributes({
    keys: ["sso:dfinity.org:email"],
    nonce,
  });

  //    `Promise.all` (rather than two sequential awaits) guarantees that
  //    if one rejects, the other's eventual settlement is still observed —
  //    no unhandled-rejection warning.
  const [, { data, signature }] = await Promise.all([
    signInPromise,
    attributesPromise,
  ]);
  log("  delegation: ok");
  log("  attributes.data.len:", data.length);
  log("  attributes.signature.len:", signature.length);

  // 4. Wrap the inner (Delegation)Identity with AttributesIdentity. This
  //    is the piece that was missing from the @slide-computer/signer flow
  //    we started with — without it, the bundle never reaches the canister
  //    and `II.verify<system>` fails with `#NoAttributes`.
  const inner = await authClient.getIdentity();
  const identity = new AttributesIdentity({
    inner,
    attributes: { data, signature },
    signer: { canisterId: Principal.fromText(II_CANISTER_ID) },
  });

  const agent = await makeAgent(identity);
  bagel = makeActor(agent);

  const p = inner.getPrincipal().toText();
  setSignedIn(p);
  log("  signed in as", p);
}

// --------------------------------------------------------- canister calls --
function formatJoin(r: JoinResult): string {
  if ("ok" in r) {
    if ("Waiting" in r.ok) return "waiting for a partner";
    return `paired with ${r.ok.Paired.email}`;
  }
  if ("Verify" in r.err) return `verify failed: ${Object.keys(r.err.Verify)[0]}`;
  if ("NoEmail" in r.err) return "no email in bundle";
  return `wrong domain: ${r.err.WrongDomain.email}`;
}

async function join() {
  if (!bagel) return;
  log("→ calling join_round()");
  try {
    const res = await bagel.join_round();
    log("  result:", formatJoin(res));
    log("  raw:", res);
  } catch (e) {
    log("  ERROR:", String(e));
  }
}

async function myMatch() {
  if (!bagel) return;
  log("→ calling my_match()");
  const opt = await bagel.my_match();
  log("  result:", opt.length === 0 ? "no match yet" : opt[0]);
}

async function reset() {
  if (!bagel) return;
  log("→ calling reset()");
  await bagel.reset();
  log("  done");
}

// ------------------------------------------------------------ wire up UI --
$signIn.addEventListener("click", () => {
  signIn().catch((e) => log("ERROR:", String(e)));
});
$join.addEventListener("click", () => join());
$match.addEventListener("click", () => myMatch());
$reset.addEventListener("click", () => reset());

log(`bagel canister: ${BAGEL_CANISTER_ID}`);
log(`II URL: ${II_URL}`);
log(`IC host: ${IC_HOST}`);
log("");
log("1. Sign in with II — single popup delivers a delegation + a signed");
log("   email attribute bundle (see @icp-sdk/auth docs).");
log("2. Join round — the wrapped AttributesIdentity attaches the bundle");
log("   as sender_info; the canister verifies origin + nonce + freshness,");
log("   then pairs you with another @dfinity.org human.");
log("3. My match — polls for the partner's email.");
