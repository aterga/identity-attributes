import { Actor, AnonymousIdentity, HttpAgent } from "@icp-sdk/core/agent";
import { AttributesIdentity } from "@icp-sdk/core/identity";
import { Principal } from "@icp-sdk/core/principal";
import { AuthClient } from "@icp-sdk/auth/client";

import { idlFactory, type Bagel, type JoinResult } from "./bagel.did";

// ---------------------------------------------------------------- config --
// Internet Identity's canister — the principal whose signature sits on
// every attribute bundle. The bagel canister's `trusted_attribute_signers`
// env var must contain this same principal (see icp.yaml), otherwise the
// IC's ingress layer will strip `sender_info` before it reaches our Motoko
// code.
const II_CANISTER_ID = "rdmx6-jaaaa-aaaaa-aaadq-cai";

const BAGEL_CANISTER_ID =
  (import.meta.env.VITE_BAGEL_CANISTER_ID as string | undefined) ??
  "uxrrr-q7777-77774-qaaaq-cai";
const IC_HOST =
  (import.meta.env.VITE_IC_HOST as string | undefined) ??
  "http://127.0.0.1:4943";

const isLocal = IC_HOST.includes("127.0.0.1") || IC_HOST.includes("localhost");

// ----------------------------------------------------- II instance toggle --
// The production deployment is at https://id.ai, the beta deployment at
// https://beta.id.ai. For local dev both roles are served from the same
// replica gateway — we still let the user pick so they can test against
// a locally-deployed beta II without recompiling.
type IIInstance = "prod" | "beta";

function defaultII(instance: IIInstance): string {
  if (isLocal) {
    return instance === "prod"
      ? "https://id.ai.localhost:4943"
      : "https://beta.id.ai.localhost:4943";
  }
  return instance === "prod" ? "https://id.ai" : "https://beta.id.ai";
}

const II_INSTANCE_KEY = "bagel.ii-instance";
function loadInstance(): IIInstance {
  const v = localStorage.getItem(II_INSTANCE_KEY);
  return v === "beta" ? "beta" : "prod";
}
function saveInstance(v: IIInstance) {
  localStorage.setItem(II_INSTANCE_KEY, v);
}

// Per-instance override via env vars (mostly for CI / custom hosts). When
// unset, `defaultII` picks the right URL for the current instance + host.
const II_URL_PROD =
  (import.meta.env.VITE_II_URL_PROD as string | undefined) ??
  (import.meta.env.VITE_II_URL as string | undefined) ?? // legacy name
  defaultII("prod");
const II_URL_BETA =
  (import.meta.env.VITE_II_URL_BETA as string | undefined) ??
  defaultII("beta");

function iiUrlFor(instance: IIInstance): string {
  return instance === "beta" ? II_URL_BETA : II_URL_PROD;
}

// AuthClient's `identityProvider` needs to point at II's `/authorize`
// endpoint — otherwise the opened window lands on the account page and
// the Signer handshake never fires.
function identityProviderFor(instance: IIInstance): string {
  const base = iiUrlFor(instance).replace(/\/+$/, "");
  return `${base}/authorize`;
}

// ---------------------------------------------------------------- DOM refs --
const $status     = document.getElementById("status")!;
const $principal  = document.getElementById("principal")!;
const $log        = document.getElementById("log")!;
const $signIn     = document.getElementById("signIn") as HTMLButtonElement;
const $join       = document.getElementById("join")   as HTMLButtonElement;
const $match      = document.getElementById("match")  as HTMLButtonElement;
const $reset      = document.getElementById("reset")  as HTMLButtonElement;
const $iiToggle   = document.getElementById("iiInstance") as HTMLSelectElement;
const $iiEndpoint = document.getElementById("iiEndpoint")!;

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
// All three are pre-populated on page load (see `bootstrap` at the bottom).
// The click handler then runs with zero blocking awaits before it calls
// `authClient.signIn()`, so the II popup always opens inside the user's
// click-gesture window. See "popup-blocker" commit for the gory details.
let iiInstance: IIInstance = loadInstance();
let authClient: AuthClient | null = null;
let pendingNonce: Promise<Uint8Array> | null = null;
let bagel: Bagel | null = null;

function setSignedIn(principalText: string) {
  $status.textContent = "signed in";
  $principal.textContent = principalText.slice(0, 5) + "…" + principalText.slice(-5);
  $principal.hidden = false;
  $signIn.disabled = true;
  $join.disabled = false;
  $match.disabled = false;
  $reset.disabled = false;
  // Don't let the user flip II instances while a delegation from the other
  // one is active — the next requestAttributes would go to a different
  // popup and confusion ensues.
  $iiToggle.disabled = true;
}

function renderEndpoint() {
  $iiEndpoint.textContent = identityProviderFor(iiInstance);
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
// So on page load we pre-build the AuthClient and kick off a canister-
// issued nonce fetch. By the time the user clicks, both are sitting in
// `authClient` and `pendingNonce`, and the click handler can call
// `authClient.signIn()` with no await standing between it and the user
// gesture.
async function signIn() {
  if (!authClient) throw new Error("AuthClient not initialised yet");
  if (!pendingNonce) throw new Error("Nonce fetch not started");

  // 1. Open the II popup NOW, while we're still inside the user-activation
  //    window granted by the click handler.
  log("→ opening II for signIn (sync — inside the click-handler gesture)");
  const signInPromise = authClient.signIn();

  // 2. Await the nonce we pre-fetched on page load. If it already resolved,
  //    this is a microtask; if not, we wait while the popup is already
  //    open (no user-gesture concern anymore). Either way we haven't
  //    blocked *before* step 1.
  const nonce = await pendingNonce;
  log("  nonce:", nonce);

  // 3. Queue the attributes request on the already-open signer channel.
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

// Flipping the toggle before sign-in changes which II the eventual click
// will talk to. After sign-in we disable it (see `setSignedIn`). A full
// reload is the safest way to flush any pre-fetched state tied to the
// previous instance (auth session, nonce, etc.).
$iiToggle.addEventListener("change", () => {
  const next = $iiToggle.value === "beta" ? "beta" : "prod";
  if (next === iiInstance) return;
  saveInstance(next);
  log(`→ switching II instance to ${next} — reloading…`);
  location.reload();
});

// ------------------------------------------------------------ bootstrap --
// Everything we can do before the first click:
//   1. render the current II endpoint for visibility
//   2. build the AuthClient (so .signIn() can be called with no `await`
//      between click and popup — see comment on signIn())
//   3. kick off generate_nonce() — it lives in `pendingNonce` for the
//      click handler to await *after* the popup is open.
$iiToggle.value = iiInstance;
renderEndpoint();

log(`bagel canister: ${BAGEL_CANISTER_ID}`);
log(`IC host:        ${IC_HOST}`);
log(`II instance:    ${iiInstance}`);
log(`II endpoint:    ${identityProviderFor(iiInstance)}`);
log("");

authClient = new AuthClient({
  identityProvider: identityProviderFor(iiInstance),
});
log("✓ AuthClient initialised (pre-click)");

pendingNonce = (async () => {
  const anonAgent = await makeAgent(new AnonymousIdentity());
  const bootstrap = makeActor(anonAgent);
  const n = await bootstrap.generate_nonce();
  // `Bagel` IDL returns `Uint8Array`-compatible `Blob`; pin the type so the
  // downstream `requestAttributes` call sees the right runtime shape.
  return n as Uint8Array;
})();
pendingNonce
  .then((n) => log("✓ pre-fetched nonce:", n))
  .catch((e) => log("✗ nonce pre-fetch failed:", String(e)));

log("");
log("1. Sign in with II — single popup delivers a delegation + a signed");
log("   email attribute bundle (see @icp-sdk/auth docs).");
log("2. Join round — the wrapped AttributesIdentity attaches the bundle");
log("   as sender_info; the canister verifies origin + nonce + freshness,");
log("   then pairs you with another @dfinity.org human.");
log("3. My match — polls for the partner's email.");
