import { Actor, AnonymousIdentity, HttpAgent } from "@icp-sdk/core/agent";
import { AuthClient } from "@icp-sdk/auth/client";
import { AttributesIdentity } from "@icp-sdk/core/identity";
import { Principal } from "@icp-sdk/core/principal";

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
// the ICRC-29 heartbeat handshake never fires.
function identityProviderFor(instance: IIInstance): string {
  const base = iiUrlFor(instance).replace(/\/+$/, "");
  return `${base}/authorize`;
}

// 8-hour delegation lifetime — matches `AuthClient`'s own default.
const MAX_TIME_TO_LIVE_NS = 8n * 60n * 60n * 1_000_000_000n;

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
// Both are built on page load so the click handler can call
// `authClient.signIn()` synchronously — the `window.open` inside it has to
// run inside the user's click gesture or Chrome's popup blocker kicks in.
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
// Two constraints collide in this handler:
//
//   (a) The `window.open` inside `authClient.signIn()` (which delegates to
//       `Signer.openChannel()` → `PostMessageTransport.establishChannel()`)
//       has to run synchronously inside the click gesture. Any `await`
//       before it and Chrome flags the eventual open as programmatic →
//       popup blocker. So we kick off `authClient.signIn(...)` *before*
//       touching `pendingNonce` and stash its promise; the `window.open`
//       inside it fires synchronously before the first await.
//
//   (b) The two JSON-RPC calls — `icrc34_delegation` and
//       `ii-icrc3-attributes` — have to share one popup. AuthClient
//       exposes them as separate methods (`signIn` + `requestAttributes`),
//       which internally both use the same `Signer` instance. The
//       Signer's default auto-close scheduler fires 200ms after each
//       response — *but* `openChannel()` calls `clearTimeout` at its
//       start, so calling `requestAttributes` immediately after `signIn`
//       resolves cancels the pending close and the same popup is reused
//       for the second request. No `await` between them → the clear
//       beats the 200 ms fire.
async function signIn() {
  if (!authClient) throw new Error("AuthClient not initialised yet");
  if (!pendingNonce) throw new Error("Nonce fetch not started");

  // 1. Kick off signIn FIRST, before any `await`. Its internal
  //    `Signer.openChannel → window.open` runs synchronously inside
  //    the click, so the popup opens unblocked.
  log("→ authClient.signIn() — popup opens inside click gesture");
  const signInPromise = authClient.signIn({
    maxTimeToLive: MAX_TIME_TO_LIVE_NS,
  });

  // 2. While the user is staring at the delegation consent screen,
  //    await the pre-fetched nonce (resolved on page load).
  const nonce = await pendingNonce;
  log("  nonce:", nonce);

  // 3. Wait for the delegation response.
  const inner = await signInPromise;
  log("  delegation: ok");

  // 4. Immediately request attributes on the SAME popup. `openChannel`
  //    inside sendRequest clears the 200ms auto-close scheduled after
  //    the delegation response, so the popup stays up for the attribute
  //    consent screen. We ask for `sso:dfinity.org:email` specifically —
  //    the scoped key authoritatively verified by the @dfinity.org SSO
  //    provider, so the canister can trust the domain without a separate
  //    `isAllowed()` check. The Motoko library's scope-fallback lookup
  //    (`II.getText(attrs, "email")`) picks it up either way.
  log("→ authClient.requestAttributes({sso:dfinity.org:email}) — same popup");
  const signedAttrs = await authClient.requestAttributes({
    keys: ["sso:dfinity.org:email"],
    nonce,
  });
  log("  attributes: data.len =", signedAttrs.data.length);
  log("  attributes: sig.len  =", signedAttrs.signature.length);

  // 5. Wrap the DelegationIdentity returned by signIn with
  //    AttributesIdentity — this injects `sender_info` on every outgoing
  //    canister call, so the bagel canister's `II.verify<system>` sees
  //    the signed bundle.
  const identity = new AttributesIdentity({
    inner,
    attributes: signedAttrs,
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
//   2. build the AuthClient (so `authClient.signIn()` can be called with
//      zero `await`s between click and `window.open` — see comment on
//      signIn()).
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
log("   email attribute bundle (icrc34_delegation + ii-icrc3-attributes,");
log("   sequential on the same Signer channel; AuthClient's default auto-");
log("   close timer is cancelled by the second call's openChannel()).");
log("2. Join round — the wrapped AttributesIdentity attaches the bundle");
log("   as sender_info; the canister verifies origin + nonce + freshness,");
log("   then pairs you with another @dfinity.org human.");
log("3. My match — polls for the partner's email.");
