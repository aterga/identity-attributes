import { Actor, AnonymousIdentity, HttpAgent } from "@icp-sdk/core/agent";
import {
  AttributesIdentity,
  DelegationIdentity,
  Ed25519KeyIdentity,
} from "@icp-sdk/core/identity";
import { Principal } from "@icp-sdk/core/principal";
import { Signer } from "@icp-sdk/signer";
import { PostMessageTransport } from "@icp-sdk/signer/web";

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

// The `PostMessageTransport.url` needs to point at II's `/authorize`
// endpoint — otherwise the opened window lands on the account page and
// the ICRC-29 heartbeat handshake never fires.
function identityProviderFor(instance: IIInstance): string {
  const base = iiUrlFor(instance).replace(/\/+$/, "");
  return `${base}/authorize`;
}

// 8-hour delegation lifetime — same default as `@icp-sdk/auth`'s AuthClient.
const MAX_TIME_TO_LIVE_NS = 8n * 60n * 60n * 1_000_000_000n;

// Uint8Array ⇄ base64 (the JSON-RPC `ii-icrc3-attributes` payload wraps the
// nonce in a base64 string). `Uint8Array.prototype.toBase64` is the tc39
// proposal; fall back to `btoa`/`atob` on older engines. Copied from
// `@icp-sdk/auth`'s internal helpers.
function toBase64(bytes: Uint8Array): string {
  const maybe = bytes as Uint8Array & { toBase64?: () => string };
  if (typeof maybe.toBase64 === "function") return maybe.toBase64();
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++)
    binary += String.fromCharCode(bytes[i]);
  return globalThis.btoa(binary);
}
function fromBase64(str: string): Uint8Array {
  const Ctor = Uint8Array as typeof Uint8Array & {
    fromBase64?: (s: string) => Uint8Array;
  };
  if (typeof Ctor.fromBase64 === "function") return Ctor.fromBase64(str);
  const binary = globalThis.atob(str);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
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
// `signer.openChannel()`, so the II popup always opens inside the user's
// click-gesture window. See "popup-blocker" commit for the gory details.
let iiInstance: IIInstance = loadInstance();
let signer: Signer<PostMessageTransport> | null = null;
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
//   (a) `window.open` (inside PostMessageTransport.establishChannel) has to
//       run synchronously inside the click gesture. Any `await` before it
//       and Chrome flags the eventual open as programmatic → popup blocker:
//         "Signer window should not be opened outside of click handler".
//       So the Signer and the nonce are pre-built on page load and the
//       click handler hits `signer.openChannel()` with zero awaits.
//
//   (b) The two JSON-RPC calls we want — `icrc34_delegation` and
//       `ii-icrc3-attributes` — have to share one popup. The Signer's
//       default `autoCloseTransportChannel: true` schedules a 200ms close
//       timer *after each response*, so once the delegation response
//       arrives the clock starts ticking — and the user has longer than
//       200ms to read + approve the attribute-consent screen. When the
//       timer fires, `channel.close()` closes the popup and the pending
//       `ii-icrc3-attributes` promise rejects with
//         "Channel was closed before a response was received".
//       `@icp-sdk/auth`'s AuthClient hard-codes the default and doesn't
//       expose the option, which is why we drive the Signer directly
//       instead. Auto-close is OFF; we `closeChannel()` ourselves in a
//       `finally` after *both* responses are in (or the flow failed).
async function signIn() {
  if (!signer) throw new Error("Signer not initialised yet");
  if (!pendingNonce) throw new Error("Nonce fetch not started");

  // 1. Open the II popup NOW, while we're still inside the user-activation
  //    window granted by the click. `openChannel()` calls `window.open`
  //    synchronously before its first `await`, so kicking it off without
  //    awaiting is enough to hand the gesture to the popup.
  log("→ opening II popup (sync — inside the click-handler gesture)");
  const channelPromise = signer.openChannel();

  // 2. Await the nonce we pre-fetched on page load. If it already
  //    resolved, this is a microtask; the popup is already opening.
  const nonce = await pendingNonce;
  log("  nonce:", nonce);

  // 3. Fresh session key per sign-in. Ed25519 is simpler than ECDSA for a
  //    demo (private key lives in-process, no separate PartialDelegation
  //    signer to manage). II signs a delegation chain for this pubkey;
  //    every outgoing canister call is then signed with the Ed25519 key.
  const sessionKey = Ed25519KeyIdentity.generate();

  try {
    // 4. Wait for the ICRC-29 heartbeat handshake before firing requests.
    //    Not strictly needed — `sendRequest` / `requestDelegation`
    //    `openChannel` internally too — but the explicit `await` makes
    //    the error path (handshake timeout) clearer.
    await channelPromise;

    // 5. Fire both JSON-RPC requests in parallel. II processes them
    //    sequentially inside the same popup — sign-in prompt first, then
    //    the attribute-consent screen — but queuing the second request
    //    up front means the Signer has an active pending `sendRequest`
    //    at the moment the delegation response arrives, which is what
    //    keeps the channel alive (see `autoCloseTransportChannel: false`
    //    on the Signer below).
    //
    //    We request `sso:dfinity.org:email` specifically (not bare
    //    `email`): it's the scoped key that's authoritatively verified
    //    by the @dfinity.org SSO provider, so the canister can trust
    //    the domain without a separate `isAllowed()` check. The Motoko
    //    library's scope-fallback lookup (`II.getText(attrs, "email")`)
    //    picks it up either way.
    log("→ icrc34_delegation + ii-icrc3-attributes (parallel, same popup)");
    const [delegationChain, attrsResponse] = await Promise.all([
      signer.requestDelegation({
        publicKey: sessionKey.getPublicKey(),
        maxTimeToLive: MAX_TIME_TO_LIVE_NS,
      }),
      signer.sendRequest({
        jsonrpc: "2.0",
        id: crypto.randomUUID(),
        method: "ii-icrc3-attributes",
        params: {
          keys: ["sso:dfinity.org:email"],
          nonce: toBase64(nonce),
        },
      }),
    ]);
    log("  delegation: ok");

    if ("error" in attrsResponse) {
      throw new Error(
        `ii-icrc3-attributes error ${attrsResponse.error.code}: ${attrsResponse.error.message}`,
      );
    }
    const result = attrsResponse.result as
      | { data?: unknown; signature?: unknown }
      | undefined;
    if (typeof result?.data !== "string" || typeof result?.signature !== "string") {
      throw new Error(
        "ii-icrc3-attributes: response missing `data` or `signature`",
      );
    }
    const data = fromBase64(result.data);
    const signature = fromBase64(result.signature);
    log("  attributes.data.len:", data.length);
    log("  attributes.signature.len:", signature.length);

    // 6. Wrap the DelegationIdentity with AttributesIdentity — this is
    //    what injects `sender_info` on every outgoing request, letting
    //    the bagel canister's `II.verify<system>` see the signed bundle.
    const inner = DelegationIdentity.fromDelegation(sessionKey, delegationChain);
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
  } finally {
    // 7. Auto-close is off, so it's on us to close the popup — both on
    //    the happy path and if anything above threw. `closeChannel` is
    //    a no-op if the channel never opened (e.g. user dismissed II).
    await signer.closeChannel();
  }
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
//   2. build the Signer + PostMessageTransport (so `signer.openChannel()`
//      can be called with no `await` between click and `window.open` —
//      see comment on signIn()). Crucially, `autoCloseTransportChannel`
//      is disabled here so the channel survives between the delegation
//      response and the attribute-consent screen (see comment on signIn()).
//   3. kick off generate_nonce() — it lives in `pendingNonce` for the
//      click handler to await *after* the popup is open.
$iiToggle.value = iiInstance;
renderEndpoint();

log(`bagel canister: ${BAGEL_CANISTER_ID}`);
log(`IC host:        ${IC_HOST}`);
log(`II instance:    ${iiInstance}`);
log(`II endpoint:    ${identityProviderFor(iiInstance)}`);
log("");

signer = new Signer({
  transport: new PostMessageTransport({
    url: identityProviderFor(iiInstance),
  }),
  // Default is `true` with a 200 ms timer after each response. With two
  // requests on the same popup (icrc34_delegation + ii-icrc3-attributes),
  // the delegation response fires the timer while the user is still
  // reading the attribute-consent screen — the timer closes the popup
  // and the attributes request rejects with "Channel was closed".
  // We turn auto-close off and call `closeChannel` ourselves in
  // `signIn`'s finally.
  autoCloseTransportChannel: false,
});
log("✓ Signer initialised (pre-click, auto-close disabled)");

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
log("   both sent on the same Signer channel).");
log("2. Join round — the wrapped AttributesIdentity attaches the bundle");
log("   as sender_info; the canister verifies origin + nonce + freshness,");
log("   then pairs you with another @dfinity.org human.");
log("3. My match — polls for the partner's email.");
