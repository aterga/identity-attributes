import {
  Actor,
  AnonymousIdentity,
  Endpoint,
  HttpAgent,
  requestIdOf,
  type HttpAgentRequest,
  type Identity,
  type SignIdentity,
} from "@icp-sdk/core/agent";
import { AuthClient } from "@icp-sdk/auth/client";
import { IDL } from "@icp-sdk/core/candid";
import { Ed25519KeyIdentity } from "@icp-sdk/core/identity";
import { Principal } from "@icp-sdk/core/principal";

/**
 * Signed attributes to be included as `sender_info` in the request content.
 */
interface SignedAttributes {
  data: Uint8Array;
  signature: Uint8Array;
}

/**
 * The canister that signed the attributes.
 */
interface Signer {
  canisterId: Principal;
}

/**
 * Options for creating an {@link AttributeIdentity}.
 */
interface AttributeIdentityOptions {
  /** The inner identity to delegate signing to. */
  inner: Identity;
  /** The signed attributes to include in the request. */
  attributes: SignedAttributes;
  /** The canister that signed the attributes. */
  signer: Signer;
}

/**
 * An Identity decorator that injects `sender_info` into the request body
 * before delegating to an inner identity for signing.
 *
 * Because `sender_info` is part of the request content, it is included in the
 * representation-independent hash (`requestIdOf`) and covered by the sender's
 * signature for `call` and `query` endpoints.
 *
 * The IC does not hash `sender_info` for `read_state` requests, so the
 * decorator skips injection for that endpoint to avoid signature verification
 * failures on update-call polls.
 *
 * Drop-in replacement for `@icp-sdk/core`'s `AttributesIdentity` (which
 * injects unconditionally and trips a basic-signature mismatch on the
 * read_state polls that follow every update call). Filed upstream as
 * https://github.com/dfinity/icp-js-core/issues/1355.
 */
class AttributeIdentity implements Identity {
  readonly #inner: Identity;
  readonly #attributes: SignedAttributes;
  readonly #signer: Signer;

  constructor(options: AttributeIdentityOptions) {
    this.#inner = options.inner;
    this.#attributes = options.attributes;
    this.#signer = options.signer;
  }

  getPrincipal(): Principal {
    return this.#inner.getPrincipal();
  }

  transformRequest(request: HttpAgentRequest): Promise<unknown> {
    if (request.endpoint === Endpoint.ReadState) {
      return this.#inner.transformRequest(request);
    }
    // We MUTATE `request.body` instead of returning a fresh body object.
    // Reason: `HttpAgent.call` keeps a reference to its original `submit`
    // and computes `requestIdOf(submit)` *after* identity transformation
    // for use as the polling lookup key. If we copy, the outer `submit`
    // stays without `sender_info`, the polling request_id is the hash
    // without `sender_info`, but the IC stores the result under the hash
    // with `sender_info` — and the agent polls forever for a key that
    // doesn't exist (infinite loading). Mutating in place keeps both
    // hashes aligned.
    //
    // This is a workaround for an agent-js bug; the proper fix is to
    // recompute `requestId` from `transformedRequest.body.content` after
    // identity transformation. Filed as a follow-up to icp-js-core#1355.
    (request.body as Record<string, unknown>).sender_info = {
      signer: this.#signer.canisterId.toUint8Array(),
      info: this.#attributes.data,
      sig: this.#attributes.signature,
    };
    return this.#inner.transformRequest(request);
  }
}

import {
  idlFactory,
  type Bagel,
  type JoinResult,
  type RegisterResult,
} from "./bagel.did";

// ICRC-3 `Value` recursive variant (matches the canonical type used by
// II's attribute bundles). The `info` blob inside `SignedAttributes` is
// a Candid-encoded value of this type — typically a `#Map` whose entries
// include `email`, scoped keys like `sso:dfinity.org:email`, and the
// `implicit:*` fields (origin, nonce, issued_at_timestamp_ns).
type ICRC3Value =
  | { Nat: bigint }
  | { Int: bigint }
  | { Blob: Uint8Array }
  | { Text: string }
  | { Array: ICRC3Value[] }
  | { Map: [string, ICRC3Value][] };

const ICRC3ValueIDL = IDL.Rec();
ICRC3ValueIDL.fill(
  IDL.Variant({
    Nat: IDL.Nat,
    Int: IDL.Int,
    Blob: IDL.Vec(IDL.Nat8),
    Text: IDL.Text,
    Array: IDL.Vec(ICRC3ValueIDL),
    Map: IDL.Vec(IDL.Tuple(IDL.Text, ICRC3ValueIDL)),
  }),
);

function decodeAttributes(blob: Uint8Array): ICRC3Value {
  const [decoded] = IDL.decode([ICRC3ValueIDL], blob) as [ICRC3Value];
  return decoded;
}

// Result of the eager local verification we run right after sign-in.
// Mirrors the four implicit-field + email-domain checks that the
// canister's `#Authorization` policy + `mo:identity-attributes` would
// enforce on `join_round`. The canister-signature on the bundle isn't
// verifiable client-side (needs subnet keys), so the canister round-
// trip remains the authoritative gate — but this catches the common
// failure modes (wrong origin, wrong nonce, stale bundle, wrong
// account) before the user clicks anything.
interface AttrCheck {
  name: string;
  ok: boolean;
  detail?: string;
}
interface VerifyResult {
  ok: boolean;
  email: string | null;
  checks: AttrCheck[];
}

function bytesEqual(
  a: Uint8Array | number[] | null,
  b: Uint8Array,
): boolean {
  if (a === null) return false;
  const aArr = a instanceof Uint8Array ? a : new Uint8Array(a);
  if (aArr.length !== b.length) return false;
  for (let i = 0; i < aArr.length; i++) if (aArr[i] !== b[i]) return false;
  return true;
}

function verifyAttributesLocally(
  decoded: ICRC3Value,
  opts: {
    expectedRpOrigin: string; // already remapped via remapToLegacyDomain
    expectedNonce: Uint8Array;
    nowNs: bigint;
    maxAgeNs: bigint;
    allowedDomain: string;
  },
): VerifyResult {
  if (!("Map" in decoded)) {
    return {
      ok: false,
      email: null,
      checks: [{ name: "bundle is a Map", ok: false, detail: "got non-Map value" }],
    };
  }
  const lookup = new Map<string, ICRC3Value>(decoded.Map);
  const checks: AttrCheck[] = [];

  // 1. implicit:origin — what II attests to MUST equal what we expect
  //    (after applying `remapToLegacyDomain`, since II maps icp0.io →
  //    ic0.app for principal stability).
  const originVal = lookup.get("implicit:origin");
  const actualOrigin =
    originVal && "Text" in originVal ? originVal.Text : null;
  checks.push({
    name: "implicit:origin",
    ok: actualOrigin === opts.expectedRpOrigin,
    detail:
      actualOrigin === null
        ? "missing"
        : actualOrigin === opts.expectedRpOrigin
          ? `${actualOrigin}`
          : `expected ${opts.expectedRpOrigin}, got ${actualOrigin}`,
  });

  // 2. implicit:nonce — bytes must equal the nonce the bagel canister
  //    issued and we passed to requestAttributes. Replay protection.
  const nonceVal = lookup.get("implicit:nonce");
  const actualNonce =
    nonceVal && "Blob" in nonceVal ? nonceVal.Blob : null;
  checks.push({
    name: "implicit:nonce",
    ok: bytesEqual(actualNonce, opts.expectedNonce),
    detail:
      actualNonce === null ? "missing" : "matches the canister-issued nonce",
  });

  // 3. implicit:issued_at_timestamp_ns — within the freshness window.
  const tsVal = lookup.get("implicit:issued_at_timestamp_ns");
  const actualTs = tsVal && "Nat" in tsVal ? tsVal.Nat : null;
  if (actualTs === null) {
    checks.push({ name: "freshness", ok: false, detail: "implicit:issued_at_timestamp_ns missing" });
  } else {
    const ageNs = opts.nowNs - actualTs;
    const ok = ageNs >= 0n && ageNs <= opts.maxAgeNs;
    const ageSec = ageNs / 1_000_000_000n;
    const maxSec = opts.maxAgeNs / 1_000_000_000n;
    checks.push({
      name: "freshness",
      ok,
      detail: ok
        ? `${ageSec}s old (≤ ${maxSec}s)`
        : ageNs < 0n
          ? `bundle issued ${-ageSec}s in the future — clock skew?`
          : `bundle is ${ageSec}s old (> ${maxSec}s)`,
    });
  }

  // 4. email domain — scope-fallback lookup, must end with @<allowedDomain>.
  const email = getMapText(decoded, "email");
  const allowed =
    email !== null && email.toLowerCase().endsWith("@" + opts.allowedDomain);
  checks.push({
    name: `email domain @${opts.allowedDomain}`,
    ok: allowed,
    detail:
      email === null
        ? "no email attribute in bundle"
        : allowed
          ? email
          : `got ${email}`,
  });

  return { ok: checks.every((c) => c.ok), email, checks };
}

// Render an ICRC-3 Value as a one-line human-readable string. Used by the
// DEBUG dump to show the full decoded attribute map.
function renderValue(v: ICRC3Value): string {
  if ("Text"  in v) return JSON.stringify(v.Text);
  if ("Nat"   in v) return v.Nat.toString();
  if ("Int"   in v) return v.Int.toString();
  if ("Blob"  in v) {
    // IDL decodes vec nat8 as either Uint8Array or number[] depending on
    // version; either way it's iterable.
    const bytes = v.Blob as Iterable<number>;
    return "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  if ("Array" in v) return "[" + v.Array.map(renderValue).join(", ") + "]";
  return (
    "{" +
    v.Map.map(([k, vv]) => `${JSON.stringify(k)}: ${renderValue(vv)}`).join(", ") +
    "}"
  );
}

// Look up `key` in a `#Map` value. Mirrors the scope-fallback behaviour of
// `mo:identity-attributes`'s `Attributes.get`: if `key` has no scope, also
// match any `<scope>:key` entry, preferring the bare match. We split on the
// LAST `:` because scopes themselves contain colons (e.g. `openid:https://…`).
function getMapText(value: ICRC3Value, key: string): string | null {
  if (!("Map" in value)) return null;
  let scoped: string | null = null;
  for (const [k, v] of value.Map) {
    if (k === key) {
      if ("Text" in v) return v.Text;
      return null;
    }
    if (!key.includes(":")) {
      const idx = k.lastIndexOf(":");
      if (idx > 0 && k.slice(idx + 1) === key && "Text" in v) {
        scoped = v.Text;
      }
    }
  }
  return scoped;
}

// ---------------------------------------------------------------- config --
// Internet Identity's canister IDs — the principal whose signature sits
// on every attribute bundle (and on the delegation chain). The bagel
// canister's `trusted_attribute_signers` env var must contain whichever
// one we're signing in against, otherwise the IC's ingress layer will
// strip `sender_info` before it reaches our Motoko code.
//
// We have to pass the *correct* signer ID into AttributesIdentity:
// the IC validates that `sender_info.signer` matches the canister that
// issued the delegation in `sender_pubkey`. A mismatch surfaces as
//   "Invalid sender info: signer X does not match canister ID Y in
//    sender_pubkey"
// at /api/v4/.../call.
const II_CANISTER_ID_PROD = "rdmx6-jaaaa-aaaaa-aaadq-cai";
const II_CANISTER_ID_BETA = "fgte5-ciaaa-aaaad-aaatq-cai";

function iiCanisterIdFor(instance: IIInstance): string {
  return instance === "beta" ? II_CANISTER_ID_BETA : II_CANISTER_ID_PROD;
}

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

// Domain we gate access on, both client-side (UX) and inside the canister
// (`Main.mo:38` — the canister-side check is the one that's actually
// trusted; this is here purely so non-DFINITY users get a clear message
// before they click Join).
const ALLOWED_DOMAIN = "dfinity.org";

// Freshness window we apply to `implicit:issued_at_timestamp_ns`. Mirrors
// the canister-side `maxAttrAgeNs` in `src/Main.mo` so the eager local
// check matches what `II.verify<system>` will enforce.
const MAX_ATTR_AGE_NS = 5n * 60n * 1_000_000_000n;

// Copied verbatim from the II repo at
// `src/frontend/src/lib/utils/iiConnection.ts:998` so this demo's local
// origin check matches what II actually attests to in the bundle's
// `implicit:origin`. II rewrites the new `<canister>.icp0.io` domain
// back to `<canister>.ic0.app` to keep principals stable for dapps that
// pre-date the icp0.io rollout.
function remapToLegacyDomain(origin: string): string {
  const ORIGIN_MAPPING_REGEX =
    /^https:\/\/(?<subdomain>[\w-]+(?:\.raw)?)\.icp0\.io$/;
  const match = origin.match(ORIGIN_MAPPING_REGEX);
  const subdomain = match?.groups?.subdomain;
  return subdomain !== undefined ? `https://${subdomain}.ic0.app` : origin;
}

// Default attribute keys we ask II to include in the bundle. Override
// with `?keys=email,sso:dfinity.org:email,name` (comma-separated) for
// triage — useful when comparing what beta II returns for scoped vs
// bare keys without having to redeploy. The Motoko library's scope-
// fallback lookup handles either form on the canister side.
const DEFAULT_REQUEST_KEYS = ["sso:dfinity.org:email"];
function requestKeys(): string[] {
  const qs = new URLSearchParams(location.search).get("keys");
  if (qs === null) return DEFAULT_REQUEST_KEYS;
  return qs
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// Toggle with `?debug=1` to dump byte-level info for the attribute bundle
// and to additionally exercise `join_round()` with a *bare* DelegationIdentity
// (no AttributesIdentity). The bare call should reach the canister and fail
// inside with `#NoAttributes`; if it instead 400s with the same EcdsaP256
// signature error, the IC ingress signature path is broken independent of
// `sender_info`.
const DEBUG = new URLSearchParams(location.search).has("debug");

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function hexHead(bytes: Uint8Array, n = 16): string {
  return hex(bytes.slice(0, n)) + (bytes.length > n ? "…" : "");
}
function hexTail(bytes: Uint8Array, n = 16): string {
  return (bytes.length > n ? "…" : "") + hex(bytes.slice(-n));
}

// ---------------------------------------------------------------- DOM refs --
const $status     = document.getElementById("status")!;
const $principal  = document.getElementById("principal")!;
const $email      = document.getElementById("email")!;
const $gate       = document.getElementById("gate")!;
const $log        = document.getElementById("log")!;
const $signIn     = document.getElementById("signIn") as HTMLButtonElement;
const $join       = document.getElementById("join")   as HTMLButtonElement;
const $match      = document.getElementById("match")  as HTMLButtonElement;
const $reset      = document.getElementById("reset")  as HTMLButtonElement;
const $iiToggle   = document.getElementById("iiInstance") as HTMLSelectElement;
const $iiEndpoint = document.getElementById("iiEndpoint")!;
const $iiControls = document.getElementById("iiControls")!;

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
// Session signing key, generated once on page load and passed to AuthClient
// so each `signIn` reuses it. Match the test-app reference at
// `dfinity/internet-identity/demos/test-app/src/index.tsx` which does the
// same with Ed25519 — AuthClient's *default* (ECDSAKeyIdentity P-256) is
// what produced the "Invalid basic signature: EcdsaP256" ingress error.
let sessionIdentity: SignIdentity | null = null;
let pendingNonce: Promise<Uint8Array> | null = null;
// Regular Bagel actor — backed by the plain DelegationIdentity (no
// AttributesIdentity wrap, so no sender_info on the wire). Used for
// every method *except* `register()`, which is the one and only call
// that needs the bundle attached.
let bagel: Bagel | null = null;
// AttributesIdentity-wrapped actor — used exclusively for `register()`.
// Once the canister has remembered the caller as a known DFINITY
// employee, no further calls need the bundle.
let bagelForRegister: Bagel | null = null;

function setSignedIn(
  principalText: string,
  verify: VerifyResult | null,
  register: RegisterResult | { thrown: string } | null,
) {
  $status.textContent = "signed in";
  $principal.textContent = principalText.slice(0, 5) + "…" + principalText.slice(-5);
  $principal.hidden = false;
  $signIn.disabled = true;
  // Don't let the user flip II instances while a delegation from the other
  // one is active — the next requestAttributes would go to a different
  // popup and confusion ensues.
  $iiToggle.disabled = true;

  if (verify?.email) {
    $email.textContent = verify.email;
    $email.hidden = false;
  }

  // Decide who's the gating authority:
  //   - register.ok  → cleared, enable Join
  //   - register.err → canister rejected, block (show their error)
  //   - register === null AND verify failed → never even attempted the
  //     canister call; show the local failure list
  //   - register thrown → IC ingress error (the EcdsaP256/Ed25519 bug);
  //     show that
  const registered = register !== null && "ok" in register;
  const registerRejected = register !== null && "err" in register;
  const registerThrown = register !== null && "thrown" in register;
  const emailFailedDomain =
    verify !== null &&
    !verify.ok &&
    verify.checks.some(
      (c) => c.name === `email domain @${ALLOWED_DOMAIN}` && !c.ok,
    );

  if (registered) {
    // Successful end state — Sign In has done its job, hide it. The
    // round-trip buttons appear here for the first time.
    $gate.className = "gate gate-ok";
    $gate.innerHTML =
      `Welcome, <code>${escapeHtml((register as { ok: { email: string } }).ok.email)}</code> ` +
      `— canister verified the bundle, you're cleared for coffee.`;
    $gate.hidden = false;
    $signIn.hidden = true;
    $join.hidden = false;
    $match.hidden = false;
    $reset.hidden = false;
    $join.disabled = false;
    $match.disabled = false;
    $reset.disabled = false;
    return;
  }

  // Failure path — explain why, keep the round-trip buttons hidden, and
  // re-enable Sign In so the user can retry (e.g. with a different
  // account).
  $gate.className = "gate gate-block";
  if (registerRejected) {
    const err = (register as { err: unknown }).err;
    $gate.innerHTML =
      `Canister rejected the bundle: <code>${escapeHtml(JSON.stringify(err))}</code>.`;
  } else if (registerThrown) {
    $gate.innerHTML =
      `Canister round-trip failed (IC ingress refused the call): ` +
      `<code>${escapeHtml((register as { thrown: string }).thrown)}</code>.`;
  } else if (emailFailedDomain && verify?.email) {
    $gate.innerHTML =
      `Sorry, <code>${escapeHtml(verify.email)}</code> isn't on the guest list — ` +
      `Bagel is only open to members of the DFINITY Foundation. ` +
      `If you are a member, please sign in with your <code>@${ALLOWED_DOMAIN}</code> ` +
      `email via the SSO option in Internet Identity.`;
  } else if (verify === null) {
    $gate.textContent =
      `Couldn't decode the attribute bundle returned by Internet Identity. ` +
      `See the log for details.`;
  } else {
    const failedItems = verify.checks
      .filter((c) => !c.ok)
      .map((c) => `<li><code>${escapeHtml(c.name)}</code>${c.detail ? ` — ${escapeHtml(c.detail)}` : ""}</li>`)
      .join("");
    $gate.innerHTML =
      `Local verification failed — the canister would reject this bundle:` +
      `<ul style="margin: 0.5rem 0 0 1.25rem; padding: 0;">${failedItems}</ul>`;
  }
  $gate.hidden = false;
  // The pre-fetched nonce was consumed by the failed register attempt,
  // so re-enabling Sign In would just hit `#UnknownNonce` next time.
  // Tell the user to reload (which kicks off a fresh nonce + AuthClient).
  $signIn.hidden = true;
  $join.hidden = true;
  $match.hidden = true;
  $reset.hidden = true;
  $iiToggle.disabled = false;
}

function showVerifying() {
  $gate.className = "gate gate-busy";
  $gate.innerHTML =
    `<span class="spin" aria-hidden="true">🥯</span> ` +
    `Verifying your DFINITY membership with the canister…`;
  $gate.hidden = false;
  $signIn.disabled = true;
  $join.disabled = true;
  $match.disabled = true;
  $reset.disabled = true;
  $iiToggle.disabled = true;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!,
  );
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
//       popup blocker. So `authClient.signIn(...)` is the very first call
//       in this function — the `window.open` inside it fires synchronously
//       before the first await.
//
//   (b) Both ICRC-25 calls — `icrc34_delegation` and
//       `ii-icrc3-attributes` — share one popup. AuthClient exposes them
//       as separate methods that internally use the same `Signer`
//       instance. We fire them in parallel: signIn opens the channel,
//       requestAttributes piggybacks on it as soon as the pre-fetched
//       nonce resolves. II processes the two requests on the same
//       channel and the user sees both consent screens in one popup
//       session.
async function signIn() {
  if (!authClient) throw new Error("AuthClient not initialised yet");
  if (!pendingNonce) throw new Error("Nonce fetch not started");

  // Local binding so the closure below sees a non-null `client`.
  const client = authClient;

  log("→ authClient.signIn() + requestAttributes() — parallel, single popup");

  // 1. Kick off signIn FIRST, before any `await`. Its internal
  //    `Signer.openChannel → window.open` runs synchronously inside the
  //    click, so the popup opens unblocked.
  const signInPromise = client.signIn({
    maxTimeToLive: MAX_TIME_TO_LIVE_NS,
  });

  // 2. Kick off requestAttributes alongside it. Wrapped in an inline
  //    async so it can await the pre-fetched nonce *without* delaying
  //    the synchronous signIn call above. We ask for
  //    `sso:dfinity.org:email` specifically — the scoped key
  //    authoritatively verified by the @dfinity.org SSO provider, so
  //    the canister can trust the domain without a separate
  //    `isAllowed()` check. The Motoko library's scope-fallback lookup
  //    (`II.getText(attrs, "email")`) picks it up either way.
  const keys = requestKeys();
  const attrsPromise = pendingNonce.then((nonce) => {
    log("  nonce:", nonce);
    log("  requesting keys:", JSON.stringify(keys));
    return client.requestAttributes({ keys, nonce });
  });

  // 3. Both responses come back on the same channel. AuthClient v6.2.1
  //    populates the JSON-RPC `id` on requestAttributes (6.2.0 didn't,
  //    which made the response unmatchable and the channel auto-close
  //    timer fire) — so Promise.all here resolves cleanly.
  const [inner, signedAttrs] = await Promise.all([
    signInPromise,
    attrsPromise,
  ]);
  log("  delegation: ok");
  log("  attributes: data.len =", signedAttrs.data.length);
  log("  attributes: sig.len  =", signedAttrs.signature.length);

  // Decode the attribute bundle locally and run the four implicit-field
  // + email-domain checks the canister will enforce on `join_round`.
  // Caught here, surfaced in the gate banner — the user gets a clear
  // verdict without having to click anything (and the canister round-
  // trip stays as the authoritative gate via `II.verify<system>`).
  let verifyResult: VerifyResult | null = null;
  try {
    const decoded = decodeAttributes(signedAttrs.data);
    if (DEBUG && "Map" in decoded) {
      log("  [debug] decoded bundle (" + decoded.Map.length + " entries):");
      for (const [k, v] of [...decoded.Map].sort(([a], [b]) => a.localeCompare(b))) {
        log("    " + k + " = " + renderValue(v));
      }
    }
    const expectedRpOrigin = remapToLegacyDomain(window.location.origin);
    // pendingNonce already resolved by the time we get here (we awaited
    // it inside attrsPromise above), so this is a no-cost re-await.
    const nonceForVerify = await pendingNonce;
    verifyResult = verifyAttributesLocally(decoded, {
      expectedRpOrigin,
      expectedNonce: nonceForVerify,
      nowNs: BigInt(Date.now()) * 1_000_000n,
      maxAgeNs: MAX_ATTR_AGE_NS,
      allowedDomain: ALLOWED_DOMAIN,
    });
    log("  local verification: " + (verifyResult.ok ? "✓ all checks pass" : "✗ failed"));
    for (const c of verifyResult.checks) {
      log("    " + (c.ok ? "✓" : "✗") + " " + c.name + (c.detail ? " — " + c.detail : ""));
    }
  } catch (e) {
    log("  ✗ failed to decode/verify attribute bundle:", String(e));
  }

  if (DEBUG) {
    const signerBytes = Principal.fromText(iiCanisterIdFor(iiInstance)).toUint8Array();
    log("  [debug] sender_info.signer:", iiCanisterIdFor(iiInstance));
    log("  [debug] sender_info.signer.bytes (len, hex):",
        signerBytes.length, hex(signerBytes));
    log("  [debug] sender_info.info head/tail:",
        hexHead(signedAttrs.data), "/", hexTail(signedAttrs.data));
    log("  [debug] sender_info.sig  head/tail:",
        hexHead(signedAttrs.signature), "/", hexTail(signedAttrs.signature));

    // Compute the request_id agent-js would produce for a hypothetical
    // join_round() body WITH and WITHOUT sender_info. Any IC team member
    // can take these hashes + the same body fields and verify whether
    // the IC computes a matching value — giving us a clean repro for
    // the basic-signature mismatch bug.
    const sampleBody = {
      request_type: "call",
      canister_id: Principal.fromText(BAGEL_CANISTER_ID),
      method_name: "join_round",
      arg: new Uint8Array([68, 73, 68, 76, 0, 0]), // empty Candid args
      sender: inner.getPrincipal(),
      ingress_expiry: 0n,
    };
    const idWithout = requestIdOf(sampleBody);
    const idWith = requestIdOf({
      ...sampleBody,
      sender_info: {
        signer: signerBytes,
        info: signedAttrs.data,
        sig: signedAttrs.signature,
      },
    });
    log("  [debug] sample request_id WITHOUT sender_info:", hex(idWithout));
    log("  [debug] sample request_id WITH    sender_info:", hex(idWith));
    log("  [debug] (ingress_expiry pinned to 0n for reproducibility)");
  }

  // 4. Build two actors:
  //    - `bagelForRegister`: `AttributeIdentity` wraps the inner
  //      DelegationIdentity so `sender_info` rides on the `/call`
  //      ingress message — but NOT on the `/read_state` polls that
  //      follow (the IC's read_state hash doesn't include sender_info,
  //      so injecting it there breaks signature verification).
  //    - `bagel`: plain DelegationIdentity, no sender_info — used for
  //      every other call (`join_round`, `my_match`, `reset`).
  //    The signer canister ID has to match the canister that *issued*
  //    the delegation in `sender_pubkey` — beta II for `beta.id.ai`,
  //    prod II for `id.ai`.
  const attrIdentity = new AttributeIdentity({
    inner,
    attributes: signedAttrs,
    signer: {
      canisterId: Principal.fromText(iiCanisterIdFor(iiInstance)),
    },
  });
  bagelForRegister = makeActor(await makeAgent(attrIdentity));
  bagel            = makeActor(await makeAgent(inner));

  const p = inner.getPrincipal().toText();
  log("  signed in as", p);

  // 5. Skip the canister round-trip if local checks already failed —
  //    the canister would just re-discover the same problem. Surface
  //    the local verdict in the gate banner.
  if (verifyResult === null || !verifyResult.ok) {
    setSignedIn(p, verifyResult, null);
    return;
  }

  // 6. Authoritative server-side verification. Sends the bundle to the
  //    canister via `register()`, which runs `II.verify<system>` and,
  //    on success, remembers the caller's principal as a known DFINITY
  //    employee. From then on, `join_round()` etc. just look the caller
  //    up — no bundle needed on subsequent calls.
  log("→ bagel.register() — canister verifies the bundle and remembers caller");
  showVerifying();
  let registerOutcome: RegisterResult | { thrown: string } | null = null;
  try {
    registerOutcome = await bagelForRegister.register();
    if ("ok" in registerOutcome) {
      log("  ✓ canister verified — registered as", registerOutcome.ok.email);
    } else {
      log("  ✗ canister rejected:", JSON.stringify(registerOutcome.err));
    }
  } catch (e) {
    registerOutcome = { thrown: String(e) };
    log("  ✗ register() failed:", String(e));
  }

  setSignedIn(p, verifyResult, registerOutcome);
}

// --------------------------------------------------------- canister calls --
function formatJoin(r: JoinResult): string {
  if ("ok" in r) {
    if ("Waiting" in r.ok) return "waiting for a partner";
    return `paired with ${r.ok.Paired.email}`;
  }
  return "not registered (call register() first via re-sign-in)";
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

// In non-debug mode the live log is just noise for the end user. Hide it
// outright; everything the user needs to act on is in the gate banner.
// The II-instance selector is also developer-only — regular users
// should always go through production II without choosing.
if (!DEBUG) {
  $log.hidden = true;
} else {
  $iiControls.hidden = false;
}

// In DEBUG mode, instrument globalThis.fetch so the actual CBOR-encoded
// request body that goes on the wire for /api/v4/.../call (and the
// related /read_state) is captured. This is the body the IC computes
// the request_id from and verifies the basic signature against. Pairing
// this dump with our agent-side request_id (logged below) lets anyone
// reproduce the verification offline and pinpoint where (if at all)
// agent-js's hash diverges from the IC's.
if (DEBUG) {
  const origFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : (input as Request).url;
    const isCall = url.includes("/canister/") && url.endsWith("/call");
    const isReadState = url.includes("/canister/") && url.endsWith("/read_state");
    if ((isCall || isReadState) && init?.body) {
      const b = init.body;
      let bytes: Uint8Array | null = null;
      if (b instanceof Uint8Array) bytes = b;
      else if (b instanceof ArrayBuffer) bytes = new Uint8Array(b);
      else if (ArrayBuffer.isView(b)) bytes = new Uint8Array(b.buffer);
      if (bytes) {
        const tag = isCall ? "call" : "read_state";
        log(`  [debug] ${tag} body (${bytes.length} bytes): ${hex(bytes)}`);
      }
    }
    return origFetch(input, init);
  };
}

log(`bagel canister: ${BAGEL_CANISTER_ID}`);
log(`IC host:        ${IC_HOST}`);
log(`II instance:    ${iiInstance}`);
log(`II endpoint:    ${identityProviderFor(iiInstance)}`);
log(`request keys:   ${JSON.stringify(requestKeys())}`);
if (DEBUG) {
  log("DEBUG mode ON  — sender_info bytes + full /call CBOR body will be");
  log("                 dumped to this log. (In non-debug mode this whole");
  log("                 log section is hidden from the user.)");
}
log("");

sessionIdentity = Ed25519KeyIdentity.generate();
authClient = new AuthClient({
  identity: sessionIdentity,
  identityProvider: identityProviderFor(iiInstance),
});
log("✓ AuthClient initialised (pre-click, Ed25519 session key)");

// Initial gate state: Sign In is disabled (set in HTML) until the nonce
// pre-fetch resolves. Surface the wait so the user knows something is
// happening and that they can't interact yet.
$gate.className = "gate gate-busy";
$gate.innerHTML =
  `<span class="spin" aria-hidden="true">🥯</span> ` +
  `Preparing a fresh challenge from the canister…`;
$gate.hidden = false;

pendingNonce = (async () => {
  const anonAgent = await makeAgent(new AnonymousIdentity());
  const bootstrap = makeActor(anonAgent);
  const n = await bootstrap.generate_nonce();
  // `Bagel` IDL returns `Uint8Array`-compatible `Blob`; pin the type so the
  // downstream `requestAttributes` call sees the right runtime shape.
  return n as Uint8Array;
})();
pendingNonce
  .then((n) => {
    log("✓ pre-fetched nonce:", n);
    // Nonce is in hand — let the user click Sign In, and clear the
    // "preparing" banner.
    $signIn.disabled = false;
    $gate.hidden = true;
  })
  .catch((e) => {
    log("✗ nonce pre-fetch failed:", String(e));
    $gate.className = "gate gate-block";
    $gate.textContent =
      "Couldn't reach the bagel canister to get a fresh challenge. " +
      "Reload the page to try again.";
    $gate.hidden = false;
  });

log("");
log("1. Sign in with II — single popup delivers a delegation + a signed");
log("   email attribute bundle (icrc34_delegation + ii-icrc3-attributes,");
log("   fired in parallel via Promise.all on the same AuthClient — both");
log("   share one PostMessageTransport channel). Right after, we call");
log("   bagel.register() with sender_info attached so the canister can");
log("   verify the bundle and remember this principal as a known");
log("   DFINITY employee.");
log("2. Join round — plain DelegationIdentity (no sender_info on the");
log("   wire). The canister just looks the caller up in `registered`");
log("   and pairs them with another waiting @dfinity.org human.");
log("3. My match — polls for the partner's email.");
