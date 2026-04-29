import { AuthClient } from "@icp-sdk/auth/client";
import { AnonymousIdentity } from "@icp-sdk/core/agent";
import type { Identity } from "@icp-sdk/core/agent";
import { AttributesIdentity } from "@icp-sdk/core/identity";
import { Principal } from "@icp-sdk/core/principal";

import { II_URL, II_CANISTER_ID } from "./config";
import { makeAnonymousBackend, makeBackend } from "./backend";
import type { DfinsightBackend } from "./declarations/dfinsight_backend.types";

export type Session =
  | { kind: "anon"; identity: Identity; backend: DfinsightBackend }
  | {
      kind: "admin";
      identity: Identity;
      backend: DfinsightBackend;
      // Inner principal — what the backend sees as `caller`.
      principal: string;
      // Verified name from the SSO attribute bundle.
      name: string;
      // Server-side admin session expiry (nanoseconds since epoch).
      expiresAtNs: bigint;
    };

export class AdminSignInError extends Error {
  constructor(public adminError: import("./declarations/dfinsight_backend.types").AdminError) {
    super("admin sign-in failed");
  }
}

let authClient: AuthClient | null = null;

// Synchronous so it can be called from inside a click handler without
// burning the browser's user-activation flag on a microtask.
function getClient(): AuthClient {
  if (!authClient) {
    authClient = new AuthClient({ identityProvider: II_URL });
  }
  return authClient;
}

/// 1-click anonymous-ish sign-in via the DFINITY SSO discovery flow.
/// The backend sees a stable principal (so we can dedupe upvotes and
/// enforce the 24h post limit) but never the user's name or email.
export async function signInAnonymous(): Promise<Session> {
  const client = getClient();
  await client.signIn();
  const identity = await client.getIdentity();
  const backend = await makeBackend(identity);
  return { kind: "anon", identity, backend };
}

/// Cached admin sign-in prep — the nonce, fetched from the canister
/// before the user clicks. signer-js requires the SSO popup to open
/// synchronously inside the click handler, which means we cannot await
/// anything (including the nonce fetch) between the click and
/// `client.signIn()`. The page calls `preflightAdminSignIn` on mount
/// and hands the result back into `signInAdmin`.
export interface AdminSignInPreflight {
  nonce: Uint8Array;
}

export async function preflightAdminSignIn(): Promise<AdminSignInPreflight> {
  // Warm the AuthClient so its constructor isn't on the click path.
  getClient();
  const bootstrap = await makeAnonymousBackend();
  const nonceRaw = await bootstrap.generate_nonce();
  const nonce =
    nonceRaw instanceof Uint8Array ? nonceRaw : new Uint8Array(nonceRaw);
  return { nonce };
}

/// 1-click admin sign-in. Same SSO flow, but we *also* request the
/// `sso:dfinity.org:name` attribute and wrap the session identity in
/// `AttributesIdentity` so the bundle rides on every ingress message
/// (where the canister picks it up via `mo:core/CallerAttributes`).
///
/// Must be called synchronously inside a click handler — pass the
/// `AdminSignInPreflight` from a `useEffect` mount-time call so this
/// function does no awaits before opening the signer popup.
export async function signInAdmin(
  preflight: AdminSignInPreflight,
): Promise<Session> {
  const client = getClient();

  // signIn + requestAttributes in one popup. `Promise.all` rather than
  // two awaits — if signIn rejects, we still observe the
  // requestAttributes settlement. Both must be invoked synchronously
  // (no awaits between here and the click) or signer-js refuses to
  // open the popup ("channels must be established in a click handler").
  const signInPromise = client.signIn();
  const attributesPromise = client.requestAttributes({
    keys: ["sso:dfinity.org:name"],
    nonce: preflight.nonce,
  });
  const [, { data, signature }] = await Promise.all([
    signInPromise,
    attributesPromise,
  ]);

  // 3. Wrap with AttributesIdentity. Without this the bundle never
  //    reaches the canister and `II.verify<system>` returns
  //    `#NoAttributes`.
  const inner = await client.getIdentity();
  const identity = new AttributesIdentity({
    inner,
    attributes: { data, signature },
    signer: { canisterId: Principal.fromText(II_CANISTER_ID) },
  });

  const backend = await makeBackend(identity);

  // 4. Burn the bundle on the backend's `establishAdminSession`. This
  //    is what verifies the caller is *actually* on the admin allowlist
  //    — the SSO popup itself only proves they have an `sso:dfinity.org`
  //    identity and a `name` attribute. If the name isn't in the list,
  //    the backend returns `#NotAdmin { name; admins }` and we surface
  //    that to the UI via `AdminSignInError`.
  const res = await backend.establishAdminSession();
  if ("err" in res) throw new AdminSignInError(res.err);

  return {
    kind: "admin",
    identity,
    backend,
    principal: inner.getPrincipal().toText(),
    name: res.ok.name,
    expiresAtNs: res.ok.expiresAt,
  };
}

export async function signOut(): Promise<void> {
  const client = getClient();
  await client.logout();
}

/// Returns the cached session if still valid, or null. Useful for
/// hydrating the UI on page load without forcing another sign-in.
export async function restoreAnonSession(): Promise<Session | null> {
  const client = getClient();
  if (!client.isAuthenticated()) return null;
  const identity = await client.getIdentity();
  // We can't tell from the cached identity alone whether the user
  // originally signed in for the admin path or the anon path —
  // attribute identities aren't restored from storage in @icp-sdk/auth.
  // Treat restored sessions as anon; the admin page re-runs the full
  // attribute flow on demand.
  if (identity.getPrincipal().isAnonymous()) return null;
  const backend = await makeBackend(identity);
  return { kind: "anon", identity, backend };
}

export async function makePublicBackend(): Promise<DfinsightBackend> {
  // Publicly-readable methods (`listAdmins`) work fine as anonymous.
  return makeBackend(new AnonymousIdentity());
}
