import { Actor, HttpAgent } from "@icp-sdk/core/agent";
import {
  DelegationChain,
  DelegationIdentity,
  Ed25519KeyIdentity,
} from "@icp-sdk/core/identity";
import { Signer } from "@slide-computer/signer";
import { PostMessageTransport } from "@slide-computer/signer-web";

import { idlFactory, type Bagel, type JoinResult } from "./bagel.did";

// Edit these three to match your local deployment (`dfx deploy bagel`
// writes them to demos/bagel/.env — cat that file and paste).
const BAGEL_CANISTER_ID =
  (import.meta.env.VITE_BAGEL_CANISTER_ID as string | undefined) ??
  "uxrrr-q7777-77774-qaaaq-cai";
const IC_HOST =
  (import.meta.env.VITE_IC_HOST as string | undefined) ??
  "http://127.0.0.1:4943";
const II_URL =
  (import.meta.env.VITE_II_URL as string | undefined) ??
  "http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:4943";

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

// --------------------------------------------------------------- app state --
let identity: DelegationIdentity | null = null;
let bagel: Bagel | null = null;
let lastNonce: Uint8Array | null = null;

function setSignedIn(idr: DelegationIdentity) {
  identity = idr;
  const p = idr.getPrincipal().toText();
  $status.textContent = "signed in";
  $principal.textContent = p.slice(0, 5) + "…" + p.slice(-5);
  $principal.hidden = false;
  $signIn.disabled = true;
  $join.disabled = false;
  $match.disabled = false;
  $reset.disabled = false;

  const agent = new HttpAgent({ host: IC_HOST, identity: idr });
  if (IC_HOST.includes("127.0.0.1") || IC_HOST.includes("localhost")) {
    agent.fetchRootKey().catch((e) => log("fetchRootKey failed:", String(e)));
  }
  bagel = Actor.createActor<Bagel>(idlFactory, {
    agent,
    canisterId: BAGEL_CANISTER_ID,
  });
}

// -------------------------------------------------------- II sign-in flow --
async function signIn() {
  log("→ generating session key");
  const session = Ed25519KeyIdentity.generate();

  // We need a nonce from the canister BEFORE asking II for the attribute
  // bundle, so that `implicit:nonce` in the signed bundle matches one we've
  // already committed to. To call the canister we need an identity — so we
  // use the session identity directly as an anonymous-ish caller.
  const bootstrapAgent = new HttpAgent({ host: IC_HOST, identity: session });
  if (IC_HOST.includes("127.0.0.1") || IC_HOST.includes("localhost")) {
    await bootstrapAgent.fetchRootKey();
  }
  const bootstrap = Actor.createActor<Bagel>(idlFactory, {
    agent: bootstrapAgent,
    canisterId: BAGEL_CANISTER_ID,
  });

  log("→ calling generate_nonce()");
  const nonce = await bootstrap.generate_nonce();
  lastNonce = nonce;
  log("  nonce:", nonce);

  log("→ opening II for delegation + email attribute");
  const transport = new PostMessageTransport({ url: II_URL });
  const signer = new Signer({ transport, autoCloseTransportChannel: false });

  const delegationPromise = signer.delegation({
    publicKey: new Uint8Array(session.getPublicKey().toDer()),
  });

  const attrsPromise = signer
    .sendRequest({
      jsonrpc: "2.0",
      method: "ii-icrc3-attributes",
      id: crypto.randomUUID(),
      params: {
        keys: ["email"],
        // @ts-ignore — Uint8Array.fromBase64/toBase64 lacks TS types yet
        nonce: nonce.toBase64(),
      },
    })
    .then((response) => {
      if (
        !("result" in response) ||
        typeof response.result !== "object" ||
        response.result === null ||
        !("data" in response.result) ||
        !("signature" in response.result)
      ) {
        throw new Error("II returned no icrc3 attributes");
      }
      return {
        // @ts-ignore
        data: Uint8Array.fromBase64(response.result.data as string),
        // @ts-ignore
        signature: Uint8Array.fromBase64(response.result.signature as string),
      };
    });

  const [delegation, attrs] = await Promise.all([delegationPromise, attrsPromise]);
  await signer.closeChannel();

  log("  delegation: ok");
  log("  attributes.data.len:", attrs.data.length);
  log("  attributes.signature.len:", attrs.signature.length);

  // Stash the signed bundle where the agent can (in a future agent-js)
  // attach it as `sender_info` on outgoing ingress messages. For now we
  // just keep it on window for inspection.
  (window as unknown as { _bagelAttrs: unknown })._bagelAttrs = attrs;

  const idr = DelegationIdentity.fromDelegation(
    session,
    delegation as unknown as DelegationChain,
  );
  setSignedIn(idr);
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
  if (!lastNonce) log("  (heads up: no nonce issued this session)");
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
log("1. Sign in with II — fetches a canister nonce, then asks II for");
log("   a signed email attribute bundle.");
log("2. Join round — calls the canister's join_round().");
log("3. My match — polls for the partner's email.");
