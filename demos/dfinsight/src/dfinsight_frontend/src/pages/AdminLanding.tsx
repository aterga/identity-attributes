import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import {
  signInAdmin,
  preflightAdminSignIn,
  makePublicBackend,
  AdminSignInError,
} from "../lib/auth";
import type { AdminSignInPreflight } from "../lib/auth";
import { sessionStore } from "../lib/sessionStore";
import type { AdminError } from "../lib/declarations/dfinsight_backend.types";
import { nameToEmail, nameToInitials } from "../lib/admins";

function formatAdminError(e: AdminError): string {
  if ("Verify" in e) {
    const tag = Object.keys(e.Verify)[0];
    return `Attribute verification failed (${tag}). Try signing in again.`;
  }
  if ("NoName" in e)
    return "Your SSO bundle didn't include a name. Make sure you grant the name attribute.";
  if ("NotAdmin" in e) {
    return [
      `You signed in as "${e.NotAdmin.name}", which is not on the admin list.`,
      `Current admins: ${e.NotAdmin.admins.join(", ")}.`,
    ].join("\n");
  }
  if ("SessionExpired" in e) return "Session expired. Sign in again.";
  if ("NotFound" in e) return "Issue not found.";
  if ("Empty" in e) return "Response can't be empty.";
  if ("AlreadyAdmin" in e) return "That name is already an admin.";
  if ("UnknownAdmin" in e) return "That name is not on the admin list.";
  if ("LastAdmin" in e)
    return "Refused. That's the last admin. Add another first.";
  return "Unknown error.";
}

export function AdminLanding() {
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [admins, setAdmins] = useState<string[] | null>(null);
  const [preflight, setPreflight] = useState<AdminSignInPreflight | null>(null);

  // Pre-fetch the canister-issued nonce so the click handler can open
  // the signer popup synchronously. signer-js rejects popup opens that
  // aren't a direct response to a click — any awaits between the click
  // and `client.signIn()` burn the user-activation flag.
  const refreshPreflight = useCallback(() => {
    setPreflight(null);
    void preflightAdminSignIn()
      .then(setPreflight)
      .catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    void (async () => {
      const backend = await makePublicBackend();
      try {
        setAdmins(await backend.listAdmins());
      } catch {
        // Public read can fail if the canister id is wrong — let the
        // sign-in flow surface the real error.
        setAdmins([]);
      }
    })();
    refreshPreflight();
  }, [refreshPreflight]);

  const onSignIn = async () => {
    if (!preflight) return;
    setError(null);
    setBusy(true);
    try {
      const s = await signInAdmin(preflight);
      sessionStore.set(s);
      navigate("/admin/panel");
    } catch (e) {
      if (e instanceof AdminSignInError) {
        setError(formatAdminError(e.adminError));
      } else {
        setError(String(e));
      }
      // Nonce was burned (or expired) — fetch a fresh one for retry.
      refreshPreflight();
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card">
      <p className="eyebrow">Verified · sso:dfinity.org:name</p>
      <h1>
        Dfinsight <em>admin</em>.
      </h1>
      <p className="lede">
        Admins read every matter of interest with its upvote score, delete
        spam, and post a public response, which closes voting on that issue.
        Admins cannot post or upvote. That only happens from the user page.
      </p>
      <button
        onClick={onSignIn}
        disabled={busy || !preflight}
        className="primary"
      >
        {(busy || !preflight) && (
          <span className="spinner sm" aria-hidden="true" />
        )}
        {busy
          ? "Signing in…"
          : !preflight
            ? "Preparing…"
            : "Sign in as Dfinsight admin"}
      </button>

      <div className="admins">
        <AdminListHeader admins={admins} />
        <AdminList admins={admins} />
      </div>

      {error && <pre className="error">{error}</pre>}

      <p className="back-link">
        <Link to="/">← Back to board</Link>
      </p>

      <details className="info">
        <summary>How does this verify I'm an admin?</summary>
        <p>
          Sign-in opens id.ai with the DFINITY SSO 1-click flow and requests
          the verified <code>sso:dfinity.org:name</code> attribute. The backend
          canister reads it via the IC's <code>sender_info</code> mechanism
          (through <code>mo:identity-attributes</code>) and checks the name
          against the allowlist.
        </p>
      </details>
    </section>
  );
}

function AdminListHeader({ admins }: { admins: string[] | null }) {
  return (
    <div className="admins-header">
      <span className="label">Current admins</span>
      <span className="count">
        {admins === null ? "—" : `${admins.length} member${admins.length === 1 ? "" : "s"}`}
      </span>
    </div>
  );
}

function AdminList({ admins }: { admins: string[] | null }) {
  if (admins === null) return <AdminListSkeleton rows={2} />;
  if (admins.length === 0) {
    return (
      <ul className="admin-list">
        <li className="admin-empty">No admins on the allowlist.</li>
      </ul>
    );
  }
  return (
    <ul className="admin-list">
      {admins.map((name) => (
        <li key={name} className="admin-row">
          <span className="avatar" aria-hidden="true">
            {nameToInitials(name)}
          </span>
          <span className="meta">
            <span className="name">{name}</span>
            <span className="email">{nameToEmail(name)}</span>
          </span>
        </li>
      ))}
    </ul>
  );
}

export function AdminListSkeleton({ rows = 2 }: { rows?: number }) {
  return (
    <ul className="admin-list" aria-busy="true" aria-label="Loading admins">
      {Array.from({ length: rows }).map((_, i) => (
        <li key={i} className="admin-skeleton-row">
          <span className="skeleton avatar" />
          <span className="skeleton-stack">
            <span className="skeleton line med" />
            <span className="skeleton line short" />
          </span>
        </li>
      ))}
    </ul>
  );
}
