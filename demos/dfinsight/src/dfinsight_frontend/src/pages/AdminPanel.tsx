import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { sessionStore } from "../lib/sessionStore";
import { signOut } from "../lib/auth";
import type {
  AdminError,
  IssueForAdmin,
} from "../lib/declarations/dfinsight_backend.types";
import { nameToEmail, nameToInitials } from "../lib/admins";
import { AdminListSkeleton } from "./AdminLanding";

function formatAdminError(e: AdminError): string {
  if ("Verify" in e) {
    const k = Object.keys(e.Verify)[0];
    return `Attribute verification failed (${k}). The bundle may have expired. Try signing in again.`;
  }
  if ("NoName" in e) return "No name attribute in your SSO bundle.";
  if ("NotAdmin" in e) {
    return `You signed in as "${e.NotAdmin.name}", which is not an admin.\nCurrent admins: ${e.NotAdmin.admins.join(", ")}`;
  }
  if ("NotFound" in e) return "Issue not found.";
  if ("Empty" in e) return "Name or response can't be empty.";
  if ("AlreadyAdmin" in e) return "That name is already an admin.";
  if ("UnknownAdmin" in e) return "That name is not on the admin list.";
  if ("LastAdmin" in e)
    return "Refused. That's the last admin. Add another first.";
  if ("SessionExpired" in e) return "Admin session expired. Sign in again.";
  return "Unknown error.";
}

export function AdminPanel() {
  const navigate = useNavigate();
  const session = sessionStore.get();
  const [issues, setIssues] = useState<IssueForAdmin[] | null>(null);
  const [admins, setAdmins] = useState<string[] | null>(null);
  const [adminDraft, setAdminDraft] = useState("");
  const [addingAdmin, setAddingAdmin] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [responseDraft, setResponseDraft] = useState<Record<string, string>>(
    {},
  );
  const [respondingId, setRespondingId] = useState<string | null>(null);

  useEffect(() => {
    if (!session || session.kind !== "admin") {
      navigate("/admin");
      return;
    }
    void refresh();
  }, [session, navigate]);

  async function refresh() {
    if (!session || session.kind !== "admin") return;
    setError(null);
    try {
      const [issuesRes, adminList] = await Promise.all([
        session.backend.adminListIssues(),
        session.backend.listAdmins(),
      ]);
      if ("err" in issuesRes) {
        setError(formatAdminError(issuesRes.err));
        return;
      }
      setIssues(issuesRes.ok);
      setAdmins(adminList);
    } catch (e) {
      setError(String(e));
    }
  }

  async function onDelete(id: bigint) {
    if (!session || session.kind !== "admin") return;
    if (!confirm("Delete this issue? It'll disappear from every list.")) return;
    const res = await session.backend.adminDeleteIssue(id);
    if ("err" in res) {
      setError(formatAdminError(res.err));
      return;
    }
    await refresh();
  }

  async function onRespond(id: bigint) {
    if (!session || session.kind !== "admin") return;
    const text = responseDraft[String(id)] ?? "";
    if (text.trim().length === 0) return;
    setRespondingId(String(id));
    try {
      const res = await session.backend.adminRespond(id, text);
      if ("err" in res) {
        setError(formatAdminError(res.err));
        return;
      }
      setResponseDraft((p) => {
        const { [String(id)]: _, ...rest } = p;
        return rest;
      });
      await refresh();
    } finally {
      setRespondingId(null);
    }
  }

  async function onAddAdmin() {
    if (!session || session.kind !== "admin") return;
    const name = adminDraft.trim();
    if (name.length === 0) return;
    setAddingAdmin(true);
    try {
      const res = await session.backend.addAdmin(name);
      if ("err" in res) {
        setError(formatAdminError(res.err));
        return;
      }
      setAdminDraft("");
      await refresh();
    } finally {
      setAddingAdmin(false);
    }
  }

  async function onRemoveAdmin(name: string) {
    if (!session || session.kind !== "admin") return;
    const self = name === session.name;
    const prompt = self
      ? `Remove yourself ("${name}") from the admin list? You'll keep this session until it expires, but won't be able to sign in again.`
      : `Remove "${name}" from the admin list?`;
    if (!confirm(prompt)) return;
    const res = await session.backend.removeAdmin(name);
    if ("err" in res) {
      setError(formatAdminError(res.err));
      return;
    }
    await refresh();
  }

  async function onSignOut() {
    await signOut();
    sessionStore.set(null);
    navigate("/admin");
  }

  if (!session || session.kind !== "admin") return null;

  return (
    <section className="card">
      <header className="row">
        <h1>
          Admin <em>panel</em>.
        </h1>
        <button className="ghost" onClick={onSignOut}>
          Sign out
        </button>
      </header>

      <p className="lede">
        Signed in as <strong>{session.name}</strong> ·{" "}
        <code>{nameToEmail(session.name)}</code>
      </p>

      {error && <pre className="error">{error}</pre>}

      <div className="admins">
        <div className="admins-header">
          <span className="label">Admins</span>
          <span className="count">
            {admins === null
              ? "—"
              : `${admins.length} member${admins.length === 1 ? "" : "s"}`}
          </span>
        </div>

        {admins === null ? (
          <AdminListSkeleton rows={2} />
        ) : admins.length === 0 ? (
          <ul className="admin-list">
            <li className="admin-empty">No admins on the allowlist.</li>
          </ul>
        ) : (
          <ul className="admin-list">
            {admins.map((name) => {
              const isSelf = name === session.name;
              return (
                <li key={name} className="admin-row">
                  <span className="avatar" aria-hidden="true">
                    {nameToInitials(name)}
                  </span>
                  <span className="meta">
                    <span className="name">
                      {name}
                      {isSelf && <span className="me-pill">You</span>}
                    </span>
                    <span className="email">{nameToEmail(name)}</span>
                  </span>
                  <span className="actions">
                    <button
                      className="ghost danger"
                      onClick={() => void onRemoveAdmin(name)}
                    >
                      Remove
                    </button>
                  </span>
                </li>
              );
            })}
          </ul>
        )}

        <form
          className="add-admin"
          onSubmit={(e) => {
            e.preventDefault();
            void onAddAdmin();
          }}
        >
          <input
            type="text"
            placeholder="Full name (matches sso:dfinity.org:name)"
            value={adminDraft}
            onChange={(e) => setAdminDraft(e.target.value)}
            disabled={addingAdmin}
          />
          <button
            type="submit"
            className="primary"
            disabled={adminDraft.trim().length === 0 || addingAdmin}
          >
            {addingAdmin && <span className="spinner sm" aria-hidden="true" />}
            {addingAdmin ? "Adding…" : "Add admin"}
          </button>
        </form>
      </div>

      <h2 style={{ marginTop: "1.75rem" }}>Matters of interest</h2>

      {issues === null ? (
        <IssuesSkeleton />
      ) : (
        <ul className="issues">
          {issues.length === 0 && <li className="empty">No issues yet.</li>}
          {issues.map((i) => (
            <li key={String(i.id)} className="issue admin">
              <header className="row">
                <span className="score">{String(i.upvotes)} upvotes</span>
                <time>
                  {new Date(Number(i.createdAt) / 1_000_000).toLocaleString()}
                </time>
              </header>
              <p className="body">{i.body}</p>
              {i.response.length === 1 ? (
                <blockquote className="response">
                  <strong>Response</strong>
                  {i.response[0]}
                </blockquote>
              ) : (
                <div className="respond">
                  <textarea
                    placeholder="Public response (closes voting)…"
                    rows={2}
                    value={responseDraft[String(i.id)] ?? ""}
                    disabled={respondingId === String(i.id)}
                    onChange={(e) =>
                      setResponseDraft((p) => ({
                        ...p,
                        [String(i.id)]: e.target.value,
                      }))
                    }
                  />
                  <button
                    className="primary"
                    disabled={
                      (responseDraft[String(i.id)] ?? "").trim().length === 0 ||
                      respondingId === String(i.id)
                    }
                    onClick={() => void onRespond(i.id)}
                  >
                    {respondingId === String(i.id) && (
                      <span className="spinner sm" aria-hidden="true" />
                    )}
                    {respondingId === String(i.id) ? "Posting…" : "Respond"}
                  </button>
                </div>
              )}
              <button className="danger" onClick={() => void onDelete(i.id)}>
                Delete
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function IssuesSkeleton() {
  return (
    <ul className="issues" aria-busy="true" aria-label="Loading issues">
      {[0, 1, 2].map((i) => (
        <li key={i} className="skeleton-issue">
          <div
            className="row"
            style={{ marginTop: 0, marginBottom: "0.625rem" }}
          >
            <span className="skeleton line short" style={{ width: "5rem" }} />
            <span className="skeleton line short" style={{ width: "9rem" }} />
          </div>
          <span className="skeleton line med" />
          <span className="skeleton line short" />
        </li>
      ))}
    </ul>
  );
}
