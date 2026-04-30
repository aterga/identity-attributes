import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { sessionStore } from "../lib/sessionStore";
import { signOut } from "../lib/auth";
import type {
  AdminError,
  IssueForAdmin,
} from "../lib/declarations/dfinsight_backend.types";

function formatAdminError(e: AdminError): string {
  if ("Verify" in e) {
    const k = Object.keys(e.Verify)[0];
    return `Attribute verification failed (${k}). The bundle may have expired — try signing in again.`;
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
    return "Refused — that's the last admin. Add another first.";
  if ("SessionExpired" in e) return "Admin session expired — sign in again.";
  return "Unknown error.";
}

export function AdminPanel() {
  const navigate = useNavigate();
  const session = sessionStore.get();
  const [issues, setIssues] = useState<IssueForAdmin[]>([]);
  const [admins, setAdmins] = useState<string[]>([]);
  const [adminDraft, setAdminDraft] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [responseDraft, setResponseDraft] = useState<Record<string, string>>(
    {},
  );

  useEffect(() => {
    if (!session || session.kind !== "admin") {
      navigate("/admin");
      return;
    }
    void refresh();
  }, [session, navigate]);

  async function refresh() {
    if (!session || session.kind !== "admin") return;
    setLoading(true);
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
    } finally {
      setLoading(false);
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
  }

  async function onAddAdmin() {
    if (!session || session.kind !== "admin") return;
    const name = adminDraft.trim();
    if (name.length === 0) return;
    const res = await session.backend.addAdmin(name);
    if ("err" in res) {
      setError(formatAdminError(res.err));
      return;
    }
    setAdminDraft("");
    await refresh();
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
        <h1>Admin panel</h1>
        <button className="ghost" onClick={onSignOut}>
          Sign out
        </button>
      </header>

      {error && <pre className="error">{error}</pre>}

      {loading && <p>Loading…</p>}

      <details className="admins">
        <summary>Admins ({admins.length})</summary>
        <ul>
          {admins.map((name) => (
            <li key={name} className="row">
              <span>{name}</span>
              <button
                className="ghost danger"
                onClick={() => void onRemoveAdmin(name)}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
        <div className="respond">
          <input
            type="text"
            placeholder="Full name (matches sso:dfinity.org:name)"
            value={adminDraft}
            onChange={(e) => setAdminDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void onAddAdmin();
            }}
          />
          <button
            className="primary"
            disabled={adminDraft.trim().length === 0}
            onClick={() => void onAddAdmin()}
          >
            Add admin
          </button>
        </div>
      </details>

      <ul className="issues">
        {!loading && issues.length === 0 && (
          <li className="empty">No issues yet.</li>
        )}
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
                <strong>Response:</strong> {i.response[0]}
              </blockquote>
            ) : (
              <div className="respond">
                <textarea
                  placeholder="Public response (closes voting)…"
                  rows={2}
                  value={responseDraft[String(i.id)] ?? ""}
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
                    (responseDraft[String(i.id)] ?? "").trim().length === 0
                  }
                  onClick={() => void onRespond(i.id)}
                >
                  Respond
                </button>
              </div>
            )}
            <button className="danger" onClick={() => void onDelete(i.id)}>
              Delete
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
