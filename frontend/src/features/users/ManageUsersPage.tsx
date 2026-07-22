import { useEffect, useState, type FormEvent } from "react";
import { Card } from "@/components/Card";
import { PageHeader } from "@/components/PageHeader";
import { useAuth, type UserRole } from "@/context/AuthContext";
import { authFetch, parseApiError } from "@/lib/api";
import { HELP_TEXT, NAV_LABELS } from "@/lib/copy";
import { formatDate } from "@/utils/dateUtils";

interface ManagedUser {
  id: number;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  last_login: string | null;
}

const ROLE_OPTIONS: UserRole[] = ["viewer", "analyst", "admin"];

/** Admin-only account management: create, change role, disable, or
 * permanently delete accounts. The route itself is wrapped in RequireAdmin
 * (router.tsx) and the sidebar link is hidden for non-admins, but the real
 * security boundary is server-side — require_admin on every
 * /api/v1/auth/users* route. This page is just the matching UI. */
export function ManageUsersPage() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [rowError, setRowError] = useState<string | null>(null);

  const [newUsername, setNewUsername] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState<UserRole>("viewer");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const loadUsers = async () => {
    setLoading(true);
    setListError(null);
    try {
      const response = await authFetch("/api/v1/auth/users");
      if (!response.ok) {
        throw new Error(parseApiError(await response.text(), `Failed to load accounts (${response.status})`));
      }
      setUsers((await response.json()) as ManagedUser[]);
    } catch (err) {
      setListError(err instanceof Error ? err.message : "Failed to load accounts.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadUsers();
  }, []);

  const createUser = async (event: FormEvent) => {
    event.preventDefault();
    if (creating) return;
    setCreateError(null);
    setCreating(true);
    try {
      const response = await authFetch("/api/v1/auth/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: newUsername.trim(),
          email: newEmail.trim(),
          password: newPassword,
          role: newRole,
        }),
      });
      if (!response.ok) {
        throw new Error(parseApiError(await response.text(), `Failed to create account (${response.status})`));
      }
      setNewUsername("");
      setNewEmail("");
      setNewPassword("");
      setNewRole("viewer");
      await loadUsers();
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : "Failed to create account.");
    } finally {
      setCreating(false);
    }
  };

  const updateUser = async (id: number, patch: Record<string, unknown>) => {
    setRowError(null);
    try {
      const response = await authFetch(`/api/v1/auth/users/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
      if (!response.ok) {
        throw new Error(parseApiError(await response.text(), `Failed to update account (${response.status})`));
      }
      await loadUsers();
    } catch (err) {
      setRowError(err instanceof Error ? err.message : "Failed to update account.");
    }
  };

  const toggleActive = async (target: ManagedUser) => {
    const message = target.is_active
      ? `Disable "${target.username}"? They won't be able to log in until this is reversed.`
      : `Re-enable "${target.username}"? They'll be able to log in again.`;
    if (!window.confirm(message)) return;
    await updateUser(target.id, { is_active: !target.is_active });
  };

  const deleteUser = async (target: ManagedUser) => {
    if (target.id === currentUser?.id) return; // also guarded server-side; just skip the round trip
    if (!window.confirm(`Permanently delete "${target.username}"? This cannot be undone.`)) return;
    setRowError(null);
    try {
      const response = await authFetch(`/api/v1/auth/users/${target.id}`, { method: "DELETE" });
      if (!response.ok) {
        throw new Error(parseApiError(await response.text(), `Failed to delete account (${response.status})`));
      }
      await loadUsers();
    } catch (err) {
      setRowError(err instanceof Error ? err.message : "Failed to delete account.");
    }
  };

  return (
    <div className="page page--narrow">
      <PageHeader title={NAV_LABELS.manageUsers} subtitle={HELP_TEXT.manageUsersPage} />

      <Card title="User accounts">
        <p className="card-footnote">
          Create, promote, disable, or permanently delete accounts. New accounts default to{" "}
          <strong>Viewer</strong> unless you pick a different role below.
        </p>

        <form className="user-create-form" onSubmit={createUser}>
          <input
            className="status-label-input"
            type="text"
            placeholder="Username"
            value={newUsername}
            onChange={(e) => setNewUsername(e.target.value)}
            disabled={creating}
            autoComplete="off"
            required
          />
          <input
            className="status-label-input"
            type="email"
            placeholder="Email"
            value={newEmail}
            onChange={(e) => setNewEmail(e.target.value)}
            disabled={creating}
            autoComplete="off"
            required
          />
          <input
            className="status-label-input"
            type="password"
            placeholder="Password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            disabled={creating}
            autoComplete="new-password"
            required
          />
          <select
            className="status-label-input"
            value={newRole}
            onChange={(e) => setNewRole(e.target.value as UserRole)}
            disabled={creating}
          >
            {ROLE_OPTIONS.map((role) => (
              <option key={role} value={role}>
                {role}
              </option>
            ))}
          </select>
          <button type="submit" className="btn btn--compact" disabled={creating}>
            {creating ? "Creating…" : "Create account"}
          </button>
        </form>
        {createError && <p className="auth-error">{createError}</p>}
        {listError && <p className="auth-error">{listError}</p>}
        {rowError && <p className="auth-error">{rowError}</p>}

        {loading ? (
          <p className="card-footnote">Loading accounts…</p>
        ) : (
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Last login</th>
                  <th>Created</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const isSelf = u.id === currentUser?.id;
                  return (
                    <tr key={u.id}>
                      <td>{u.username}</td>
                      <td>{u.email}</td>
                      <td>
                        <select
                          className="status-label-input"
                          value={u.role}
                          onChange={(e) => void updateUser(u.id, { role: e.target.value })}
                        >
                          {ROLE_OPTIONS.map((role) => (
                            <option key={role} value={role}>
                              {role}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn btn--compact"
                          disabled={isSelf && u.is_active}
                          title={isSelf && u.is_active ? "You can't disable your own account" : undefined}
                          onClick={() => void toggleActive(u)}
                        >
                          {u.is_active ? "Active" : "Disabled"}
                        </button>
                      </td>
                      <td>{formatDate(u.last_login ?? undefined)}</td>
                      <td>{formatDate(u.created_at)}</td>
                      <td>
                        <button
                          type="button"
                          className="btn btn--ghost"
                          disabled={isSelf}
                          title={isSelf ? "You can't delete your own account" : "Delete permanently"}
                          onClick={() => void deleteUser(u)}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
