import React, { useState, useEffect, useCallback } from 'react';
import {
  Users,
  UserPlus,
  ShieldCheck,
  KeyRound,
  Mail,
  User,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Lock,
} from 'lucide-react';
import { User as UserType, UserRole } from '../types';
import { useAuth } from '../context/AuthContext';

export const UsersPage: React.FC = () => {
  const { token, hasRole } = useAuth();
  const [users, setUsers] = useState<UserType[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // New user form state
  const [username, setUsername] = useState<string>('');
  const [fullName, setFullName] = useState<string>('');
  const [email, setEmail] = useState<string>('');
  const [role, setRole] = useState<UserRole>('Investigator');
  const [password, setPassword] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  const fetchUsers = useCallback(async () => {
    if (!token) return;
    try {
      setIsLoading(true);
      setError(null);
      const res = await fetch('/api/auth/users', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Failed to load user accounts');
      }
      const data = await res.json();
      setUsers(data.users);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !fullName.trim() || !email.trim() || !password) {
      setNotification({ type: 'error', message: 'All fields are required.' });
      return;
    }

    if (password.length < 8) {
      setNotification({ type: 'error', message: 'Password must be at least 8 characters long.' });
      return;
    }

    try {
      setIsSubmitting(true);
      const res = await fetch('/api/auth/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          username: username.trim(),
          fullName: fullName.trim(),
          email: email.trim(),
          role,
          password,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to create user account');
      }

      setNotification({
        type: 'success',
        message: `Account created for ${data.user.fullName} with role ${data.user.role}.`,
      });

      setUsername('');
      setFullName('');
      setEmail('');
      setPassword('');
      fetchUsers();
    } catch (err: unknown) {
      setNotification({
        type: 'error',
        message: err instanceof Error ? err.message : 'User creation failed',
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const getRoleBadge = (r: UserRole) => {
    switch (r) {
      case 'Administrator':
        return 'bg-purple-950/80 text-purple-300 border-purple-600/70';
      case 'Investigator':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-600/70';
      case 'Auditor':
        return 'bg-amber-950/80 text-amber-300 border-amber-600/70';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  if (!hasRole('Administrator')) {
    return (
      <div className="p-8 rounded-xl bg-red-950/30 border border-red-800 text-center space-y-3">
        <Lock className="w-10 h-10 text-red-400 mx-auto" />
        <h3 className="font-bold text-slate-100 text-base">RESTRICTED ADMINISTRATOR ACCESS ONLY</h3>
        <p className="text-xs text-red-300 max-w-md mx-auto">
          Role-Based Access Control (RBAC) enforces that only accounts with Administrator clearance can provision operator accounts and alter role assignments.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-6 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Users className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold uppercase tracking-wider text-slate-100 font-mono">
              Access Control & User Provisioning
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Enforce the Principle of Least Privilege across Administrators, Forensic Investigators, and Independent Compliance Auditors.
          </p>
        </div>
        <span className="text-xs font-mono text-purple-400 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 self-start sm:self-auto">
          ADMIN SECURITY CLEARANCE
        </span>
      </div>

      {notification && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between transition-all ${
            notification.type === 'success'
              ? 'bg-emerald-950/80 border-emerald-700/80 text-emerald-200'
              : 'bg-red-950/80 border-red-700/80 text-red-200'
          }`}
        >
          <div className="flex items-center gap-3">
            {notification.type === 'success' ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
            )}
            <p className="text-xs font-semibold">{notification.message}</p>
          </div>
          <button
            onClick={() => setNotification(null)}
            className="text-xs opacity-75 hover:opacity-100 font-bold px-2 py-1"
          >
            Dismiss
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: User Roster */}
        <div className="lg:col-span-2 p-6 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
              Authorized Personnel Roster ({users.length})
            </h3>
            <button
              onClick={fetchUsers}
              disabled={isLoading}
              className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-cyan-400 transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800/80 text-slate-400 font-mono">
                  <th className="pb-2.5 font-semibold">USER</th>
                  <th className="pb-2.5 font-semibold">ROLE</th>
                  <th className="pb-2.5 font-semibold">EMAIL</th>
                  <th className="pb-2.5 font-semibold">REGISTERED (UTC)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-900/40 transition">
                    <td className="py-3 pr-3">
                      <div className="font-bold text-slate-200">{u.fullName}</div>
                      <div className="text-[11px] text-slate-400 font-mono">@{u.username}</div>
                    </td>
                    <td className="py-3 pr-3">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${getRoleBadge(
                          u.role
                        )}`}
                      >
                        {u.role}
                      </span>
                    </td>
                    <td className="py-3 pr-3 font-mono text-slate-300 text-[11px]">{u.email}</td>
                    <td className="py-3 font-mono text-slate-500 text-[11px]">
                      {u.createdAt ? new Date(u.createdAt).toLocaleDateString() : 'N/A'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* RBAC Matrix Guide */}
          <div className="mt-4 pt-4 border-t border-slate-800/80">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono mb-2">
              Role Permission Matrix
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-purple-900/40">
                <span className="font-bold text-purple-300 block mb-1">Administrator</span>
                <span className="text-slate-400 leading-tight block">
                  User creation, role assignment, audit chain verification, evidence acquisition & downloads.
                </span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-cyan-900/40">
                <span className="font-bold text-cyan-300 block mb-1">Investigator</span>
                <span className="text-slate-400 leading-tight block">
                  Evidence acquisition, live bitstream verification, custody transfers, PDF certificates.
                </span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-amber-900/40">
                <span className="font-bold text-amber-300 block mb-1">Auditor</span>
                <span className="text-slate-400 leading-tight block">
                  Read-only forensic inspection, chain verification, custody timeline review, report downloads.
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Right 1 Col: Provision Account Form */}
        <div className="p-6 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800/80">
            <UserPlus className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
              Provision New Account
            </h3>
          </div>

          <form onSubmit={handleCreateUser} className="space-y-3.5 text-xs">
            <div>
              <label className="block text-slate-300 font-semibold mb-1 uppercase tracking-wider">
                Full Legal Name
              </label>
              <input
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="e.g. Agent John Reynolds"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                required
              />
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1 uppercase tracking-wider">
                Operator Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. jreynolds"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                required
              />
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1 uppercase tracking-wider">
                Email Address
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="e.g. jreynolds@deiv.local"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                required
              />
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1 uppercase tracking-wider">
                Assigned Forensic Role
              </label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value as UserRole)}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="Investigator">Investigator (Acquisition & Verification)</option>
                <option value="Auditor">Auditor (Independent Compliance / Read-Only)</option>
                <option value="Administrator">Administrator (Full Privileges)</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1 uppercase tracking-wider">
                Temporary Passphrase (min 8 chars)
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                required
                minLength={8}
              />
              <span className="text-[10px] text-slate-500 font-mono mt-1 block">
                Will be hashed with unique random salt using scrypt (Node crypto).
              </span>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white font-semibold text-xs shadow-md transition disabled:opacity-50 mt-2"
            >
              {isSubmitting ? 'Hashing & Provisioning...' : 'Provision Operator Account'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
