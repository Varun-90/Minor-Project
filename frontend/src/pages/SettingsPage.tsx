import React, { useEffect, useState } from 'react';
import { netshieldApi } from '../services/api.ts';
import { useAuth } from '../context/AuthContext.tsx';
import {
  listFirestoreUsersForAdmin,
  persistPredictionToFirestore,
  saveSystemConfigToFirestore,
} from '../lib/firebase.ts';
import type { ModelEvaluationMetrics } from '../../../ml/src/pipeline.ts';
import type { SystemSettings } from '../../../backend/src/store.ts';
import type { UserRole } from '../../../backend/src/auth.ts';

const SAMPLE_ZEEK_LOG = JSON.stringify(
  {
    ts: Math.floor(Date.now() / 1000),
    'id.orig_h': '172.16.0.1',
    'id.orig_p': 52910,
    'id.resp_h': '192.168.10.50',
    'id.resp_p': 80,
    proto: 'tcp',
    duration: 0.14,
    orig_bytes: 3400,
    resp_bytes: 48,
    conn_state: 'S0',
    orig_pkts: 185,
    resp_pkts: 1,
  },
  null,
  2
);

export function SettingsPage() {
  const { user, isFirebaseBacked } = useAuth();
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [activeModel, setActiveModel] = useState<ModelEvaluationMetrics | null>(null);
  const [savingSettings, setSavingSettings] = useState(false);
  const [settingsMsg, setSettingsMsg] = useState<string | null>(null);

  const [users, setUsers] = useState<
    Array<{ id: string; username: string; email: string; role: UserRole }>
  >([]);
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<UserRole>('analyst');
  const [userMsg, setUserMsg] = useState<string | null>(null);

  const [zeekInput, setZeekInput] = useState(SAMPLE_ZEEK_LOG);
  const [zeekResult, setZeekResult] = useState<string | null>(null);
  const [parsingZeek, setParsingZeek] = useState(false);

  useEffect(() => {
    netshieldApi.getSettings().then((res) => setSettings(res.settings)).catch(() => {});
    netshieldApi.getModelMetrics().then((res) => setActiveModel(res.activeModel)).catch(() => {});

    if (user?.role === 'admin') {
      if (isFirebaseBacked) {
        listFirestoreUsersForAdmin()
          .then((fbUsers) => {
            setUsers(
              fbUsers.map((u) => ({
                id: u.uid,
                username: u.username,
                email: u.email,
                role: u.role,
              }))
            );
          })
          .catch(() => {});
      } else {
        netshieldApi
          .getLocalUsers()
          .then((res) => setUsers(res.users))
          .catch(() => {});
      }
    }
  }, [user, isFirebaseBacked]);

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!settings) return;
    setSavingSettings(true);
    setSettingsMsg(null);
    try {
      const res = await netshieldApi.updateSettings(settings);
      setSettings(res.settings);
      if (isFirebaseBacked && user) {
        await saveSystemConfigToFirestore(user.uid, res.settings);
      }
      setSettingsMsg('System configuration and alert thresholds updated.');
    } catch (err: any) {
      setSettingsMsg(err?.response?.data?.error || 'Failed to update configuration.');
    } finally {
      setSavingSettings(false);
    }
  };

  const handleCreateLocalUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setUserMsg(null);
    try {
      const res = await netshieldApi.createLocalUser(newUsername.trim(), newPassword, newRole);
      setUsers((prev) => [...prev, res.user]);
      setNewUsername('');
      setNewPassword('');
      setUserMsg(`Created user "${res.user.username}" (${res.user.role}).`);
    } catch (err: any) {
      setUserMsg(err?.response?.data?.error || 'Failed to create user.');
    }
  };

  const handleTestZeek = async () => {
    setParsingZeek(true);
    setZeekResult(null);
    try {
      const res = await netshieldApi.parseZeekRecord(zeekInput);
      if (isFirebaseBacked && user) {
        await persistPredictionToFirestore(user.uid, res.event, res.alert);
      }
      setZeekResult(
        `Classified as ${res.event.prediction} (${res.event.attackType}) · Score ${(
          res.event.score * 100
        ).toFixed(1)}% · Severity ${res.event.severity} · Stored as ${res.event.id}`
      );
    } catch (err: any) {
      setZeekResult(err?.response?.data?.error || 'Zeek record parsing failed.');
    } finally {
      setParsingZeek(false);
    }
  };

  return (
    <div className="space-y-8">
      <div className="pb-6 border-b border-neutral-200">
        <h1 className="text-2xl font-semibold tracking-tight text-neutral-950">Settings</h1>
        <p className="text-sm text-neutral-600 mt-1">
          Manage user profile, role-based access, detection thresholds, and optional Zeek log integration.
        </p>
      </div>

      {/* Profile & Active Model Info */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <section className="lg:col-span-6 border border-neutral-200 p-6 bg-white">
          <h2 className="text-base font-semibold text-neutral-950 mb-4">Profile Management</h2>
          <dl className="divide-y divide-neutral-200 text-sm">
            <div className="py-2.5 flex justify-between">
              <dt className="text-neutral-600">Username</dt>
              <dd className="font-mono text-neutral-950">{user?.username}</dd>
            </div>
            <div className="py-2.5 flex justify-between">
              <dt className="text-neutral-600">Email</dt>
              <dd className="font-mono text-neutral-950">{user?.email}</dd>
            </div>
            <div className="py-2.5 flex justify-between">
              <dt className="text-neutral-600">Assigned Role</dt>
              <dd className="font-mono font-semibold text-neutral-950 uppercase">{user?.role}</dd>
            </div>
            <div className="py-2.5 flex justify-between">
              <dt className="text-neutral-600">Authentication Method</dt>
              <dd className="font-mono text-neutral-700">
                {user?.authProvider === 'firebase' ? 'Google SSO (Cloud Persistence)' : 'Local API Credentials'}
              </dd>
            </div>
          </dl>
        </section>

        <section className="lg:col-span-6 border border-neutral-200 p-6 bg-white">
          <h2 className="text-base font-semibold text-neutral-950 mb-4">Active Model Information</h2>
          <dl className="divide-y divide-neutral-200 text-sm">
            <div className="py-2.5 flex justify-between">
              <dt className="text-neutral-600">Algorithm</dt>
              <dd className="font-mono text-neutral-950">{activeModel?.algorithm ?? 'RandomForestClassifier'}</dd>
            </div>
            <div className="py-2.5 flex justify-between">
              <dt className="text-neutral-600">Version</dt>
              <dd className="font-mono text-neutral-950">{activeModel?.version ?? '—'}</dd>
            </div>
            <div className="py-2.5 flex justify-between">
              <dt className="text-neutral-600">Training Benchmark</dt>
              <dd className="font-mono text-neutral-950">{activeModel?.dataset ?? 'CIC-IDS2017'}</dd>
            </div>
            <div className="py-2.5 flex justify-between">
              <dt className="text-neutral-600">Operating Mode</dt>
              <dd className="font-mono text-neutral-950">Detection-Only (Non-Blocking)</dd>
            </div>
          </dl>
        </section>
      </div>

      {/* System Configuration & Alert Policy */}
      {settings && (
        <section className="border border-neutral-200 p-6 bg-white">
          <h2 className="text-base font-semibold text-neutral-950">
            Alert Policy & Polling Configuration
          </h2>
          <p className="text-xs text-neutral-500 mt-0.5 mb-5">
            Probability thresholds mapping Random Forest attack confidence scores to alert severity levels
          </p>

          {settingsMsg && (
            <div className="mb-4 border border-neutral-900 bg-neutral-100 px-4 py-2.5 text-xs text-neutral-950">
              {settingsMsg}
            </div>
          )}

          <form onSubmit={handleSaveSettings} className="space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
              <div>
                <label className="block text-xs text-neutral-600 mb-1">Polling Interval (sec)</label>
                <input
                  type="number"
                  min={0}
                  max={300}
                  value={settings.pollingIntervalSec}
                  onChange={(e) =>
                    setSettings({ ...settings, pollingIntervalSec: Number(e.target.value) })
                  }
                  className="w-full px-3 py-2 text-sm font-mono border border-neutral-300 bg-white focus:outline-none focus:border-neutral-950"
                />
              </div>
              <div>
                <label className="block text-xs text-neutral-600 mb-1">Critical Threshold</label>
                <input
                  type="number"
                  step="0.05"
                  min={0.5}
                  max={0.99}
                  value={settings.criticalThreshold}
                  onChange={(e) =>
                    setSettings({ ...settings, criticalThreshold: Number(e.target.value) })
                  }
                  className="w-full px-3 py-2 text-sm font-mono border border-neutral-300 bg-white focus:outline-none focus:border-neutral-950"
                />
              </div>
              <div>
                <label className="block text-xs text-neutral-600 mb-1">High Threshold</label>
                <input
                  type="number"
                  step="0.05"
                  min={0.4}
                  max={0.95}
                  value={settings.highThreshold}
                  onChange={(e) =>
                    setSettings({ ...settings, highThreshold: Number(e.target.value) })
                  }
                  className="w-full px-3 py-2 text-sm font-mono border border-neutral-300 bg-white focus:outline-none focus:border-neutral-950"
                />
              </div>
              <div>
                <label className="block text-xs text-neutral-600 mb-1">Medium Threshold</label>
                <input
                  type="number"
                  step="0.05"
                  min={0.3}
                  max={0.9}
                  value={settings.mediumThreshold}
                  onChange={(e) =>
                    setSettings({ ...settings, mediumThreshold: Number(e.target.value) })
                  }
                  className="w-full px-3 py-2 text-sm font-mono border border-neutral-300 bg-white focus:outline-none focus:border-neutral-950"
                />
              </div>
              <div>
                <label className="block text-xs text-neutral-600 mb-1">Low Threshold</label>
                <input
                  type="number"
                  step="0.05"
                  min={0.2}
                  max={0.85}
                  value={settings.lowThreshold}
                  onChange={(e) =>
                    setSettings({ ...settings, lowThreshold: Number(e.target.value) })
                  }
                  className="w-full px-3 py-2 text-sm font-mono border border-neutral-300 bg-white focus:outline-none focus:border-neutral-950"
                />
              </div>
            </div>

            <div className="flex items-center justify-between pt-2">
              <label className="inline-flex items-center gap-2 text-xs text-neutral-700 cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.zeekIntegrationEnabled}
                  onChange={(e) =>
                    setSettings({ ...settings, zeekIntegrationEnabled: e.target.checked })
                  }
                  className="accent-neutral-950"
                />
                <span>Enable optional Zeek conn.log ingestion adapter (authorized networks only)</span>
              </label>

              <button
                type="submit"
                disabled={savingSettings || user?.role === 'viewer'}
                className="px-4 py-2 text-xs font-medium bg-neutral-950 text-white hover:bg-neutral-800 disabled:opacity-40 cursor-pointer whitespace-nowrap"
              >
                {savingSettings ? 'Saving...' : 'Save Configuration'}
              </button>
            </div>
          </form>
        </section>
      )}

      {/* Optional Decoupled Zeek Adapter Module */}
      <section className="border border-neutral-200 p-6 bg-white">
        <div className="mb-4">
          <h2 className="text-base font-semibold text-neutral-950">
            Zeek Network-Flow Log Adapter (Optional Module)
          </h2>
          <p className="text-xs text-neutral-500 mt-0.5">
            Decoupled JSON conn.log mapper for future authorized live collector integration. Main system does not depend on live packet capture.
          </p>
        </div>

        <textarea
          rows={8}
          value={zeekInput}
          onChange={(e) => setZeekInput(e.target.value)}
          className="w-full p-3 text-xs font-mono border border-neutral-300 bg-neutral-50 text-neutral-950 focus:outline-none focus:border-neutral-950"
        />

        <div className="mt-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <button
            type="button"
            disabled={parsingZeek || user?.role === 'viewer'}
            onClick={() => void handleTestZeek()}
            className="px-4 py-2 text-xs font-medium border border-neutral-950 bg-white text-neutral-950 hover:bg-neutral-100 disabled:opacity-40 cursor-pointer whitespace-nowrap"
          >
            {parsingZeek ? 'Analyzing Zeek Record...' : 'Parse & Classify Zeek JSON Record'}
          </button>
          {zeekResult && <p className="text-xs font-mono text-neutral-900">{zeekResult}</p>}
        </div>
      </section>

      {/* Admin User Management */}
      {user?.role === 'admin' && (
        <section className="border border-neutral-200 p-6 bg-white space-y-6">
          <div>
            <h2 className="text-base font-semibold text-neutral-950">User Management</h2>
            <p className="text-xs text-neutral-500 mt-0.5">
              Registered accounts and role-based access control permissions
            </p>
          </div>

          {userMsg && (
            <div className="border border-neutral-900 bg-neutral-100 px-4 py-2.5 text-xs text-neutral-950">
              {userMsg}
            </div>
          )}

          {!isFirebaseBacked && (
            <form
              onSubmit={handleCreateLocalUser}
              className="grid grid-cols-1 sm:grid-cols-4 gap-3 pb-5 border-b border-neutral-200"
            >
              <input
                type="text"
                placeholder="New username"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                required
                className="px-3 py-2 text-sm border border-neutral-300 bg-white focus:outline-none focus:border-neutral-950"
              />
              <input
                type="password"
                placeholder="Password (min 8 chars)"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                minLength={8}
                className="px-3 py-2 text-sm border border-neutral-300 bg-white focus:outline-none focus:border-neutral-950"
              />
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value as UserRole)}
                className="px-3 py-2 text-sm border border-neutral-300 bg-white focus:outline-none focus:border-neutral-950"
              >
                <option value="analyst">Analyst</option>
                <option value="viewer">Viewer</option>
                <option value="admin">Admin</option>
              </select>
              <button
                type="submit"
                className="px-4 py-2 text-xs font-medium bg-neutral-950 text-white hover:bg-neutral-800 cursor-pointer"
              >
                Add Local User
              </button>
            </form>
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-neutral-200 bg-neutral-50 text-xs font-medium text-neutral-600">
                  <th className="py-2.5 px-4">Username</th>
                  <th className="py-2.5 px-4">Email</th>
                  <th className="py-2.5 px-4">Role</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-200 text-xs font-mono">
                {users.map((u) => (
                  <tr key={u.id}>
                    <td className="py-2.5 px-4 text-neutral-950 font-medium">{u.username}</td>
                    <td className="py-2.5 px-4 text-neutral-600">{u.email}</td>
                    <td className="py-2.5 px-4 uppercase text-neutral-900">{u.role}</td>
                  </tr>
                ))}
                {users.length === 0 && (
                  <tr>
                    <td colSpan={3} className="py-6 text-center text-neutral-500 font-sans">
                      No additional user accounts registered.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
