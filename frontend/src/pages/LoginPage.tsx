import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock, Shield, User } from 'lucide-react';
import { useAuth } from '../context/AuthContext.tsx';
import { netshieldApi } from '../services/api.ts';

export function LoginPage() {
  const { user, signInWithGoogle, signInLocal, bootstrapLocal } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [needsBootstrap, setNeedsBootstrap] = useState(false);
  const [checkingStatus, setCheckingStatus] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [googleSubmitting, setGoogleSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (user) {
      navigate('/', { replace: true });
    }
  }, [user, navigate]);

  useEffect(() => {
    let active = true;
    netshieldApi
      .getAuthStatus()
      .then((res) => {
        if (active) {
          setNeedsBootstrap(res.localBootstrapRequired);
          setCheckingStatus(false);
        }
      })
      .catch(() => {
        if (active) setCheckingStatus(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const handleCredentialSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!username.trim() || !password) {
      setError('Enter both username and password.');
      return;
    }

    if (needsBootstrap) {
      if (password.length < 8) {
        setError('Administrator password must be at least 8 characters.');
        return;
      }
      if (password !== confirmPassword) {
        setError('Passwords do not match.');
        return;
      }
    }

    setSubmitting(true);
    try {
      if (needsBootstrap) {
        await bootstrapLocal(username.trim(), password);
      } else {
        await signInLocal(username.trim(), password);
      }
      navigate('/', { replace: true });
    } catch (err: any) {
      const apiErr = err?.response?.data?.error || err?.message || 'Authentication failed.';
      setError(apiErr);
    } finally {
      setSubmitting(false);
    }
  };

  const handleGoogleLogin = async () => {
    setError(null);
    setGoogleSubmitting(true);
    try {
      await signInWithGoogle();
      navigate('/', { replace: true });
    } catch (err: any) {
      setError(err?.message || 'Google sign-in was cancelled or failed.');
    } finally {
      setGoogleSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-white text-neutral-950 grid grid-cols-1 lg:grid-cols-12">
      {/* Left Institutional Panel */}
      <div className="hidden lg:flex lg:col-span-5 bg-neutral-950 text-white p-12 flex-col justify-between border-r border-neutral-800">
        <div className="flex items-center gap-2.5">
          <Shield className="w-6 h-6 text-white" strokeWidth={1.75} />
          <span className="text-lg font-semibold tracking-tight">NetShield AI</span>
        </div>

        <div className="max-w-md">
          <p className="text-xs font-mono text-neutral-400 mb-3">
            Network Intrusion Detection · CIC-IDS2017 Pipeline
          </p>
          <h1 className="text-3xl font-semibold tracking-tight leading-snug mb-5">
            AI-Powered Network Threat Detection and Intrusion Monitoring
          </h1>
          <p className="text-sm text-neutral-400 leading-relaxed mb-8">
            Analyze network-flow records using a trained Random Forest classifier, inspect
            per-feature decision metrics, and manage security alerts in detection-only mode.
          </p>
          <div className="border-t border-neutral-800 pt-6 grid grid-cols-2 gap-6">
            <div>
              <p className="text-xs text-neutral-500">Classifier Architecture</p>
              <p className="text-sm font-mono text-white mt-1">Random Forest Ensemble</p>
            </div>
            <div>
              <p className="text-xs text-neutral-500">Operating Posture</p>
              <p className="text-sm font-mono text-white mt-1">Detection-Only Mode</p>
            </div>
          </div>
        </div>

        <p className="text-xs text-neutral-500">
          Authorized network analysis only. Offline flow records are never misrepresented as live capture.
        </p>
      </div>

      {/* Right Authentication Form */}
      <div className="lg:col-span-7 flex items-center justify-center p-6 sm:p-12 bg-white">
        <div className="w-full max-w-md">
          <div className="lg:hidden flex items-center gap-2 mb-8">
            <Shield className="w-5 h-5 text-neutral-950" strokeWidth={1.75} />
            <span className="text-base font-semibold tracking-tight">NetShield AI</span>
          </div>

          <div className="mb-8">
            <h2 className="text-2xl font-semibold tracking-tight text-neutral-950">
              {needsBootstrap ? 'Initialize Administrator Account' : 'Sign in to NetShield AI'}
            </h2>
            <p className="text-sm text-neutral-600 mt-1.5">
              {needsBootstrap
                ? 'Set the initial local administrator password or sign in with Google for cloud persistence.'
                : 'Authenticate with your security console credentials or Google account.'}
            </p>
          </div>

          {error && (
            <div
              role="alert"
              className="mb-6 border border-neutral-900 bg-neutral-100 px-4 py-3 text-sm text-neutral-950"
            >
              <span className="font-semibold">Authentication Error: </span>
              <span>{error}</span>
            </div>
          )}

          {/* Primary Google Sign-In for Cloud Firestore Persistence */}
          <button
            type="button"
            onClick={handleGoogleLogin}
            disabled={googleSubmitting}
            className="w-full flex items-center justify-center gap-2.5 px-4 py-2.5 text-sm font-medium border border-neutral-950 bg-neutral-950 text-white hover:bg-neutral-800 disabled:opacity-50 transition-colors cursor-pointer"
          >
            <span>{googleSubmitting ? 'Signing in...' : 'Continue with Google Account'}</span>
          </button>

          <div className="my-6 flex items-center gap-4">
            <div className="h-px flex-1 bg-neutral-200" />
            <span className="text-xs text-neutral-500">
              {needsBootstrap ? 'Or create local API admin' : 'Or sign in with credentials'}
            </span>
            <div className="h-px flex-1 bg-neutral-200" />
          </div>

          {checkingStatus ? (
            <div className="py-6 text-center text-sm text-neutral-500">
              Checking authentication configuration...
            </div>
          ) : (
            <form onSubmit={handleCredentialSubmit} className="space-y-4">
              <div>
                <label htmlFor="username" className="block text-xs font-medium text-neutral-700 mb-1.5">
                  Username
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-neutral-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                  <input
                    id="username"
                    type="text"
                    autoComplete="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder={needsBootstrap ? 'Choose admin username (e.g. secadmin)' : 'Enter username'}
                    className="w-full pl-9 pr-3 py-2.5 text-sm border border-neutral-300 bg-white text-neutral-950 focus:outline-none focus:border-neutral-950"
                    required
                  />
                </div>
              </div>

              <div>
                <label htmlFor="password" className="block text-xs font-medium text-neutral-700 mb-1.5">
                  Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-neutral-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                  <input
                    id="password"
                    type="password"
                    autoComplete={needsBootstrap ? 'new-password' : 'current-password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={needsBootstrap ? 'Minimum 8 characters' : 'Enter password'}
                    className="w-full pl-9 pr-3 py-2.5 text-sm border border-neutral-300 bg-white text-neutral-950 focus:outline-none focus:border-neutral-950"
                    required
                  />
                </div>
              </div>

              {needsBootstrap && (
                <div>
                  <label
                    htmlFor="confirm-password"
                    className="block text-xs font-medium text-neutral-700 mb-1.5"
                  >
                    Confirm Password
                  </label>
                  <div className="relative">
                    <Lock className="w-4 h-4 text-neutral-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                    <input
                      id="confirm-password"
                      type="password"
                      autoComplete="new-password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="Re-enter password"
                      className="w-full pl-9 pr-3 py-2.5 text-sm border border-neutral-300 bg-white text-neutral-950 focus:outline-none focus:border-neutral-950"
                      required
                    />
                  </div>
                </div>
              )}

              <button
                type="submit"
                disabled={submitting}
                className="w-full px-4 py-2.5 text-sm font-medium border border-neutral-950 bg-white text-neutral-950 hover:bg-neutral-100 disabled:opacity-50 transition-colors cursor-pointer"
              >
                {submitting
                  ? 'Authenticating...'
                  : needsBootstrap
                    ? 'Claim Local Admin & Sign In'
                    : 'Login'}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
