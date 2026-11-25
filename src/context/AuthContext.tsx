/**
 * NetShield AI Authentication Context
 * Coordinates Firebase Google Sign-In (persistent Firestore sync) and Local API Credential Login.
 * All tokens remain strictly in React/JS memory.
 */

import React, { createContext, useContext, useEffect, useState } from 'react';
import { onAuthStateChanged, signInWithPopup, signOut as firebaseSignOut } from 'firebase/auth';
import {
  auth,
  ensureFirestoreUserProfile,
  googleAuthProvider,
} from '../lib/firebase.ts';
import { netshieldApi, setAuthToken, setDynamicTokenProvider } from '../services/api.ts';
import type { AuthUser } from '../server/auth.ts';

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  signInWithGoogle: () => Promise<void>;
  signInLocal: (username: string, password: string) => Promise<void>;
  bootstrapLocal: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  isFirebaseBacked: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (fbUser) => {
      if (fbUser && fbUser.emailVerified) {
        try {
          const idToken = await fbUser.getIdToken();
          setAuthToken(null);
          setDynamicTokenProvider(async () => {
            const current = auth.currentUser;
            return current ? current.getIdToken() : null;
          });
          const profile = await ensureFirestoreUserProfile(
            fbUser.uid,
            fbUser.email || `${fbUser.uid}@firebase.user`,
            fbUser.displayName
          );
          setUser({
            uid: fbUser.uid,
            username: profile.username,
            email: profile.email,
            role: profile.role,
            authProvider: 'firebase',
          });
          // Ensure token is warmed
          void idToken;
        } catch (err) {
          console.error('Failed to synchronize Firebase user profile:', err);
          setUser(null);
        }
      } else {
        setDynamicTokenProvider(null);
        setUser((prev) => (prev?.authProvider === 'local' ? prev : null));
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const signInWithGoogle = async () => {
    const result = await signInWithPopup(auth, googleAuthProvider);
    const fbUser = result.user;
    if (!fbUser.emailVerified) {
      await firebaseSignOut(auth);
      throw new Error('Google account email must be verified to access NetShield AI.');
    }
    setAuthToken(null);
    setDynamicTokenProvider(async () => {
      const current = auth.currentUser;
      return current ? current.getIdToken() : null;
    });
    const profile = await ensureFirestoreUserProfile(
      fbUser.uid,
      fbUser.email || `${fbUser.uid}@firebase.user`,
      fbUser.displayName
    );
    setUser({
      uid: fbUser.uid,
      username: profile.username,
      email: profile.email,
      role: profile.role,
      authProvider: 'firebase',
    });
  };

  const signInLocal = async (username: string, password: string) => {
    const resp = await netshieldApi.loginLocal(username, password);
    setDynamicTokenProvider(null);
    setAuthToken(resp.access_token);
    setUser(resp.user);
  };

  const bootstrapLocal = async (username: string, password: string) => {
    const resp = await netshieldApi.bootstrapLocalAdmin(username, password);
    setDynamicTokenProvider(null);
    setAuthToken(resp.access_token);
    setUser(resp.user);
  };

  const logout = async () => {
    setAuthToken(null);
    setDynamicTokenProvider(null);
    if (auth.currentUser) {
      await firebaseSignOut(auth);
    }
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        signInWithGoogle,
        signInLocal,
        bootstrapLocal,
        logout,
        isFirebaseBacked: user?.authProvider === 'firebase',
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
