/**
 * NetShield AI Authentication & RBAC Middleware
 * Supports both:
 *  1. Firebase Auth ID Tokens (cryptographically verified via Google's x509 public keys)
 *  2. Local API Bearer Tokens (HMAC-SHA256 signed, backed by scrypt-hashed server credentials)
 */

import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import firebaseConfig from '../../firebase-applet-config.json';

export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface AuthUser {
  uid: string;
  username: string;
  email: string;
  role: UserRole;
  authProvider: 'firebase' | 'local';
}

export interface AuthenticatedRequest extends Request {
  user?: AuthUser;
}

interface LocalUserRecord {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  salt: string;
  passwordHash: string;
  createdAt: string;
}

const BOOTSTRAPPED_ADMIN_EMAIL = 'varunsoniff2007@gmail.com';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;

// In-memory local user registry (zero hardcoded credentials)
const localUsers = new Map<string, LocalUserRecord>();
let bootstrappedFromEnv = false;

export function hashPassword(password: string, existingSalt?: string): { salt: string; hash: string } {
  const salt = existingSalt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

export function verifyPassword(password: string, salt: string, storedHash: string): boolean {
  const derived = crypto.scryptSync(password, salt, 64);
  const storedBuf = Buffer.from(storedHash, 'hex');
  if (derived.length !== storedBuf.length) return false;
  return crypto.timingSafeEqual(derived, storedBuf);
}

// Initialize optional env-configured admin without writing plaintext files
function ensureEnvAdmin() {
  if (bootstrappedFromEnv) return;
  bootstrappedFromEnv = true;
  const envUser = process.env.NETSHIELD_ADMIN_USERNAME?.trim();
  const envPass = process.env.NETSHIELD_ADMIN_PASSWORD?.trim();
  if (envUser && envPass && envPass.length >= 8) {
    const { salt, hash } = hashPassword(envPass);
    localUsers.set(envUser.toLowerCase(), {
      id: `local_${crypto.randomBytes(6).toString('hex')}`,
      username: envUser,
      email: `${envUser}@netshield.local`,
      role: 'admin',
      salt,
      passwordHash: hash,
      createdAt: new Date().toISOString(),
    });
  }
}

export function isLocalBootstrapRequired(): boolean {
  ensureEnvAdmin();
  return localUsers.size === 0;
}

export function isEnvPasswordConfigured(): boolean {
  return Boolean(process.env.NETSHIELD_ADMIN_USERNAME?.trim() && process.env.NETSHIELD_ADMIN_PASSWORD?.trim());
}

export function bootstrapLocalAdmin(username: string, password: string): LocalUserRecord {
  ensureEnvAdmin();
  if (localUsers.size > 0) {
    throw new Error('Local administrator account has already been configured.');
  }
  const cleanUsername = username.trim();
  if (cleanUsername.length < 3 || cleanUsername.length > 40) {
    throw new Error('Username must be between 3 and 40 characters.');
  }
  if (password.length < 8) {
    throw new Error('Password must be at least 8 characters long.');
  }
  const { salt, hash } = hashPassword(password);
  const record: LocalUserRecord = {
    id: `local_admin_${crypto.randomBytes(4).toString('hex')}`,
    username: cleanUsername,
    email: `${cleanUsername}@netshield.local`,
    role: 'admin',
    salt,
    passwordHash: hash,
    createdAt: new Date().toISOString(),
  };
  localUsers.set(cleanUsername.toLowerCase(), record);
  return record;
}

export function createLocalUser(username: string, password: string, role: UserRole): Omit<LocalUserRecord, 'salt' | 'passwordHash'> {
  ensureEnvAdmin();
  const clean = username.trim();
  if (localUsers.has(clean.toLowerCase())) {
    throw new Error(`Username "${clean}" already exists.`);
  }
  const { salt, hash } = hashPassword(password);
  const record: LocalUserRecord = {
    id: `local_${crypto.randomBytes(6).toString('hex')}`,
    username: clean,
    email: `${clean}@netshield.local`,
    role,
    salt,
    passwordHash: hash,
    createdAt: new Date().toISOString(),
  };
  localUsers.set(clean.toLowerCase(), record);
  return {
    id: record.id,
    username: record.username,
    email: record.email,
    role: record.role,
    createdAt: record.createdAt,
  };
}

export function listLocalUsers(): Array<Omit<LocalUserRecord, 'salt' | 'passwordHash'>> {
  ensureEnvAdmin();
  return Array.from(localUsers.values()).map(({ id, username, email, role, createdAt }) => ({
    id,
    username,
    email,
    role,
    createdAt,
  }));
}

export function updateLocalUserRole(userId: string, role: UserRole): Omit<LocalUserRecord, 'salt' | 'passwordHash'> | null {
  ensureEnvAdmin();
  for (const [key, user] of localUsers.entries()) {
    if (user.id === userId) {
      const updated = { ...user, role };
      localUsers.set(key, updated);
      return {
        id: updated.id,
        username: updated.username,
        email: updated.email,
        role: updated.role,
        createdAt: updated.createdAt,
      };
    }
  }
  return null;
}

export function authenticateLocalUser(username: string, password: string): { token: string; user: AuthUser } | null {
  ensureEnvAdmin();
  const envUser = process.env.NETSHIELD_ADMIN_USERNAME?.trim();
  const envPass = process.env.NETSHIELD_ADMIN_PASSWORD?.trim();

  // Configured env passcode always overrides any claimed fallback hash
  if (envUser && envPass && username.trim().toLowerCase() === envUser.toLowerCase()) {
    const a = Buffer.from(password);
    const b = Buffer.from(envPass);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      const user: AuthUser = {
        uid: 'env_admin',
        username: envUser,
        email: `${envUser}@netshield.local`,
        role: 'admin',
        authProvider: 'local',
      };
      return { token: signLocalToken(user), user };
    }
    return null;
  }

  const record = localUsers.get(username.trim().toLowerCase());
  if (!record) return null;
  if (!verifyPassword(password, record.salt, record.passwordHash)) return null;

  const user: AuthUser = {
    uid: record.id,
    username: record.username,
    email: record.email,
    role: record.role,
    authProvider: 'local',
  };
  return { token: signLocalToken(user), user };
}

function base64UrlEncode(input: string | Buffer): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(input: string): Buffer {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  return Buffer.from(padded + '='.repeat(padLen), 'base64');
}

export function signLocalToken(user: AuthUser): string {
  const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'NETSHIELD' }));
  const payload = base64UrlEncode(
    JSON.stringify({
      sub: user.uid,
      username: user.username,
      email: user.email,
      role: user.role,
      exp: Date.now() + TOKEN_TTL_MS,
    })
  );
  const sig = base64UrlEncode(
    crypto.createHmac('sha256', SESSION_SECRET).update(`${header}.${payload}`).digest()
  );
  return `${header}.${payload}.${sig}`;
}

function verifyLocalToken(token: string): AuthUser | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;
  try {
    const header = JSON.parse(base64UrlDecode(headerB64).toString('utf-8')) as { typ?: string };
    if (header.typ !== 'NETSHIELD') return null;

    const expectedSig = base64UrlEncode(
      crypto.createHmac('sha256', SESSION_SECRET).update(`${headerB64}.${payloadB64}`).digest()
    );
    const a = Buffer.from(sigB64);
    const b = Buffer.from(expectedSig);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

    const payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf-8')) as {
      sub: string;
      username: string;
      email: string;
      role: UserRole;
      exp: number;
    };
    if (!payload.exp || Date.now() > payload.exp) return null;

    return {
      uid: payload.sub,
      username: payload.username,
      email: payload.email,
      role: payload.role,
      authProvider: 'local',
    };
  } catch {
    return null;
  }
}

// --- Google Firebase ID Token RS256 Verification (Zero IAM required) ---
let cachedCerts: Record<string, string> = {};
let certsExpiresAt = 0;

async function getGooglePublicCerts(): Promise<Record<string, string>> {
  if (Date.now() < certsExpiresAt && Object.keys(cachedCerts).length > 0) {
    return cachedCerts;
  }
  const resp = await fetch(
    'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com'
  );
  if (!resp.ok) {
    throw new Error('Unable to fetch Google public verification certificates.');
  }
  const cacheControl = resp.headers.get('cache-control') || '';
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/);
  const maxAgeSec = maxAgeMatch ? Number(maxAgeMatch[1]) : 3600;
  cachedCerts = (await resp.json()) as Record<string, string>;
  certsExpiresAt = Date.now() + maxAgeSec * 1000;
  return cachedCerts;
}

async function verifyFirebaseIdToken(token: string): Promise<AuthUser | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;
  try {
    const header = JSON.parse(base64UrlDecode(headerB64).toString('utf-8')) as {
      alg?: string;
      kid?: string;
    };
    if (header.alg !== 'RS256' || !header.kid) return null;

    const certs = await getGooglePublicCerts();
    const cert = certs[header.kid];
    if (!cert) return null;

    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(`${headerB64}.${payloadB64}`);
    verifier.end();
    const sigBuf = base64UrlDecode(sigB64);
    if (!verifier.verify(cert, sigBuf)) return null;

    const payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf-8')) as {
      aud?: string;
      iss?: string;
      sub?: string;
      email?: string;
      email_verified?: boolean;
      name?: string;
      exp?: number;
    };

    const projectId = firebaseConfig.projectId;
    if (payload.aud !== projectId) return null;
    if (payload.iss !== `https://securetoken.google.com/${projectId}`) return null;
    if (!payload.sub || !payload.exp || Date.now() / 1000 >= payload.exp) return null;
    if (!payload.email_verified) return null;

    const email = payload.email || `${payload.sub}@firebase.user`;
    const isAdmin = email.toLowerCase() === BOOTSTRAPPED_ADMIN_EMAIL.toLowerCase();

    return {
      uid: payload.sub,
      username: payload.name || email.split('@')[0],
      email,
      role: isAdmin ? 'admin' : 'analyst',
      authProvider: 'firebase',
    };
  } catch {
    return null;
  }
}

export async function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required. Missing Bearer token.' });
  }
  const token = header.slice('Bearer '.length).trim();

  // Check local HMAC token first
  const localUser = verifyLocalToken(token);
  if (localUser) {
    req.user = localUser;
    return next();
  }

  // Otherwise verify Firebase ID token cryptographically
  const firebaseUser = await verifyFirebaseIdToken(token);
  if (firebaseUser) {
    req.user = firebaseUser;
    return next();
  }

  return res.status(401).json({ error: 'Invalid or expired authentication token.' });
}

export function requireRole(...allowedRoles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Forbidden: Requires one of [${allowedRoles.join(', ')}] role.`,
      });
    }
    return next();
  };
}
