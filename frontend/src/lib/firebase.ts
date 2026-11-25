/**
 * Firebase Client Initialization, Connection Validation & Structured Firestore Error Handling
 */

import { initializeApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider } from 'firebase/auth';
import {
  collection,
  doc,
  getDoc,
  getDocFromServer,
  getDocs,
  getFirestore,
  orderBy,
  query,
  runTransaction,
  serverTimestamp,
  setDoc,
  updateDoc,
  where,
  writeBatch,
} from 'firebase/firestore';
import firebaseConfig from '../../../firebase-applet-config.json';
import type { ModelEvaluationMetrics } from '../../../ml/src/pipeline.ts';
import type { StoredAlert, StoredNetworkEvent, SystemSettings } from '../../../backend/src/store.ts';

const app = initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const auth = getAuth(app);
export const googleAuthProvider = new GoogleAuthProvider();

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(
  error: unknown,
  operationType: OperationType,
  path: string | null
): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo:
        auth.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

async function testConnection() {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration.');
    }
  }
}
void testConnection();

const BOOTSTRAPPED_ADMIN_EMAIL = 'varunsoniff2007@gmail.com';

function sanitizeId(raw: string): string {
  const cleaned = raw.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128);
  return cleaned || `doc_${Date.now()}`;
}

export interface FirestoreUserProfile {
  uid: string;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
}

const inFlightProfileSync = new Map<string, Promise<FirestoreUserProfile>>();

export async function ensureFirestoreUserProfile(
  uid: string,
  email: string,
  displayName: string | null
): Promise<FirestoreUserProfile> {
  const existingPromise = inFlightProfileSync.get(uid);
  if (existingPromise) {
    return existingPromise;
  }

  const path = `users/${uid}`;
  const syncPromise = (async (): Promise<FirestoreUserProfile> => {
    try {
      const ref = doc(db, 'users', uid);
      return await runTransaction(db, async (tx) => {
        const snap = await tx.get(ref);
        if (snap.exists()) {
          return snap.data() as FirestoreUserProfile;
        }
        const isBootstrappedAdmin = email.toLowerCase() === BOOTSTRAPPED_ADMIN_EMAIL.toLowerCase();
        const role: 'admin' | 'analyst' = isBootstrappedAdmin ? 'admin' : 'analyst';
        const rawName = (displayName || email.split('@')[0] || 'analyst').trim().slice(0, 64);
        const username = rawName.length >= 2 ? rawName : 'analyst';
        const payload = {
          uid: sanitizeId(uid),
          username,
          email: email.slice(0, 256),
          role,
          createdAt: serverTimestamp(),
        };
        tx.set(ref, payload);
        return { uid: payload.uid, username: payload.username, email: payload.email, role };
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.WRITE, path);
    } finally {
      inFlightProfileSync.delete(uid);
    }
  })();

  inFlightProfileSync.set(uid, syncPromise);
  return syncPromise;
}

export async function persistPredictionToFirestore(
  ownerId: string,
  event: StoredNetworkEvent,
  alert: StoredAlert | null
): Promise<void> {
  const safeOwnerId = sanitizeId(ownerId);
  const safeEventId = sanitizeId(event.id);
  const batch = writeBatch(db);

  const eventRef = doc(db, 'network_events', safeEventId);
  batch.set(eventRef, {
    ownerId: safeOwnerId,
    eventTime: String(event.eventTime).slice(0, 64),
    srcIp: String(event.srcIp).slice(0, 64),
    dstIp: String(event.dstIp).slice(0, 64),
    srcPort: Math.min(Math.max(Number(event.srcPort) || 0, 0), 65535),
    dstPort: Math.min(Math.max(Number(event.dstPort) || 0, 0), 65535),
    protocol: event.protocol,
    prediction: event.prediction,
    attackType: String(event.attackType).slice(0, 64),
    score: Math.min(Math.max(Number(event.score) || 0, 0), 1),
    severity: event.severity,
    modelVersion: String(event.modelVersion).slice(0, 32),
    flowDuration: Math.max(Number(event.flowDuration) || 0, 0),
    totalFwdPackets: Math.max(Number(event.totalFwdPackets) || 0, 0),
    totalBwdPackets: Math.max(Number(event.totalBwdPackets) || 0, 0),
    totalBytes: Math.max(Number(event.totalBytes) || 0, 0),
    flowBytesPerSec: Math.max(Number(event.flowBytesPerSec) || 0, 0),
    flowPacketsPerSec: Math.max(Number(event.flowPacketsPerSec) || 0, 0),
    synFlagCount: Math.max(Number(event.synFlagCount) || 0, 0),
    ackFlagCount: Math.max(Number(event.ackFlagCount) || 0, 0),
    sourceBatch: String(event.sourceBatch || 'Manual').slice(0, 128),
    createdAt: serverTimestamp(),
  });

  if (alert) {
    const safeAlertId = sanitizeId(alert.id);
    const alertRef = doc(db, 'alerts', safeAlertId);
    batch.set(alertRef, {
      ownerId: safeOwnerId,
      eventId: safeEventId,
      srcIp: String(alert.srcIp).slice(0, 64),
      dstIp: String(alert.dstIp).slice(0, 64),
      attackType: String(alert.attackType).slice(0, 64),
      severity: alert.severity,
      status: alert.status,
      description: String(alert.description).slice(0, 500),
      resolvedAt: String(alert.resolvedAt || '').slice(0, 64),
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
  }

  try {
    await batch.commit();
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, `network_events/${safeEventId}`);
  }
}

export async function updateAlertStatusInFirestore(
  alertId: string,
  status: 'Open' | 'Investigating' | 'Resolved',
  resolvedAt: string
): Promise<void> {
  const safeId = sanitizeId(alertId);
  const path = `alerts/${safeId}`;
  try {
    const ref = doc(db, 'alerts', safeId);
    const snap = await getDoc(ref);
    if (!snap.exists()) return;
    await updateDoc(ref, {
      status,
      resolvedAt: resolvedAt.slice(0, 64),
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function persistModelRegistryToFirestore(
  ownerId: string,
  metrics: ModelEvaluationMetrics
): Promise<void> {
  const safeOwnerId = sanitizeId(ownerId);
  const modelId = sanitizeId(`rf_${metrics.version}_${Date.now()}`);
  const path = `model_registry/${modelId}`;
  try {
    await setDoc(doc(db, 'model_registry', modelId), {
      ownerId: safeOwnerId,
      version: metrics.version.slice(0, 32),
      algorithm: metrics.algorithm.slice(0, 64),
      accuracy: Math.min(Math.max(metrics.accuracy, 0), 1),
      precisionScore: Math.min(Math.max(metrics.precision, 0), 1),
      recallScore: Math.min(Math.max(metrics.recall, 0), 1),
      f1Score: Math.min(Math.max(metrics.f1Score, 0), 1),
      falsePositiveRate: Math.min(Math.max(metrics.falsePositiveRate, 0), 1),
      tn: Math.max(metrics.confusionMatrix.tn, 0),
      fp: Math.max(metrics.confusionMatrix.fp, 0),
      fn: Math.max(metrics.confusionMatrix.fn, 0),
      tp: Math.max(metrics.confusionMatrix.tp, 0),
      trainSamples: Math.max(metrics.trainSamples, 0),
      testSamples: Math.max(metrics.testSamples, 0),
      nEstimators: Math.min(Math.max(metrics.nEstimators, 1), 500),
      maxDepth: Math.min(Math.max(metrics.maxDepth, 1), 50),
      artifactPath: metrics.artifactPath.slice(0, 256),
      isActive: Boolean(metrics.isActive),
      createdAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function saveSystemConfigToFirestore(
  ownerId: string,
  settings: SystemSettings
): Promise<void> {
  const safeId = sanitizeId(ownerId);
  const path = `system_config/${safeId}`;
  try {
    const ref = doc(db, 'system_config', safeId);
    const snap = await getDoc(ref);
    const payload = {
      ownerId: safeId,
      pollingIntervalSec: Math.min(Math.max(settings.pollingIntervalSec, 0), 300),
      criticalThreshold: Math.min(Math.max(settings.criticalThreshold, 0), 1),
      highThreshold: Math.min(Math.max(settings.highThreshold, 0), 1),
      mediumThreshold: Math.min(Math.max(settings.mediumThreshold, 0), 1),
      lowThreshold: Math.min(Math.max(settings.lowThreshold, 0), 1),
      detectionMode: 'detection_only' as const,
      zeekIntegrationEnabled: Boolean(settings.zeekIntegrationEnabled),
      updatedAt: serverTimestamp(),
    };
    if (snap.exists()) {
      await updateDoc(ref, {
        pollingIntervalSec: payload.pollingIntervalSec,
        criticalThreshold: payload.criticalThreshold,
        highThreshold: payload.highThreshold,
        mediumThreshold: payload.mediumThreshold,
        lowThreshold: payload.lowThreshold,
        zeekIntegrationEnabled: payload.zeekIntegrationEnabled,
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(ref, payload);
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function listFirestoreUsersForAdmin() {
  const path = 'users';
  try {
    const snap = await getDocs(collection(db, path));
    return snap.docs.map((d) => d.data() as { uid: string; username: string; email: string; role: 'admin' | 'analyst' | 'viewer' });
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}

export async function listUserModelRegistryFromFirestore(ownerId: string) {
  const path = 'model_registry';
  try {
    const q = query(
      collection(db, path),
      where('ownerId', '==', sanitizeId(ownerId)),
      orderBy('createdAt', 'desc')
    );
    const snap = await getDocs(q);
    return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  } catch (error) {
    // Graceful fallback if composite index is still building
    console.warn('Model registry Firestore list fallback:', error);
    return [];
  }
}
