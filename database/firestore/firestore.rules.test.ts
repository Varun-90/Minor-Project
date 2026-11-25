/**
 * NetShield AI - Firestore Security Rules Test Specification (Dirty Dozen)
 * Run against Firebase Emulator Suite using @firebase/rules-unit-testing.
 */

export interface DirtyDozenCase {
  id: number;
  name: string;
  collection: string;
  docId: string;
  operation: 'create' | 'update' | 'get' | 'list';
  actor: { uid: string; email: string; email_verified: boolean };
  payload?: Record<string, unknown>;
  expected: 'PERMISSION_DENIED';
}

export const DIRTY_DOZEN_CASES: DirtyDozenCase[] = [
  {
    id: 1,
    name: 'Shadow Field Injection on network_events',
    collection: 'network_events',
    docId: 'evt_shadow_01',
    operation: 'create',
    actor: { uid: 'analyst_a', email: 'a@example.com', email_verified: true },
    payload: { ownerId: 'analyst_a', bypassAudit: true },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 2,
    name: 'Identity Spoofing on network_events',
    collection: 'network_events',
    docId: 'evt_spoof_02',
    operation: 'create',
    actor: { uid: 'analyst_a', email: 'a@example.com', email_verified: true },
    payload: { ownerId: 'analyst_b', prediction: 'Normal' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 3,
    name: 'Self-Assigned Admin Role on users',
    collection: 'users',
    docId: 'analyst_a',
    operation: 'create',
    actor: { uid: 'analyst_a', email: 'a@example.com', email_verified: true },
    payload: { uid: 'analyst_a', username: 'attacker', email: 'a@example.com', role: 'admin' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 4,
    name: 'Role Privilege Escalation Update on users',
    collection: 'users',
    docId: 'analyst_a',
    operation: 'update',
    actor: { uid: 'analyst_a', email: 'a@example.com', email_verified: true },
    payload: { role: 'admin' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 5,
    name: 'PII Cross-User Read on users',
    collection: 'users',
    docId: 'analyst_b',
    operation: 'get',
    actor: { uid: 'analyst_a', email: 'a@example.com', email_verified: true },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 6,
    name: 'Unverified Admin Email Spoof on admins',
    collection: 'admins',
    docId: 'admin_1',
    operation: 'get',
    actor: { uid: 'spoof_uid', email: 'varunsoniff2007@gmail.com', email_verified: false },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 7,
    name: 'Orphaned Alert Creation without network_event',
    collection: 'alerts',
    docId: 'alt_orphan_07',
    operation: 'create',
    actor: { uid: 'analyst_a', email: 'a@example.com', email_verified: true },
    payload: { ownerId: 'analyst_a', eventId: 'non_existent_event_999', status: 'Open', severity: 'High' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 8,
    name: 'Resolved Alert Terminal State Tampering',
    collection: 'alerts',
    docId: 'alt_resolved_08',
    operation: 'update',
    actor: { uid: 'analyst_a', email: 'a@example.com', email_verified: true },
    payload: { status: 'Open' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 9,
    name: 'Value Poisoning on Alert Status',
    collection: 'alerts',
    docId: 'alt_open_09',
    operation: 'update',
    actor: { uid: 'analyst_a', email: 'a@example.com', email_verified: true },
    payload: { status: 12345 },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 10,
    name: 'Immutable createdAt Overwrite on alerts',
    collection: 'alerts',
    docId: 'alt_open_10',
    operation: 'update',
    actor: { uid: 'analyst_a', email: 'a@example.com', email_verified: true },
    payload: { createdAt: '1999-01-01T00:00:00Z' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 11,
    name: 'Path Variable ID Poisoning',
    collection: 'network_events',
    docId: 'invalid$id!'.repeat(20),
    operation: 'create',
    actor: { uid: 'analyst_a', email: 'a@example.com', email_verified: true },
    payload: { ownerId: 'analyst_a' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 12,
    name: 'Unconstrained Collection Scraping on network_events',
    collection: 'network_events',
    docId: '*',
    operation: 'list',
    actor: { uid: 'analyst_a', email: 'a@example.com', email_verified: true },
    expected: 'PERMISSION_DENIED',
  },
];
