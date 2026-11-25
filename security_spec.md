# NetShield AI Security Specification (Phase 0 TDD)

## 1. Data Invariants
1. **Identity Integrity**: Every document in `network_events`, `alerts`, `model_registry`, and `system_config` must set `ownerId == request.auth.uid` on creation and never allow `ownerId` to be modified on update.
2. **PII Isolation**: `users/{userId}` contains `email`. Only the document owner (`request.auth.uid == userId`) or a verified administrator may read it. Non-owners cannot `get` or `list` other users' profiles.
3. **Privilege Escalation Prevention**: Non-admin users cannot self-assign `role: "admin"` on `users/{userId}` creation, cannot modify their own `role` field on update, and cannot write to `admins/{userId}`.
4. **Relational Referential Integrity**: An `alerts/{alertId}` document cannot be created unless its referenced `eventId` exists in `network_events/{eventId}` (checked via `exists()` or `existsAfter()` for atomic batch creation).
5. **Terminal State Locking**: Once an alert's `status` becomes `"Resolved"`, non-admin users cannot perform further updates on that alert.
6. **Temporal Integrity**: `createdAt` must equal `request.time` on creation and remain immutable on update; `updatedAt` must equal `request.time` on every mutation.
7. **Strict Schema Enforcement**: Every write must pass an entity-specific `isValid[Entity]()` validator checking exact allowed keys, types, ranges, enums, and string max lengths.
8. **Secure List Queries**: Every `allow list` rule evaluates `resource.data` directly without `get()` or `exists()` lookups.

## 2. The "Dirty Dozen" Adversarial Payloads
1. **Shadow Field Injection on Event**: Create `network_events/evt1` with valid fields plus ghost key `bypassAudit: true`. Expect `PERMISSION_DENIED`.
2. **Identity Spoofing on Event**: Authenticated as `userA`, create `network_events/evt2` with `ownerId: "userB"`. Expect `PERMISSION_DENIED`.
3. **Self-Assigned Admin Role**: Authenticated as unprivileged `userA`, create `users/userA` with `role: "admin"`. Expect `PERMISSION_DENIED`.
4. **Privilege Escalation Update**: Authenticated as `userA`, update `users/userA` changing `role` from `"analyst"` to `"admin"`. Expect `PERMISSION_DENIED`.
5. **PII Cross-User Read**: Authenticated as `userA`, `get` `users/userB`. Expect `PERMISSION_DENIED`.
6. **Unverified Admin Email Spoof**: Request token has `email: "varunsoniff2007@gmail.com"` with `email_verified: false`. Attempt to read `admins/uid1`. Expect `PERMISSION_DENIED`.
7. **Orphaned Alert Creation**: Create `alerts/alt1` referencing non-existent `eventId: "missing_evt_999"`. Expect `PERMISSION_DENIED`.
8. **Resolved Alert Tampering**: Non-admin owner attempts to update an alert whose `existing().status == "Resolved"` back to `"Open"`. Expect `PERMISSION_DENIED`.
9. **Value Poisoning on Alert Update**: Update `alerts/alt1` with `status: 12345` (invalid type) or 1MB `description`. Expect `PERMISSION_DENIED`.
10. **Immutable Field Overwrite**: Update `alerts/alt1` modifying `createdAt` or `eventId`. Expect `PERMISSION_DENIED`.
11. **Path ID Poisoning**: Create `network_events/<200-char-invalid-id-with-$pecial-chars>`. Expect `PERMISSION_DENIED`.
12. **Blanket Collection Scraping**: Unprivileged `userA` runs unconstrained `list` query on `network_events` containing `userB`'s documents. Expect `PERMISSION_DENIED`.
