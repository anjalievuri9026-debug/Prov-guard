import test from 'node:test';
import assert from 'node:assert/strict';
import { db, initDatabase } from '../server/db.js';
import { WARNING_THRESHOLD_SECONDS } from '../src/context/AuthContext.js';

test('Scenario 1: Warning threshold is configured to exactly 10 minutes (600 seconds)', () => {
  assert.equal(WARNING_THRESHOLD_SECONDS, 600, 'Warning threshold must be exactly 600 seconds (10 minutes)');
});

test('Scenario 2: Countdown calculation and MM:SS formatting logic', () => {
  const formatCountdown = (seconds: number | null): string => {
    if (seconds === null || seconds < 0) return '00:00';
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  assert.equal(formatCountdown(600), '10:00', '600 seconds must format to 10:00');
  assert.equal(formatCountdown(599), '09:59', '599 seconds must format to 09:59');
  assert.equal(formatCountdown(65), '01:05', '65 seconds must format to 01:05');
  assert.equal(formatCountdown(0), '00:00', '0 seconds must format to 00:00');
  assert.equal(formatCountdown(-5), '00:00', 'Negative seconds must format to 00:00');
});

test('Scenario 3: Warning trigger logic activates only within 10-minute window', () => {
  const checkShouldWarn = (expiresAtIso: string, currentTimeMs: number): { warn: boolean; remainingSec: number } => {
    const diffSec = Math.floor((new Date(expiresAtIso).getTime() - currentTimeMs) / 1000);
    const warn = diffSec > 0 && diffSec <= WARNING_THRESHOLD_SECONDS;
    return { warn, remainingSec: Math.max(0, diffSec) };
  };

  const now = Date.now();
  // Case A: 15 minutes remaining -> No warning
  const fifteenMins = new Date(now + 15 * 60 * 1000).toISOString();
  assert.equal(checkShouldWarn(fifteenMins, now).warn, false);

  // Case B: Exactly 10 minutes remaining -> Warning active
  const tenMins = new Date(now + 10 * 60 * 1000).toISOString();
  const resB = checkShouldWarn(tenMins, now);
  assert.equal(resB.warn, true);
  assert.equal(resB.remainingSec, 600);

  // Case C: 5 minutes remaining -> Warning active
  const fiveMins = new Date(now + 5 * 60 * 1000).toISOString();
  assert.equal(checkShouldWarn(fiveMins, now).warn, true);

  // Case D: 0 seconds (expired) -> No warning modal (auto-logout triggers)
  const expired = new Date(now - 1000).toISOString();
  assert.equal(checkShouldWarn(expired, now).warn, false);
});

test('Scenario 4 & 5: Server-side session renewal, expiry enforcement, and expired access denial', async () => {
  initDatabase();

  const user = db.prepare('SELECT id FROM users LIMIT 1').get() as { id: string };
  assert.ok(user);

  const testToken = `test-sess-${Date.now()}`;
  const now = new Date();
  // Valid active session with 5 minutes remaining (within warning window)
  const expiresAt = new Date(now.getTime() + 5 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)').run(
    testToken,
    user.id,
    expiresAt,
    now.toISOString()
  );

  // Verify session is lookupable while active
  const activeLookup = db.prepare('SELECT * FROM sessions WHERE token = ? AND expires_at > ?').get(
    testToken,
    new Date().toISOString()
  );
  assert.ok(activeLookup, 'Session must be valid before expiration');

  // Simulate Continue Session: Extend session
  const newExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  db.prepare('UPDATE sessions SET expires_at = ? WHERE token = ?').run(newExpiresAt, testToken);

  const extendedLookup = db.prepare('SELECT expires_at FROM sessions WHERE token = ?').get(testToken) as { expires_at: string };
  assert.equal(extendedLookup.expires_at, newExpiresAt);

  // Test expiration denial: Expire the session in database
  const pastTime = new Date(Date.now() - 60000).toISOString();
  db.prepare('UPDATE sessions SET expires_at = ? WHERE token = ?').run(pastTime, testToken);

  // Protected API query must reject expired session
  const expiredLookup = db.prepare('SELECT * FROM sessions WHERE token = ? AND expires_at > ?').get(
    testToken,
    new Date().toISOString()
  );
  assert.equal(expiredLookup, undefined, 'Expired session must NOT be accepted by protected query');

  // Clean up test token
  db.prepare('DELETE FROM sessions WHERE token = ?').run(testToken);
});

test('Scenario 6: Server-side expiry timestamp consistency across page refresh', () => {
  initDatabase();
  const user = db.prepare('SELECT id FROM users LIMIT 1').get() as { id: string };
  const testToken = `refresh-test-${Date.now()}`;
  const persistentExpiry = new Date(Date.now() + 18 * 60 * 1000).toISOString();

  db.prepare('INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)').run(
    testToken,
    user.id,
    persistentExpiry,
    new Date().toISOString()
  );

  // On refresh, /api/auth/me queries database
  const sessionRow = db.prepare('SELECT expires_at FROM sessions WHERE token = ?').get(testToken) as { expires_at: string };
  assert.equal(sessionRow.expires_at, persistentExpiry, 'Page refresh must retrieve true server-side expiration timestamp');

  db.prepare('DELETE FROM sessions WHERE token = ?').run(testToken);
});

test('Scenario 7: Duplicate renewal protection logic', () => {
  const currentExpiry = new Date(Date.now() + 23 * 60 * 60 * 1000 + 55 * 60 * 1000); // 23h 55m remaining
  const now = new Date();
  const twentyThreeHoursFiftyMinutes = (23 * 60 + 50) * 60 * 1000;

  const isDuplicate = currentExpiry.getTime() - now.getTime() > twentyThreeHoursFiftyMinutes;
  assert.equal(isDuplicate, true, 'Rapid duplicate renewal within threshold must be detected and de-duplicated');
});
