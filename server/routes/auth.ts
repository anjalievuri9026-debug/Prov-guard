import { Router, Response } from 'express';
import crypto from 'node:crypto';
import { db, UserRow, appendAuditLog } from '../db.js';
import { verifyPassword, hashPassword } from '../crypto.js';
import { AuthenticatedRequest, requireAuth, requireRole } from '../middleware/auth.js';
import { loginRateLimiter, recordFailedLogin, clearFailedLogin, isValidUsername } from '../middleware/security.js';

export const authRouter = Router();

// Login endpoint with brute-force rate limiting
authRouter.post('/login', loginRateLimiter, (req, res): void => {
  const { username, password } = req.body;
  const clientIp = (req.ip || req.socket.remoteAddress || 'unknown-client') as string;

  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    res.status(400).json({ error: 'Username and password are required.' });
    return;
  }

  const cleanUsername = username.trim().toLowerCase();

  if (!isValidUsername(cleanUsername)) {
    recordFailedLogin(clientIp);
    res.status(400).json({ error: 'Invalid username format.' });
    return;
  }

  const userStmt = db.prepare('SELECT * FROM users WHERE LOWER(username) = ? AND is_active = 1');
  const user = userStmt.get(cleanUsername) as UserRow | undefined;

  if (!user || !verifyPassword(password, user.password_hash, user.password_salt)) {
    recordFailedLogin(clientIp);

    // Record failed login in audit log
    appendAuditLog({
      actorId: user ? user.id : 'ANONYMOUS',
      actorName: cleanUsername,
      actorRole: user ? user.role : 'UNKNOWN',
      action: 'AUTH_LOGIN_FAILED',
      evidenceId: null,
      details: {
        attempted_username: cleanUsername,
        ip: clientIp,
        user_agent: req.headers['user-agent'] || 'UNKNOWN',
      },
    });

    res.status(401).json({ error: 'Invalid username or password.' });
    return;
  }

  // Clear failed login attempts counter on success
  clearFailedLogin(clientIp);

  // Generate secure session token (256-bit entropy)
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24 hours
  const now = new Date().toISOString();

  const insertSession = db.prepare('INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)');
  insertSession.run(token, user.id, expiresAt, now);

  // Set HTTP-only cookie
  res.cookie('deiv_session', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000,
  });

  appendAuditLog({
    actorId: user.id,
    actorName: user.full_name,
    actorRole: user.role,
    action: 'AUTH_LOGIN_SUCCESS',
    evidenceId: null,
    details: {
      session_expires_at: expiresAt,
      ip: req.ip || req.socket.remoteAddress,
    },
  });

  res.json({
    token,
    expiresAt,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: user.full_name,
      role: user.role,
    },
  });
});

// Logout endpoint
authRouter.post('/logout', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  if (req.sessionToken) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(req.sessionToken);
  }
  res.clearCookie('deiv_session');

  if (req.user) {
    appendAuditLog({
      actorId: req.user.id,
      actorName: req.user.full_name,
      actorRole: req.user.role,
      action: 'AUTH_LOGOUT',
      evidenceId: null,
      details: {
        timestamp: new Date().toISOString(),
      },
    });
  }

  res.json({ message: 'Signed out successfully.' });
});

// Current user profile
authRouter.get('/me', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  res.json({
    user: {
      id: req.user!.id,
      username: req.user!.username,
      email: req.user!.email,
      fullName: req.user!.full_name,
      role: req.user!.role,
      createdAt: req.user!.created_at,
    },
    expiresAt: req.sessionExpiresAt,
  });
});

// Extend active session endpoint (refreshes TTL)
authRouter.post('/extend-session', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  if (!req.sessionToken) {
    res.status(401).json({ error: 'No active session token identified.' });
    return;
  }

  const now = new Date();
  const sessionStmt = db.prepare('SELECT expires_at FROM sessions WHERE token = ?');
  const session = sessionStmt.get(req.sessionToken) as { expires_at: string } | undefined;

  if (!session) {
    res.status(401).json({ error: 'Session not found. Please log in again.' });
    return;
  }

  const currentExpiry = new Date(session.expires_at);
  if (currentExpiry.getTime() <= now.getTime()) {
    // Session is already expired! Remove it and deny renewal.
    db.prepare('DELETE FROM sessions WHERE token = ?').run(req.sessionToken);
    res.status(401).json({ error: 'Session has already expired. Renewal is not permitted.' });
    return;
  }

  // Prevent duplicate concurrent renewal requests (within 10 seconds of recent extension)
  const twentyThreeHoursFiftyMinutes = (23 * 60 + 50) * 60 * 1000;
  if (currentExpiry.getTime() - now.getTime() > twentyThreeHoursFiftyMinutes) {
    res.json({
      message: 'Session already renewed.',
      expiresAt: session.expires_at,
    });
    return;
  }

  const newExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  db.prepare('UPDATE sessions SET expires_at = ? WHERE token = ?').run(newExpiresAt, req.sessionToken);

  res.cookie('deiv_session', req.sessionToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000,
  });

  appendAuditLog({
    actorId: req.user!.id,
    actorName: req.user!.full_name,
    actorRole: req.user!.role,
    action: 'AUTH_SESSION_EXTENDED',
    evidenceId: null,
    details: {
      new_expires_at: newExpiresAt,
      ip: req.ip || req.socket.remoteAddress,
    },
  });

  res.json({
    message: 'Session successfully extended.',
    expiresAt: newExpiresAt,
  });
});

// List all users (Admin only)
authRouter.get('/users', requireAuth, requireRole('Administrator'), (_req: AuthenticatedRequest, res: Response): void => {
  const stmt = db.prepare(`
    SELECT id, username, email, full_name, role, is_active, created_at, updated_at
    FROM users
    ORDER BY created_at ASC
  `);
  const users = stmt.all();
  res.json({ users });
});

// Create new user (Admin only)
authRouter.post('/users', requireAuth, requireRole('Administrator'), (req: AuthenticatedRequest, res: Response): void => {
  const { username, email, fullName, role, password } = req.body;

  if (!username || !email || !fullName || !role || !password) {
    res.status(400).json({ error: 'All fields (username, email, fullName, role, password) are required.' });
    return;
  }

  const validRoles = ['Administrator', 'Investigator', 'Auditor'];
  if (!validRoles.includes(role)) {
    res.status(400).json({ error: `Invalid role. Must be one of: ${validRoles.join(', ')}` });
    return;
  }

  if (password.length < 8) {
    res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    return;
  }

  const cleanUsername = username.trim().toLowerCase();
  const cleanEmail = email.trim().toLowerCase();

  // Check unique constraints
  const checkStmt = db.prepare('SELECT id FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?');
  const existing = checkStmt.get(cleanUsername, cleanEmail);
  if (existing) {
    res.status(409).json({ error: 'A user with that username or email address already exists.' });
    return;
  }

  const userId = `usr-${crypto.randomUUID().slice(0, 8)}`;
  const now = new Date().toISOString();
  const { hash, salt } = hashPassword(password);

  const insert = db.prepare(`
    INSERT INTO users (id, username, email, full_name, role, password_hash, password_salt, is_active, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
  `);

  insert.run(userId, cleanUsername, cleanEmail, fullName.trim(), role, hash, salt, now, now);

  appendAuditLog({
    actorId: req.user!.id,
    actorName: req.user!.full_name,
    actorRole: req.user!.role,
    action: 'USER_CREATED',
    evidenceId: null,
    details: {
      new_user_id: userId,
      new_username: cleanUsername,
      assigned_role: role,
      created_by: req.user!.username,
    },
  });

  res.status(201).json({
    message: 'User account created successfully.',
    user: {
      id: userId,
      username: cleanUsername,
      email: cleanEmail,
      fullName: fullName.trim(),
      role,
      createdAt: now,
    },
  });
});
