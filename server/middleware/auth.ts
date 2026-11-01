import { Request, Response, NextFunction } from 'express';
import { db, UserRow } from '../db.js';

export interface AuthenticatedRequest extends Request {
  user?: Omit<UserRow, 'password_hash' | 'password_salt'>;
  sessionToken?: string;
  sessionExpiresAt?: string;
}

export function authMiddleware(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  let token: string | undefined;

  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  } else if (req.headers.cookie) {
    const cookies = req.headers.cookie.split(';');
    for (const cookie of cookies) {
      const [name, val] = cookie.trim().split('=');
      if (name === 'deiv_session') {
        token = decodeURIComponent(val);
        break;
      }
    }
  }

  if (!token) {
    next();
    return;
  }

  try {
    const now = new Date().toISOString();
    const sessionStmt = db.prepare(`
      SELECT s.token, s.expires_at, u.id, u.username, u.email, u.full_name, u.role, u.is_active, u.created_at, u.updated_at
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.token = ? AND s.expires_at > ? AND u.is_active = 1
    `);

    const result = sessionStmt.get(token, now) as {
      token: string;
      expires_at: string;
      id: string;
      username: string;
      email: string;
      full_name: string;
      role: 'Administrator' | 'Investigator' | 'Auditor';
      is_active: number;
      created_at: string;
      updated_at: string;
    } | undefined;

    if (result) {
      req.user = {
        id: result.id,
        username: result.username,
        email: result.email,
        full_name: result.full_name,
        role: result.role,
        is_active: result.is_active,
        created_at: result.created_at,
        updated_at: result.updated_at,
      };
      req.sessionToken = token;
      req.sessionExpiresAt = result.expires_at;
    }
  } catch (err) {
    console.error('Session lookup error:', err);
  }

  next();
}

export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required. Please sign in.' });
    return;
  }
  next();
}

export function requireRole(...allowedRoles: ('Administrator' | 'Investigator' | 'Auditor')[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required. Please sign in.' });
      return;
    }
    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({
        error: `Access denied. Role '${req.user.role}' is not authorized to perform this operation. Required: ${allowedRoles.join(' or ')}.`,
      });
      return;
    }
    next();
  };
}
