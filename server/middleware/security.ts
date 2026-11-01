import { Request, Response, NextFunction } from 'express';

// In-memory brute-force protection tracking failed login attempts per IP
interface RateLimitRecord {
  count: number;
  firstAttemptTime: number;
  lockUntil?: number;
}

const loginAttempts = new Map<string, RateLimitRecord>();
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes window
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes lockout

/**
 * Applies defense-in-depth HTTP security headers to all responses.
 */
export function securityHeadersMiddleware(req: Request, res: Response, next: NextFunction): void {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
}

/**
 * Rate limiter middleware for login endpoints to thwart brute-force password guessing.
 */
export function loginRateLimiter(req: Request, res: Response, next: NextFunction): void {
  const ip = req.ip || req.socket.remoteAddress || 'unknown-client';
  const now = Date.now();
  const record = loginAttempts.get(ip);

  if (record) {
    // Check if currently locked out
    if (record.lockUntil && now < record.lockUntil) {
      const remainingSeconds = Math.ceil((record.lockUntil - now) / 1000);
      res.status(429).json({
        error: `Too many failed login attempts from this IP. Gateway locked for ${remainingSeconds} seconds to prevent brute-force attacks.`,
      });
      return;
    }

    // Reset window if expired
    if (now - record.firstAttemptTime > WINDOW_MS) {
      loginAttempts.delete(ip);
    }
  }

  next();
}

/**
 * Records a failed attempt for an IP.
 */
export function recordFailedLogin(ip: string): void {
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, firstAttemptTime: now };
  record.count += 1;

  if (record.count >= MAX_ATTEMPTS) {
    record.lockUntil = now + LOCKOUT_MS;
  }

  loginAttempts.set(ip, record);
}

/**
 * Clears failed attempts on successful login.
 */
export function clearFailedLogin(ip: string): void {
  loginAttempts.delete(ip);
}

/**
 * Validates and sanitizes a case ID string (e.g., CASE-2026-ALPHA).
 */
export function isValidCaseId(caseId: string): boolean {
  if (!caseId || typeof caseId !== 'string') return false;
  const trimmed = caseId.trim();
  return trimmed.length >= 3 && trimmed.length <= 50 && /^[A-Za-z0-9_.-]+$/.test(trimmed);
}

/**
 * Validates username (alphanumeric, underscores, 3-30 chars).
 */
export function isValidUsername(username: string): boolean {
  if (!username || typeof username !== 'string') return false;
  const trimmed = username.trim();
  return trimmed.length >= 3 && trimmed.length <= 30 && /^[a-zA-Z0-9_.-]+$/.test(trimmed);
}
