import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { User, UserRole } from '../types';
import { Clock, ShieldAlert, RefreshCw, LogOut, CheckCircle2, AlertTriangle } from 'lucide-react';

interface AuthContextType {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  sessionExpiresAt: string | null;
  isApproachingExpiry: boolean;
  remainingSeconds: number | null;
  login: (username: string, password: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  hasRole: (...roles: UserRole[]) => boolean;
  refreshUser: () => Promise<void>;
  extendSession: () => Promise<boolean>;
  simulateExpiryWarning: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Warning threshold: Exactly 10 minutes (600 seconds) before actual session expiration
export const WARNING_THRESHOLD_SECONDS = 10 * 60; // 600 seconds

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(() => {
    return sessionStorage.getItem('deiv_token');
  });
  const [sessionExpiresAt, setSessionExpiresAt] = useState<string | null>(() => {
    return sessionStorage.getItem('deiv_expires_at');
  });
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [remainingSeconds, setRemainingSeconds] = useState<number | null>(null);
  const [isApproachingExpiry, setIsApproachingExpiry] = useState<boolean>(false);
  const [isExtending, setIsExtending] = useState<boolean>(false);
  const [extendError, setExtendError] = useState<string | null>(null);
  const [extendNotification, setExtendNotification] = useState<string | null>(null);

  const isExtendingRef = useRef(false);
  const broadcastChannelRef = useRef<BroadcastChannel | null>(null);

  // Initialize BroadcastChannel for multiple open tabs synchronization
  useEffect(() => {
    try {
      if (typeof window !== 'undefined' && 'BroadcastChannel' in window) {
        const channel = new BroadcastChannel('provguard_auth_channel');
        broadcastChannelRef.current = channel;

        channel.onmessage = (event) => {
          const { type, expiresAt } = event.data || {};
          if (type === 'SESSION_EXTENDED' && expiresAt) {
            setSessionExpiresAt(expiresAt);
            sessionStorage.setItem('deiv_expires_at', expiresAt);
            setIsApproachingExpiry(false);
            setRemainingSeconds(null);
            setExtendError(null);
            setExtendNotification('Session renewed in another tab.');
            setTimeout(() => setExtendNotification(null), 3500);
          } else if (type === 'SESSION_LOGOUT' || type === 'SESSION_EXPIRED') {
            sessionStorage.removeItem('deiv_token');
            sessionStorage.removeItem('deiv_expires_at');
            setToken(null);
            setSessionExpiresAt(null);
            setUser(null);
            setIsApproachingExpiry(false);
            setRemainingSeconds(null);
          }
        };
      }
    } catch {
      // BroadcastChannel unavailable; fallback to storage event below
    }

    // Storage event fallback for older environments or cross-tab events
    const handleStorage = (e: StorageEvent) => {
      if (e.key === 'provguard_sync_event' && e.newValue) {
        try {
          const data = JSON.parse(e.newValue);
          if (data.type === 'SESSION_EXTENDED' && data.expiresAt) {
            setSessionExpiresAt(data.expiresAt);
            sessionStorage.setItem('deiv_expires_at', data.expiresAt);
            setIsApproachingExpiry(false);
            setRemainingSeconds(null);
            setExtendError(null);
          } else if (data.type === 'SESSION_LOGOUT') {
            sessionStorage.removeItem('deiv_token');
            sessionStorage.removeItem('deiv_expires_at');
            setToken(null);
            setSessionExpiresAt(null);
            setUser(null);
            setIsApproachingExpiry(false);
            setRemainingSeconds(null);
          }
        } catch {}
      }
    };

    window.addEventListener('storage', handleStorage);

    return () => {
      if (broadcastChannelRef.current) {
        broadcastChannelRef.current.close();
      }
      window.removeEventListener('storage', handleStorage);
    };
  }, []);

  const broadcastSync = (type: string, data?: Record<string, unknown>) => {
    if (broadcastChannelRef.current) {
      try {
        broadcastChannelRef.current.postMessage({ type, ...data });
      } catch {}
    }
    try {
      localStorage.setItem(
        'provguard_sync_event',
        JSON.stringify({ type, timestamp: Date.now(), ...data })
      );
    } catch {}
  };

  const logout = useCallback(async (isExpired = false) => {
    try {
      const currentToken = token || sessionStorage.getItem('deiv_token');
      if (currentToken) {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { Authorization: `Bearer ${currentToken}` },
        });
      }
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      sessionStorage.removeItem('deiv_token');
      sessionStorage.removeItem('deiv_expires_at');
      if (isExpired) {
        sessionStorage.setItem('deiv_expired_notice', 'Your session has expired due to inactivity. Please sign in again.');
      }
      setToken(null);
      setSessionExpiresAt(null);
      setUser(null);
      setIsApproachingExpiry(false);
      setRemainingSeconds(null);
      setExtendError(null);
      broadcastSync(isExpired ? 'SESSION_EXPIRED' : 'SESSION_LOGOUT');
    }
  }, [token]);

  const refreshUser = useCallback(async () => {
    const currentToken = token || sessionStorage.getItem('deiv_token');
    if (!currentToken) {
      setUser(null);
      setIsLoading(false);
      return;
    }

    try {
      const res = await fetch('/api/auth/me', {
        headers: {
          Authorization: `Bearer ${currentToken}`,
        },
      });

      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        if (data.expiresAt) {
          setSessionExpiresAt(data.expiresAt);
          sessionStorage.setItem('deiv_expires_at', data.expiresAt);
        }
      } else {
        // Session invalid or expired on backend
        logout(true);
      }
    } catch (err) {
      console.error('Failed to fetch user session:', err);
    } finally {
      setIsLoading(false);
    }
  }, [token, logout]);

  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  const login = async (username: string, password: string): Promise<{ success: boolean; error?: string }> => {
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json();
      if (!res.ok) {
        return { success: false, error: data.error || 'Authentication failed' };
      }

      sessionStorage.removeItem('deiv_expired_notice');
      sessionStorage.setItem('deiv_token', data.token);
      if (data.expiresAt) {
        sessionStorage.setItem('deiv_expires_at', data.expiresAt);
        setSessionExpiresAt(data.expiresAt);
      }
      setToken(data.token);
      setUser(data.user);
      setIsApproachingExpiry(false);
      setExtendError(null);
      return { success: true };
    } catch (err: unknown) {
      return { success: false, error: 'Network or server error: ' + (err instanceof Error ? err.message : String(err)) };
    }
  };

  const extendSession = async (): Promise<boolean> => {
    if (isExtendingRef.current) return false; // Prevent duplicate rapid clicks
    const currentToken = token || sessionStorage.getItem('deiv_token');
    if (!currentToken) {
      setExtendError('No active authentication token. Please sign in again.');
      logout(true);
      return false;
    }

    try {
      isExtendingRef.current = true;
      setIsExtending(true);
      setExtendError(null);

      const res = await fetch('/api/auth/extend-session', {
        method: 'POST',
        headers: { Authorization: `Bearer ${currentToken}` },
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to renew session. Authentication may have expired.');
      }

      const newExpiry = data.expiresAt || new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      setSessionExpiresAt(newExpiry);
      sessionStorage.setItem('deiv_expires_at', newExpiry);

      // Only close modal after successful renewal
      setIsApproachingExpiry(false);
      setRemainingSeconds(null);
      setExtendError(null);

      // Broadcast renewal to other open tabs
      broadcastSync('SESSION_EXTENDED', { expiresAt: newExpiry });

      setExtendNotification('Session successfully renewed for an additional 24 hours.');
      setTimeout(() => setExtendNotification(null), 3500);
      return true;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('Failed to extend session:', err);
      setExtendError(msg);

      if (msg.toLowerCase().includes('expired') || msg.toLowerCase().includes('not found')) {
        setTimeout(() => {
          logout(true);
        }, 2000);
      }
      return false;
    } finally {
      isExtendingRef.current = false;
      setIsExtending(false);
    }
  };

  // Educational testing utility: simulate approaching expiry in 10 minutes (600s)
  const simulateExpiryWarning = () => {
    const fakeExpiresAt = new Date(Date.now() + 600 * 1000).toISOString();
    setSessionExpiresAt(fakeExpiresAt);
    setRemainingSeconds(600);
    setIsApproachingExpiry(true);
    setExtendError(null);
  };

  // Real-time Session Countdown and Auto-Logout Inactivity Monitor
  useEffect(() => {
    if (!user || !sessionExpiresAt) {
      setIsApproachingExpiry(false);
      setRemainingSeconds(null);
      return;
    }

    const checkExpiry = () => {
      const now = Date.now();
      const expiresTime = new Date(sessionExpiresAt).getTime();
      const diffSec = Math.floor((expiresTime - now) / 1000);

      if (diffSec <= 0) {
        // Genuine expiration reached
        setRemainingSeconds(0);
        setIsApproachingExpiry(false);
        logout(true);
      } else if (diffSec <= WARNING_THRESHOLD_SECONDS) {
        // Within 10-minute (600 seconds) warning window
        setRemainingSeconds(diffSec);
        setIsApproachingExpiry(true);
      } else {
        // More than 10 minutes remaining
        setRemainingSeconds(diffSec);
        setIsApproachingExpiry(false);
      }
    };

    checkExpiry();
    const interval = setInterval(checkExpiry, 1000);
    return () => clearInterval(interval);
  }, [user, sessionExpiresAt, logout]);

  const hasRole = (...roles: UserRole[]): boolean => {
    if (!user) return false;
    return roles.includes(user.role);
  };

  // Formats seconds into MM:SS live countdown
  const formatCountdown = (seconds: number | null): string => {
    if (seconds === null || seconds < 0) return '00:00';
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isLoading,
        sessionExpiresAt,
        isApproachingExpiry,
        remainingSeconds,
        login,
        logout: () => logout(false),
        hasRole,
        refreshUser,
        extendSession,
        simulateExpiryWarning,
      }}
    >
      {children}

      {/* Extension success notification toast */}
      {extendNotification && (
        <div className="fixed bottom-5 right-5 z-50 p-3.5 rounded-xl bg-emerald-950/95 border border-emerald-500 text-emerald-200 text-xs font-semibold shadow-2xl flex items-center gap-2.5 animate-in fade-in duration-200">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{extendNotification}</span>
        </div>
      )}

      {/* 10-Minute Impending Session Expiration Warning Modal */}
      {isApproachingExpiry && user && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="session-warning-title"
          className="fixed inset-0 z-50 bg-black/85 backdrop-blur-md flex items-center justify-center p-4"
        >
          <div className="bg-[#0b0f19] border-2 border-amber-600/90 rounded-2xl p-6 w-full max-w-md shadow-[0_0_60px_rgba(245,158,11,0.3)] space-y-4 animate-in zoom-in-95 duration-200">
            {/* Modal Header */}
            <div className="flex items-center gap-3 pb-3 border-b border-slate-800">
              <div className="p-2.5 rounded-xl bg-amber-950/80 border border-amber-600/70 text-amber-400 shrink-0">
                <Clock className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <h3 id="session-warning-title" className="text-base font-bold text-slate-100 font-mono tracking-tight">
                  Session Expiring Soon!
                </h3>
                <p className="text-xs text-amber-400 font-medium">
                  Automated Security Inactivity Policy
                </p>
              </div>
            </div>

            {/* Modal Body */}
            <div className="space-y-3 text-xs text-slate-300">
              <p className="leading-relaxed">
                Your session will expire in 10 minutes due to inactivity. Would you like to continue your session?
              </p>

              {/* Live Countdown Timer in MM:SS Format */}
              <div className="p-4 rounded-xl bg-slate-950 border border-amber-900/70 flex flex-col items-center justify-center text-center shadow-inner">
                <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400 mb-1">
                  Time Remaining Before Auto-Logout
                </span>
                <span className="text-4xl font-extrabold font-mono text-amber-400 tracking-wider drop-shadow-[0_0_10px_rgba(245,158,11,0.4)]">
                  {formatCountdown(remainingSeconds)}
                </span>
                <span className="text-[10px] text-slate-500 font-mono mt-1">
                  Updates continuously every second
                </span>
              </div>

              {/* Renewal error alert if API call fails */}
              {extendError && (
                <div className="p-3 rounded-lg bg-red-950/80 border border-red-700/80 text-red-200 text-xs flex items-start gap-2 animate-in fade-in">
                  <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold">Renewal Failed: </span>
                    <span>{extendError}</span>
                  </div>
                </div>
              )}
            </div>

            {/* Action Buttons: Continue Session & Logout */}
            <div className="flex items-center gap-3 pt-2">
              <button
                type="button"
                onClick={() => logout(false)}
                className="flex-1 py-2.5 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-red-300 font-semibold text-xs border border-slate-700 transition flex items-center justify-center gap-1.5 focus:outline-none focus:ring-2 focus:ring-slate-500"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Logout</span>
              </button>

              <button
                type="button"
                onClick={() => extendSession()}
                disabled={isExtending}
                className="flex-1 py-2.5 px-3 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-xs shadow-lg transition flex items-center justify-center gap-1.5 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-cyan-400"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isExtending ? 'animate-spin' : ''}`} />
                <span>{isExtending ? 'Renewing...' : 'Continue Session'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
