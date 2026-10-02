import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useAuth } from '../auth/AuthContext';

export default function Login() {
  const { login, demoCredentials } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as any)?.from?.pathname || '/dashboard';

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    
    const success = await login(email, password);
    setLoading(false);
    
    if (success) {
      navigate(from, { replace: true });
    } else {
      setError('Invalid email or password. Try the demo credentials below.');
    }
  };

  const handleDemo = async () => {
    setLoading(true);
    const success = await login(demoCredentials.username, demoCredentials.password);
    setLoading(false);
    if (success) {
      navigate(from, { replace: true });
    } else {
      setError('Demo login failed. Please check if backend is running.');
    }
  };

  return (
    <div className="min-h-screen bg-canvas text-ink font-sans flex items-center justify-center px-4">
      <motion.div
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
        className="w-full max-w-sm"
      >
        <Link to="/" className="flex items-center justify-center gap-2 font-display text-lg font-extrabold mb-8">
          <span className="text-xl">🛡️</span> SentinelLoop
        </Link>

        <div className="p-7 rounded-2xl bg-white border border-border shadow-xl">
          <h1 className="font-display text-xl font-bold mb-1">Welcome back</h1>
          <p className="text-sm text-ink-soft mb-6">Log in to your SentinelLoop dashboard.</p>

          <button
            type="button"
            onClick={handleDemo}
            disabled={loading}
            className="w-full mb-5 px-4 py-3 rounded-xl text-sm font-bold text-white bg-gradient-to-r from-accent-indigo to-accent-purple shadow-md shadow-indigo-500/20 hover:shadow-indigo-500/35 hover:-translate-y-0.5 transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? '⏳ Logging in...' : '⚡ One-Click Demo Login'}
          </button>
          <p className="text-[11px] text-center text-ink-soft mb-6">
            Uses test@sentinelloop.ai — no setup needed.
          </p>

          <div className="flex items-center gap-3 mb-6">
            <div className="h-px flex-1 bg-border" />
            <span className="text-[11px] uppercase tracking-wider text-ink-soft">or sign in manually</span>
            <div className="h-px flex-1 bg-border" />
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-ink-soft uppercase tracking-wider mb-1.5">
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="test@sentinelloop.ai"
                className="w-full px-3.5 py-2.5 rounded-lg bg-canvas border border-border text-ink placeholder-ink-soft/50 focus:outline-none focus:border-accent-indigo transition text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-ink-soft uppercase tracking-wider mb-1.5">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-3.5 py-2.5 rounded-lg bg-canvas border border-border text-ink placeholder-ink-soft/50 focus:outline-none focus:border-accent-indigo transition text-sm"
              />
            </div>

            {error && <p className="text-xs text-danger">{error}</p>}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg text-sm font-semibold text-ink border border-border bg-white hover:bg-black/[0.02] transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Logging in...' : 'Log in'}
            </button>
          </form>

          <div className="mt-3 p-3 rounded-lg bg-canvas border border-border text-[11px] text-ink-soft font-mono">
            demo credentials: <span className="font-semibold text-ink">{demoCredentials.username}</span> /{' '}
            <span className="font-semibold text-ink">{demoCredentials.password}</span>
          </div>
        </div>

        <p className="text-center text-sm text-ink-soft mt-6">
          Don't have an account?{' '}
          <Link to="/signup" className="font-semibold text-accent-indigo hover:underline">
            Sign up
          </Link>
        </p>
      </motion.div>
    </div>
  );
}
