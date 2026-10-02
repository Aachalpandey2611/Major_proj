import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useAuth } from '../auth/AuthContext';

export default function Signup() {
  const { login, demoCredentials } = useAuth();
  const navigate = useNavigate();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Demo product: any signup drops straight into the demo admin session.
    login(demoCredentials.username, demoCredentials.password);
    navigate('/dashboard', { replace: true });
  };

  const handleDemo = () => {
    login(demoCredentials.username, demoCredentials.password);
    navigate('/dashboard', { replace: true });
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
          <h1 className="font-display text-xl font-bold mb-1">Create your account</h1>
          <p className="text-sm text-ink-soft mb-6">Start securing your LLM chatbot in minutes.</p>

          <button
            type="button"
            onClick={handleDemo}
            className="w-full mb-5 px-4 py-3 rounded-xl text-sm font-bold text-white bg-gradient-to-r from-accent-indigo to-accent-purple shadow-md shadow-indigo-500/20 hover:shadow-indigo-500/35 hover:-translate-y-0.5 transition"
          >
            ⚡ Skip Setup — Try Demo
          </button>

          <div className="flex items-center gap-3 mb-6">
            <div className="h-px flex-1 bg-border" />
            <span className="text-[11px] uppercase tracking-wider text-ink-soft">or sign up</span>
            <div className="h-px flex-1 bg-border" />
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-ink-soft uppercase tracking-wider mb-1.5">
                Full Name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Jane Doe"
                className="w-full px-3.5 py-2.5 rounded-lg bg-canvas border border-border text-ink placeholder-ink-soft/50 focus:outline-none focus:border-accent-indigo transition text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-ink-soft uppercase tracking-wider mb-1.5">
                Work Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="jane@company.com"
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

            <button
              type="submit"
              className="w-full py-2.5 rounded-lg text-sm font-semibold text-ink border border-border bg-white hover:bg-black/[0.02] transition"
            >
              Create Account
            </button>
          </form>
        </div>

        <p className="text-center text-sm text-ink-soft mt-6">
          Already have an account?{' '}
          <Link to="/login" className="font-semibold text-accent-indigo hover:underline">
            Log in
          </Link>
        </p>
      </motion.div>
    </div>
  );
}
