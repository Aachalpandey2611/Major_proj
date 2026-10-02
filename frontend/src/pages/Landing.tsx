import React, { Suspense, lazy, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion, type Variants } from 'framer-motion';
import { TechMarquee } from '../components/TechMarquee';
import { ScanIntro } from '../components/ScanIntro';
import { AnimatedNumber } from '../components/AnimatedNumber';
import { useAuth } from '../auth/AuthContext';

const ThreeHero = lazy(() => import('../components/ThreeHero'));

const reveal: Variants = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0, transition: { duration: 0.45, ease: [0.22, 1, 0.36, 1] as [number, number, number, number] } },
};

function RevealCard({ children, i = 0, className = '' }: { children: React.ReactNode; i?: number; className?: string }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.3 }}
      transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] as [number, number, number, number], delay: i * 0.08 }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

const PROBLEMS = [
  {
    icon: (
      <svg className="h-6 w-6 text-rose-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    ),
    title: 'Every custom chatbot is a new attack surface',
    body: 'System prompts, RAG pipelines, and tool integrations create injection points that raw model safety training was never built to defend.',
  },
  {
    icon: (
      <svg className="h-6 w-6 text-amber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
    title: 'Manual red-teaming takes days, not minutes',
    body: 'Testing prompt injection, jailbreaks, and data leakage by hand across every attack category is slow, inconsistent, and easy to fall behind on.',
  },
  {
    icon: (
      <svg className="h-6 w-6 text-accent-indigo" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    ),
    title: 'One missed prompt is the breach',
    body: 'A single unguarded prompt injection can leak your system prompt, API keys, or customer PII — exactly what attackers target first.',
  },
];

const STEPS = [
  { n: '01', title: 'Register Target', body: 'Point SentinelLoop at your chatbot endpoint and verify ownership in seconds.' },
  { n: '02', title: 'Real-Time Guard', body: 'Every incoming prompt is scanned — rules, semantic similarity, and an LLM judge decide BLOCK or ALLOW before it reaches your model.' },
  { n: '03', title: 'Automated Red-Team Scan', body: '15 OWASP LLM Top-10 attack categories run against your deployed chatbot, each finding mapped to a concrete code fix.' },
  { n: '04', title: 'Auto-Retest + CI/CD Gate', body: 'Redeploy your fix and the watcher retests automatically. The same gate wires into GitHub Actions to block merges.' },
];

const FEATURES = [
  { icon: '⚡', title: 'Real-Time Prompt Guard', body: 'Every prompt is scanned before it reaches your LLM — sub-second BLOCK / ALLOW decisions, before any downstream call.' },
  { icon: '🧠', title: 'Explainable LLM Judge', body: 'Ambiguous cases get a reasoned verdict from an LLM judge, not just an opaque score — every decision has a stated reason.' },
  { icon: '🕸️', title: 'Semantic Similarity Engine', body: 'A 400+ prompt attack corpus lets the guard recognize novel phrasings of known injection and jailbreak patterns.' },
  { icon: '🔁', title: 'Auto-Retest on Redeploy', body: 'A fingerprint watcher detects when you ship a fix and automatically re-verifies every open finding — no manual re-scan.' },
  { icon: '🚦', title: 'CI/CD Security Gate', body: 'Wire SentinelLoop into GitHub Actions and block merges the moment a critical or high-severity finding appears.' },
  { icon: '📋', title: 'Compliance Mapping', body: 'Every finding maps to OWASP LLM Top 10, EU AI Act, NIST AI RMF, and ISO/IEC 42001 — guidance, not legal advice.' },
];

const FRAMEWORKS = ['OWASP LLM Top 10', 'EU AI Act', 'NIST AI RMF', 'ISO/IEC 42001'];

export default function Landing() {
  const [introDone, setIntroDone] = useState(false);
  const { isAuthenticated } = useAuth();
  const ctaTo = isAuthenticated ? '/dashboard' : '/login';
  const ctaLabel = isAuthenticated ? 'Open Dashboard' : 'Launch Live Demo';

  return (
    <div className="min-h-screen bg-canvas text-ink font-sans selection:bg-accent-indigo/20">
      <ScanIntro onComplete={() => setIntroDone(true)} />

      {/* Header */}
      <header className="sticky top-0 z-30 border-b border-border/70 bg-canvas/80 backdrop-blur-2xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="relative flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-accent-indigo via-accent-purple to-accent-pink shadow-lg shadow-indigo-500/25">
              <span className="text-base">🛡️</span>
            </div>
            <div>
              <span className="font-display text-base font-bold text-ink">SentinelLoop</span>
              <span className="ml-2 text-[10px] uppercase font-bold tracking-widest text-accent-indigo bg-accent-indigo/10 px-2 py-0.5 rounded border border-accent-indigo/20">
                v1.0
              </span>
            </div>
          </div>
          <nav className="hidden items-center gap-8 text-xs font-semibold uppercase tracking-wider text-ink-soft md:flex">
            <a href="#how-it-works" className="transition hover:text-ink">How it works</a>
            <a href="#features" className="transition hover:text-ink">Features</a>
            <a href="#stack" className="transition hover:text-ink">Tech stack</a>
          </nav>
          <div className="flex items-center gap-3">
            {!isAuthenticated ? (
              <>
                <Link
                  to="/login"
                  className="px-5 py-2.5 text-xs font-bold text-ink-soft hover:text-ink transition"
                >
                  Sign In
                </Link>
                <Link
                  to="/signup"
                  className="rounded-xl bg-gradient-to-r from-accent-indigo via-accent-purple to-accent-pink px-5 py-2.5 text-xs font-bold text-white shadow-md shadow-indigo-500/25 transition hover:scale-105"
                >
                  Get Started Free
                </Link>
              </>
            ) : (
              <>
                <Link
                  to="/dashboard"
                  className="rounded-xl bg-gradient-to-r from-accent-indigo via-accent-purple to-accent-pink px-5 py-2.5 text-xs font-bold text-white shadow-md shadow-indigo-500/25 transition hover:scale-105"
                >
                  Open Dashboard
                </Link>
                <button
                  onClick={() => {
                    localStorage.removeItem('sentinelloop_auth_token');
                    window.location.reload();
                  }}
                  className="px-5 py-2.5 text-xs font-bold text-red-600 hover:text-red-700 transition"
                >
                  Logout
                </button>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="relative flex min-h-[82vh] items-center overflow-hidden bg-canvas py-20">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_25%_25%,rgba(99,102,241,0.10),transparent_55%)]" />
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_80%_75%,rgba(236,72,153,0.08),transparent_50%)]" />
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.5]"
          style={{
            backgroundImage:
              'linear-gradient(to right, #0B0E14 1px, transparent 1px), linear-gradient(to bottom, #0B0E14 1px, transparent 1px)',
            backgroundSize: '56px 56px',
            opacity: 0.035,
            maskImage: 'radial-gradient(circle at 50% 30%, black, transparent 70%)',
          }}
        />

        <div className="relative mx-auto grid max-w-7xl grid-cols-1 items-center gap-10 px-6 lg:grid-cols-2">
          <motion.div initial="hidden" animate={introDone ? 'show' : 'hidden'} variants={reveal}>
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-accent-indigo/25 bg-accent-indigo/5 px-4 py-1.5">
              <span className="h-2 w-2 rounded-full bg-safe animate-pulse" />
              <span className="text-xs font-semibold tracking-wide text-accent-indigo">
                Live security layer for LLM applications
              </span>
            </div>

            <h1 className="font-display text-4xl font-extrabold leading-[1.08] text-ink md:text-5xl lg:text-6xl">
              LLM Security,{' '}
              <span className="bg-gradient-to-r from-accent-indigo via-accent-purple to-accent-pink bg-clip-text text-transparent">
                Closed Loop.
              </span>
            </h1>

            <p className="mt-6 max-w-xl text-base leading-relaxed text-ink-soft">
              SentinelLoop sits between your users and your LLM in real time, scans every prompt for
              injection and jailbreak attempts, and automatically red-teams your chatbot for the
              vulnerabilities your team didn't know to test for.
            </p>

            <div className="mt-9 flex flex-wrap items-center gap-4">
              <Link
                to={ctaTo}
                className="group relative inline-flex items-center gap-2 overflow-hidden rounded-xl bg-gradient-to-r from-accent-indigo via-accent-purple to-accent-pink p-0.5 shadow-lg shadow-indigo-500/20 transition-all duration-300 hover:scale-105"
              >
                <span className="inline-flex items-center gap-2 rounded-[10px] bg-white px-7 py-3.5 text-sm font-bold text-ink transition-all duration-300 group-hover:bg-transparent group-hover:text-white">
                  {ctaLabel}
                  <svg className="h-4 w-4 transition-transform group-hover:translate-x-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                  </svg>
                </span>
              </Link>
              <a
                href="#how-it-works"
                className="rounded-xl border border-border bg-white px-6 py-3.5 text-sm font-semibold text-ink-soft transition hover:bg-black/[0.02] hover:text-ink"
              >
                How it works
              </a>
            </div>

            <div className="mt-12 flex flex-wrap items-center gap-2.5">
              <span className="text-[11px] uppercase tracking-widest text-ink-soft/70 font-mono mr-1">Maps to:</span>
              {FRAMEWORKS.map((fw) => (
                <span key={fw} className="rounded-lg border border-border bg-white px-3 py-1 text-xs font-mono text-ink-soft">
                  {fw}
                </span>
              ))}
            </div>
          </motion.div>

          <motion.div
            initial="hidden"
            animate={introDone ? 'show' : 'hidden'}
            variants={reveal}
            className="relative h-[340px] sm:h-[420px]"
          >
            <div className="absolute inset-0 rounded-[2rem] border border-border bg-gradient-to-br from-indigo-50 via-white to-pink-50 overflow-hidden">
              <Suspense fallback={<div className="w-full h-full" />}>
                <ThreeHero />
              </Suspense>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Problem Cards */}
      <section className="mx-auto max-w-7xl px-6 py-20">
        <div className="text-center">
          <p className="text-xs font-mono uppercase tracking-widest text-accent-indigo">The Problem</p>
          <h2 className="mt-2 font-display text-3xl font-bold text-ink">Why LLM Security Testing Is Broken</h2>
        </div>
        <div className="mt-12 grid grid-cols-1 gap-6 md:grid-cols-3">
          {PROBLEMS.map((p, i) => (
            <RevealCard key={p.title} i={i} className="rounded-2xl border border-border bg-white p-6 shadow-sm">
              <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-canvas border border-border">
                {p.icon}
              </div>
              <h3 className="font-display text-lg font-bold text-ink">{p.title}</h3>
              <p className="mt-3 text-sm leading-relaxed text-ink-soft">{p.body}</p>
            </RevealCard>
          ))}
        </div>
      </section>

      {/* How it works */}
      <section id="how-it-works" className="border-y border-border bg-white/60 py-20">
        <div className="mx-auto max-w-7xl px-6">
          <div className="text-center">
            <p className="text-xs font-mono uppercase tracking-widest text-accent-purple">End-to-End Workflow</p>
            <h2 className="mt-2 font-display text-3xl font-bold text-ink">Four Automated Steps, One Closed Loop</h2>
          </div>
          <div className="relative mt-14 grid grid-cols-1 gap-8 md:grid-cols-4">
            {STEPS.map((s, i) => (
              <RevealCard key={s.n} i={i} className="rounded-2xl border border-border bg-white p-6 shadow-sm">
                <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-accent-indigo to-accent-purple font-display text-lg font-bold text-white shadow-md shadow-indigo-500/20">
                  {s.n}
                </div>
                <h3 className="font-display text-base font-bold text-ink">{s.title}</h3>
                <p className="mt-2 text-xs leading-relaxed text-ink-soft">{s.body}</p>
              </RevealCard>
            ))}
          </div>
        </div>
      </section>

      {/* Impact Stats */}
      <section className="mx-auto max-w-7xl px-6 py-16">
        <RevealCard className="relative overflow-hidden rounded-3xl bg-white border border-border p-10 shadow-sm">
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_0%,rgba(99,102,241,0.06),transparent_60%)]" />
          <div className="relative grid grid-cols-2 gap-8 text-center md:grid-cols-4">
            {[
              { value: 15, label: 'Attack Categories' },
              { value: 3, label: 'Detection Layers' },
              { value: 444, label: 'Attack Corpus Prompts' },
              { value: 100, suffix: '%', label: 'Findings With a Fix' },
            ].map((stat) => (
              <div key={stat.label}>
                <p className="font-display text-4xl font-extrabold bg-gradient-to-r from-accent-indigo via-accent-purple to-accent-pink bg-clip-text text-transparent">
                  <AnimatedNumber value={stat.value} suffix={stat.suffix ?? ''} />
                </p>
                <p className="mt-2 text-xs font-semibold text-ink-soft">{stat.label}</p>
              </div>
            ))}
          </div>
        </RevealCard>
      </section>

      {/* Features Grid */}
      <section id="features" className="mx-auto max-w-7xl px-6 py-16">
        <div className="text-center">
          <p className="text-xs font-mono uppercase tracking-widest text-accent-indigo">Capabilities</p>
          <h2 className="mt-2 font-display text-3xl font-bold text-ink">Engineered for LLM Application Security</h2>
        </div>
        <div className="mt-12 grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f, i) => (
            <RevealCard key={f.title} i={i} className="rounded-2xl border border-border bg-white p-6 shadow-sm hover:shadow-md hover:-translate-y-1 transition">
              <span className="text-2xl">{f.icon}</span>
              <h3 className="mt-3 font-display text-base font-bold text-ink">{f.title}</h3>
              <p className="mt-2 text-xs leading-relaxed text-ink-soft">{f.body}</p>
            </RevealCard>
          ))}
        </div>
      </section>

      {/* Tech Marquee */}
      <section id="stack" className="border-y border-border bg-white/60 py-16">
        <h2 className="text-center font-display text-xl font-bold text-ink">Built With</h2>
        <div className="mt-8">
          <TechMarquee />
        </div>
      </section>

      {/* Footer CTA */}
      <footer className="mx-auto max-w-7xl px-6 py-16 text-center">
        <h2 className="font-display text-3xl font-bold text-ink">See it catch an attack, live.</h2>
        <p className="mt-3 text-sm text-ink-soft">One click gets you into the demo — no setup, admin credentials pre-filled.</p>
        <div className="mt-8">
          <Link
            to={ctaTo}
            className="inline-block rounded-xl bg-gradient-to-r from-accent-indigo via-accent-purple to-accent-pink px-8 py-3.5 text-sm font-bold text-white shadow-lg shadow-indigo-500/25 transition hover:scale-105"
          >
            {ctaLabel}
          </Link>
        </div>
        <p className="mt-12 text-xs text-ink-soft/70 font-mono">
          🛡️ SentinelLoop — Attack → Fix → Auto-Verify → CI/CD Gate.
        </p>
      </footer>
    </div>
  );
}
