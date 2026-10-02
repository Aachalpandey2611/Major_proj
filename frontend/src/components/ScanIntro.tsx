import { motion } from 'framer-motion';
import { useEffect, useMemo, useState } from 'react';

/**
 * "Cut and scattered" page-load reveal, SentinelLoop-themed.
 *
 * A light canvas cover with the SentinelLoop mark holds for a beat, then
 * gets sliced into vertical strips that fly apart — each strip alternating
 * left/right drift, its own rotation and delay — rather than sliding away
 * as one flat sheet. Still transform-only per strip (translate + rotate),
 * so it stays on the GPU compositor with zero layout/paint cost per frame.
 *
 * Plays on EVERY load/refresh (not session-gated) — this is the intended
 * f
 * irst-impression moment for the demo, not a one-time onboarding beat.
 */

const STRIP_COUNT = 7;
const HOLD_MS = 600;
const STRIP_DURATION = 0.55; // seconds, per strip
const STRIP_STAGGER = 0.06; // seconds between each strip's release
const SHRED_MS = Math.round(((STRIP_COUNT - 1) * STRIP_STAGGER + STRIP_DURATION) * 1000) + 250;
const TOTAL_MS = HOLD_MS + SHRED_MS;

type Phase = 'hold' | 'shred' | 'done';

function stripPlan(i: number) {
  // Even strips peel up-left, odd strips peel up-right — neighbors always
  // diverge in opposite directions so the cut reads clearly, and later
  // strips travel further so the wave doesn't look uniform.
  const dir = i % 2 === 0 ? -1 : 1;
  const driftX = dir * (65 + i * 14); // vw — dominant motion, sells the "cut apart"
  const driftY = -(30 + (i % 4) * 12); // vh — modest, so horizontal separation reads first
  const rotate = dir * (20 + i * 4); // deg
  const delay = i * STRIP_STAGGER; // left-to-right release wave
  return { driftX, driftY, rotate, delay };
}

export function ScanIntro({ onComplete }: { onComplete: () => void }) {
  const [phase, setPhase] = useState<Phase>('hold');

  const strips = useMemo(() => Array.from({ length: STRIP_COUNT }, (_, i) => stripPlan(i)), []);

  useEffect(() => {
    document.body.style.overflow = 'hidden';
    const t1 = setTimeout(() => setPhase('shred'), HOLD_MS);
    const t2 = setTimeout(() => {
      setPhase('done');
      document.body.style.overflow = '';
      onComplete();
    }, TOTAL_MS);
    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      document.body.style.overflow = '';
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (phase === 'done') return null;

  const shredding = phase === 'shred';
  const stripWidthPct = 100 / STRIP_COUNT;

  return (
    <div className="fixed inset-0 z-[100] overflow-hidden bg-intro">
      {/* Cut strips reconstructing the cover sheet at rest */}
      {strips.map((s, i) => (
        <motion.div
          key={i}
          className="absolute top-0 h-screen bg-intro border-r border-white/[0.05]"
          style={{
            left: `${i * stripWidthPct}%`,
            width: `${stripWidthPct + 0.4}%`,
            willChange: 'transform',
          }}
          initial={{ x: 0, y: 0, rotate: 0, scale: 1 }}
          animate={
            shredding
              ? { x: `${s.driftX}vw`, y: `${s.driftY}vh`, rotate: s.rotate, scale: 0.9 }
              : { x: 0, y: 0, rotate: 0, scale: 1 }
          }
          transition={{ duration: STRIP_DURATION, delay: s.delay, ease: [0.55, 0, 0.2, 1] }}
        />
      ))}

      {/* SentinelLoop mark — fades/scales out quickly as the cuts start */}
      <motion.div
        className="absolute inset-0 flex items-center justify-center"
        initial={{ opacity: 1, scale: 1 }}
        animate={shredding ? { opacity: 0, scale: 0.9 } : { opacity: 1, scale: 1 }}
        transition={{ duration: 0.35, ease: 'easeIn' }}
      >
        <div className="flex flex-col items-center">
          <motion.div
            className="mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br from-accent-indigo via-accent-purple to-accent-pink text-lg shadow-lg shadow-black/30"
            animate={{ scale: [1, 1.06, 1] }}
            transition={{ duration: 1.0, repeat: Infinity, ease: 'easeInOut' }}
          >
            🛡️
          </motion.div>
          <p className="font-display text-lg font-bold tracking-tight text-white">SentinelLoop</p>
        </div>
      </motion.div>
    </div>
  );
}
