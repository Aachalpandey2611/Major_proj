const STACK = [
  'React', 'TypeScript', 'Tailwind CSS', 'FastAPI', 'Python',
  'PostgreSQL', 'Redis', 'Celery', 'Google Gemini', 'sentence-transformers',
  'PBKDF2HMAC', 'Presidio', 'OWASP LLM Top 10', 'EU AI Act', 'NIST AI RMF', 'ISO/IEC 42001',
];

function Track() {
  return (
    <div className="flex shrink-0 items-center gap-3 pr-3">
      {STACK.map((item) => (
        <span
          key={item}
          className="whitespace-nowrap rounded-full border border-border bg-white px-4 py-2 text-sm font-medium text-ink-soft shadow-sm"
        >
          {item}
        </span>
      ))}
    </div>
  );
}

export function TechMarquee() {
  return (
    <div className="relative overflow-hidden">
      <div className="pointer-events-none absolute inset-y-0 left-0 z-10 w-16 bg-gradient-to-r from-canvas to-transparent" />
      <div className="pointer-events-none absolute inset-y-0 right-0 z-10 w-16 bg-gradient-to-l from-canvas to-transparent" />
      <div className="flex w-max animate-marquee">
        <Track />
        <Track />
      </div>
    </div>
  );
}
