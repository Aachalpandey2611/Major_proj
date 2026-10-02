import { BrowserRouter, Routes, Route, Navigate, NavLink, useNavigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { Toaster } from 'react-hot-toast';
import { AuthProvider, ProtectedRoute, useAuth } from './auth/AuthContext';
import Landing from './pages/Landing';
import Login from './pages/Login';
import Signup from './pages/Signup';
import Guard from './pages/Guard';
import Home from './pages/Home';
import Findings from './pages/Findings';
import ScanProgress from './pages/ScanProgress';
import FullySecure from './pages/FullySecure';
import Dashboard from './pages/Dashboard';
import OnboardingWizard from './pages/OnboardingWizard';

function NavTab({ to, children, end }: { to: string; children: React.ReactNode; end?: boolean }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `px-3.5 py-1.5 rounded-lg text-sm font-semibold transition ${
          isActive
            ? 'bg-accent-indigo/10 text-accent-indigo border border-accent-indigo/25'
            : 'text-ink-soft hover:text-ink border border-transparent'
        }`
      }
    >
      {children}
    </NavLink>
  );
}

function AppShell({ children }: { children: React.ReactNode }) {
  const { username, logout } = useAuth();
  const navigate = useNavigate();

  const handleRestartOnboarding = () => {
    if (window.confirm('Restart the onboarding tutorial? This will guide you through the setup process again.')) {
      localStorage.removeItem('onboarding_completed');
      window.location.reload();
    }
  };

  return (
    <div className="min-h-screen bg-canvas text-ink font-sans selection:bg-accent-indigo/20">
      <nav className="border-b border-border bg-canvas/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between gap-6">
          <div className="flex items-center gap-3 shrink-0">
            <span className="text-xl font-bold bg-gradient-to-r from-accent-indigo via-accent-purple to-accent-pink bg-clip-text text-transparent">
              🛡️ SentinelLoop
            </span>
          </div>

          <div className="flex items-center gap-1.5">
            <NavTab to="/dashboard" end>Prompt Guard</NavTab>
            <NavTab to="/dashboard/scanner">Vulnerability Scanner</NavTab>
            <NavTab to="/dashboard/analytics">Analytics</NavTab>
          </div>

          <div className="flex items-center gap-4 shrink-0">
            <button
              onClick={handleRestartOnboarding}
              className="text-xs font-semibold text-ink-soft hover:text-ink transition"
              title="Restart onboarding tutorial"
            >
              ? Help
            </button>
            <a
              href="http://localhost:8001/docs"
              target="_blank"
              rel="noreferrer"
              className="text-xs font-semibold text-ink-soft hover:text-ink transition"
            >
              API Docs ↗
            </a>
            <div className="flex items-center gap-2 pl-3 border-l border-border">
              <span className="text-xs text-ink-soft">{username}</span>
              <button
                onClick={() => {
                  logout();
                  navigate('/');
                }}
                className="text-xs font-semibold text-ink-soft hover:text-danger transition"
              >
                Log out
              </button>
            </div>
          </div>
        </div>
      </nav>

      {children}
    </div>
  );
}

function OnboardingWrapper() {
  const [showOnboarding, setShowOnboarding] = useState(false);
  const { user } = useAuth();

  useEffect(() => {
    // Check if user has completed onboarding
    const hasCompletedOnboarding = localStorage.getItem('onboarding_completed');
    
    // Show onboarding if user is logged in and hasn't completed it
    if (user && !hasCompletedOnboarding) {
      setShowOnboarding(true);
    } else {
      setShowOnboarding(false);
    }
  }, [user]);

  const handleOnboardingComplete = () => {
    setShowOnboarding(false);
  };

  if (showOnboarding) {
    return <OnboardingWizard onComplete={handleOnboardingComplete} />;
  }

  return (
    <Routes>
      {/* Public marketing + auth */}
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<Signup />} />

      {/* Protected product */}
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <AppShell><Guard /></AppShell>
          </ProtectedRoute>
        }
      />
      <Route
        path="/dashboard/scanner"
        element={
          <ProtectedRoute>
            <AppShell><Home /></AppShell>
          </ProtectedRoute>
        }
      />
      <Route
        path="/dashboard/analytics"
        element={
          <ProtectedRoute>
            <AppShell><Dashboard /></AppShell>
          </ProtectedRoute>
        }
      />
      <Route
        path="/dashboard/findings"
        element={
          <ProtectedRoute>
            <AppShell><Findings /></AppShell>
          </ProtectedRoute>
        }
      />
      <Route
        path="/dashboard/scan-progress"
        element={
          <ProtectedRoute>
            <AppShell><ScanProgress /></AppShell>
          </ProtectedRoute>
        }
      />
      <Route
        path="/dashboard/fully-secure"
        element={
          <ProtectedRoute>
            <FullySecure />
          </ProtectedRoute>
        }
      />

      {/* Any unknown path (typos, old bookmarks) -> back to the landing page
          instead of a blank screen with no matching route. */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#fff',
              color: '#0B0E14',
              border: '1px solid #e5e7eb',
              padding: '16px',
              fontSize: '14px',
              borderRadius: '12px',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
            },
            success: {
              iconTheme: {
                primary: '#10b981',
                secondary: '#fff',
              },
            },
            error: {
              iconTheme: {
                primary: '#ef4444',
                secondary: '#fff',
              },
            },
          }}
        />
        <OnboardingWrapper />
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
