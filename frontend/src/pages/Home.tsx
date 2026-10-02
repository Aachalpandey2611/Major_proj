import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api, Target } from '../api';
import { showToast } from '../utils/toast';

export default function Home() {
  const navigate = useNavigate();
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [scanningTargetId, setScanningTargetId] = useState<string | null>(null);
  const [deploymentDetected, setDeploymentDetected] = useState<string | null>(null); // target_id that was redeployed

  // Register Form State
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [environment, setEnvironment] = useState('staging');
  const [authToken, setAuthToken] = useState('');
  const [registerResult, setRegisterResult] = useState<any | null>(null);

  useEffect(() => {
    fetchTargets();
  }, []);

  const fetchTargets = async () => {
    try {
      setLoading(true);
      const data = await api.getTargets();
      setTargets(data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load targets.');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setError(null);
      const res = await api.registerTarget({
        name,
        url,
        environment,
        auth_token: authToken || undefined,
      });
      setRegisterResult(res);
      fetchTargets();
      // Reset form fields
      setName('');
      setUrl('');
      setAuthToken('');
      // Show success toast
      showToast.targetRegistered(res.name);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to register target.');
      showToast.error(err.response?.data?.detail || 'Failed to register target');
    }
  };

  const handleVerify = async (id: string) => {
    try {
      setError(null);
      await api.verifyOwnership(id);
      const target = targets.find(t => t.id === id);
      showToast.targetVerified(target?.name || 'Target');
      fetchTargets();
    } catch (err: any) {
      showToast.error(err.response?.data?.detail || 'Verification failed');
    }
  };

  const handleStartScan = async (targetId: string) => {
    try {
      setError(null);
      setScanningTargetId(targetId);
      const target = targets.find(t => t.id === targetId);
      showToast.scanStarted(target?.name || 'target');
      const result = await api.triggerScan(targetId);
      // Navigate to scan progress page
      navigate(`/dashboard/scan-progress?scan_id=${result.scan_id}&target_id=${targetId}`);
    } catch (err: any) {
      // Handle both string and object error responses
      const errorData = err.response?.data;
      console.log('🔍 ERROR DEBUG - Full error:', err);
      console.log('🔍 ERROR DEBUG - errorData:', errorData);
      console.log('🔍 ERROR DEBUG - errorData type:', typeof errorData);
      
      let errorMessage = 'Failed to start scan.';
      
      if (typeof errorData === 'string') {
        errorMessage = errorData;
      } else if (errorData?.detail) {
        errorMessage = typeof errorData.detail === 'string' ? errorData.detail : errorData.detail.message || 'Failed to start scan.';
      } else if (errorData?.message) {
        errorMessage = errorData.message;
      } else if (errorData?.error) {
        errorMessage = errorData.error;
      }
      
      console.log('🔍 ERROR DEBUG - Final errorMessage:', errorMessage);
      setError(errorMessage);
      showToast.scanFailed(errorMessage);
      setScanningTargetId(null);
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="flex justify-between items-center mb-10">
        <div>
          <h1 className="text-4xl font-extrabold tracking-tight bg-gradient-to-r from-accent-indigo via-accent-purple to-accent-pink bg-clip-text text-transparent">
            Vulnerability Scanner
          </h1>
          <p className="text-ink-soft mt-2">Register a chatbot, run 15 automated attacks, get code-level fixes and auto-retest on redeploy.</p>
        </div>
        <div className="flex space-x-2">
          <span className="px-3 py-1 text-xs rounded-full bg-accent-indigo/10 border border-accent-indigo/20 text-accent-indigo">
            v0.1.0 MVP
          </span>
        </div>
      </div>

      {error && (
        <div className="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-600 text-sm">
          ⚠️ {error}
        </div>
      )}

      {/* Deployment Detected Banner */}
      {deploymentDetected && (
        <div className="mb-6 p-5 rounded-xl bg-gradient-to-r from-cyan-50 to-blue-50 border border-cyan-300 shadow-md animate-[slideDown_0.5s_ease-out]">
          <div className="flex items-start justify-between">
            <div className="flex items-start space-x-3">
              <span className="text-3xl">🔄</span>
              <div>
                <h3 className="font-bold text-cyan-900 text-lg mb-1">Deployment Detected!</h3>
                <p className="text-cyan-700 text-sm">
                  New version of <span className="font-semibold">{targets.find(t => t.id === deploymentDetected)?.name}</span> detected. 
                  Automatically retesting open vulnerabilities...
                </p>
              </div>
            </div>
            <button
              onClick={() => setDeploymentDetected(null)}
              className="text-cyan-600 hover:text-cyan-800 text-xl"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

        {/* Register Form */}
        <div className="lg:col-span-1 p-6 rounded-2xl bg-white border border-border shadow-sm">
          <h2 className="text-xl font-bold mb-6 text-ink">Register Chatbot Target</h2>
          <form onSubmit={handleRegister} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-ink-soft uppercase tracking-wider mb-2">
                Chatbot Name
              </label>
              <input
                type="text"
                required
                placeholder="e.g. Support Bot Prod"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full px-4 py-2.5 rounded-lg bg-canvas border border-border text-ink placeholder-ink-soft/50 focus:outline-none focus:border-accent-indigo transition"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-ink-soft uppercase tracking-wider mb-2">
                Target Chat Endpoint URL
              </label>
              <input
                type="url"
                required
                placeholder="http://localhost:9000/chat"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="w-full px-4 py-2.5 rounded-lg bg-canvas border border-border text-ink placeholder-ink-soft/50 focus:outline-none focus:border-accent-indigo transition"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-ink-soft uppercase tracking-wider mb-2">
                Environment
              </label>
              <select
                value={environment}
                onChange={(e) => setEnvironment(e.target.value)}
                className="w-full px-4 py-2.5 rounded-lg bg-canvas border border-border text-ink focus:outline-none focus:border-accent-indigo transition"
              >
                <option value="dev">Development</option>
                <option value="staging">Staging</option>
                <option value="prod">Production</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold text-ink-soft uppercase tracking-wider mb-2">
                Authorization Token (Optional)
              </label>
              <input
                type="password"
                placeholder="Bearer secret-key (encrypted at rest)"
                value={authToken}
                onChange={(e) => setAuthToken(e.target.value)}
                className="w-full px-4 py-2.5 rounded-lg bg-canvas border border-border text-ink placeholder-ink-soft/50 focus:outline-none focus:border-accent-indigo transition"
              />
            </div>
            <button
              type="submit"
              className="w-full py-3 rounded-lg font-semibold bg-gradient-to-r from-accent-indigo to-accent-purple hover:opacity-90 text-white shadow-md shadow-indigo-500/20 transition duration-300"
            >
              Register Target
            </button>
          </form>
        </div>

        {/* Registered Targets List */}
        <div className="lg:col-span-2 space-y-6">

          {/* Registration Token Display (Sticky Alert) */}
          {registerResult && (
            <div className="p-6 rounded-2xl bg-indigo-50 border border-accent-indigo/30 shadow-sm relative overflow-hidden">
              <div className="absolute right-0 top-0 w-24 h-24 bg-accent-indigo/10 rounded-full blur-2xl"></div>
              <button
                onClick={() => setRegisterResult(null)}
                className="absolute top-4 right-4 text-ink-soft hover:text-ink"
              >
                ✕
              </button>
              <h3 className="text-lg font-bold text-accent-indigo mb-2">🎉 Registration Successful!</h3>
              <p className="text-xs text-amber-600 font-bold mb-4">⚠️ {registerResult.management_token_warning}</p>

              <div className="mb-4">
                <label className="block text-[10px] font-bold uppercase tracking-wider text-ink-soft mb-1">
                  Management Token (Save this!)
                </label>
                <div className="flex items-center space-x-2">
                  <code className="flex-1 p-2 rounded bg-white border border-border text-accent-indigo font-mono text-sm break-all select-all">
                    {registerResult.management_token}
                  </code>
                </div>
              </div>

              <div className="text-ink-soft text-xs space-y-2">
                <p><strong>Verification instructions:</strong> {registerResult.verification_instructions}</p>
                <p className="text-ink-soft/80 border-t border-border pt-2 mt-2">{registerResult.watcher_disclosure}</p>
              </div>
            </div>
          )}

          <div className="p-6 rounded-2xl bg-white border border-border shadow-sm">
            <h2 className="text-xl font-bold mb-6 text-ink">Monitored Chatbots</h2>

            {loading ? (
              <div className="space-y-4">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="p-5 rounded-xl bg-canvas border border-border animate-pulse">
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                      <div className="flex-1">
                        <div className="h-6 bg-border rounded w-1/3 mb-2"></div>
                        <div className="h-4 bg-border rounded w-2/3 mb-3"></div>
                        <div className="flex gap-4">
                          <div className="h-3 bg-border rounded w-20"></div>
                          <div className="h-3 bg-border rounded w-20"></div>
                        </div>
                      </div>
                      <div className="flex gap-3">
                        <div className="h-9 bg-border rounded w-24"></div>
                        <div className="h-9 bg-border rounded w-24"></div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : targets.length === 0 ? (
              <div className="text-center py-10 text-ink-soft">No targets registered yet. Add one above.</div>
            ) : (
              <div className="space-y-4">
                {targets.map((t) => (
                  <div
                    key={t.id}
                    className="p-5 rounded-xl bg-canvas border border-border hover:border-accent-indigo/40 transition flex flex-col md:flex-row md:items-center justify-between gap-4"
                  >
                    <div>
                      <div className="flex items-center space-x-2.5">
                        <h3 className="font-bold text-ink text-lg">{t.name}</h3>
                        <span className={`px-2 py-0.5 text-[10px] uppercase font-bold rounded-full ${
                          t.environment === 'prod' ? 'bg-red-100 text-red-600 border border-red-200' :
                          t.environment === 'staging' ? 'bg-amber-100 text-amber-600 border border-amber-200' :
                          'bg-emerald-100 text-emerald-600 border border-emerald-200'
                        }`}>
                          {t.environment}
                        </span>
                      </div>
                      <code className="text-ink-soft text-xs mt-1 block">{t.url}</code>

                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-3 text-xs text-ink-soft">
                        <span className="flex items-center space-x-1.5">
                          <span className={`w-2 h-2 rounded-full ${t.ownership_verified ? 'bg-emerald-500' : 'bg-amber-500'}`}></span>
                          <span>{t.ownership_verified ? 'Verified' : 'Verification Pending'}</span>
                        </span>
                        <span className="flex items-center space-x-1.5">
                          <span className={`w-2 h-2 rounded-full ${t.watcher_enabled ? 'bg-accent-indigo' : 'bg-border'}`}></span>
                          <span>Watcher {t.watcher_enabled ? 'Active' : 'Disabled'}</span>
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center space-x-3 self-end md:self-auto">
                      {!t.ownership_verified && (
                        <button
                          onClick={() => handleVerify(t.id)}
                          className="px-3.5 py-2 text-xs rounded-lg font-semibold border border-amber-300 hover:border-amber-400 bg-amber-50 hover:bg-amber-100 text-amber-700 transition"
                        >
                          Verify Ownership
                        </button>
                      )}

                      {t.ownership_verified && (
                        <>
                          <button
                            onClick={() => handleStartScan(t.id)}
                            disabled={scanningTargetId === t.id}
                            className="px-4 py-2 text-xs rounded-lg font-semibold bg-gradient-to-r from-emerald-500 to-emerald-600 hover:opacity-90 text-white transition shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            {scanningTargetId === t.id ? 'Starting...' : 'Start Scan'}
                          </button>
                          <Link
                            to={`/dashboard/findings?target_id=${t.id}`}
                            className="px-4 py-2 text-xs rounded-lg font-semibold bg-gradient-to-r from-accent-indigo to-accent-purple hover:opacity-90 text-white transition shadow-sm"
                          >
                            View Audit
                          </Link>
                        </>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
