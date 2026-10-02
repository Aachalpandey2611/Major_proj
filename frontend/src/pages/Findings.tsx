import React, { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { api, Finding, Target } from '../api';
import { useSSE } from '../hooks/useSSE';
import { showToast } from '../utils/toast';

export default function Findings() {
  const [searchParams] = useSearchParams();
  const targetId = searchParams.get('target_id');

  const [target, setTarget] = useState<Target | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filter State
  const [statusFilter, setStatusFilter] = useState<'open' | 'all'>('open');

  // Modal / Detail State
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // Scan/Retest Execution State
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const { status: scanStatus, completedAttacks, totalAttacks } = useSSE(activeScanId);

  // API Key management modal state
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [mgmtToken, setMgmtToken] = useState('');
  const [keyLabel, setKeyLabel] = useState('github-actions-ci');
  const [generatedKey, setGeneratedKey] = useState<any | null>(null);

  useEffect(() => {
    if (targetId) {
      fetchTargetData();
      fetchFindings();
    }
  }, [targetId, statusFilter]);

  // Refresh findings when scan finishes
  useEffect(() => {
    if (scanStatus === 'done' || scanStatus === 'fully_secure' || scanStatus === 'failed') {
      fetchFindings();
    }
  }, [scanStatus]);

  const fetchTargetData = async () => {
    try {
      if (!targetId) return;
      const data = await api.getTarget(targetId);
      setTarget(data);
    } catch (err) {}
  };

  const fetchFindings = async () => {
    try {
      if (!targetId) return;
      setLoading(true);
      const data = await api.getFindings(targetId, statusFilter === 'open' ? 'open' : undefined);
      setFindings(data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to fetch findings.');
    } finally {
      setLoading(false);
    }
  };

  const handleStartScan = async () => {
    try {
      if (!targetId) return;
      setError(null);
      const res = await api.triggerScan(targetId);
      setActiveScanId(res.scan_id);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to start scan.');
    }
  };

  const handleRetest = async () => {
    try {
      console.log('🔄 RETEST CLICKED - Findings count:', findings.length, 'First scan_id:', findings[0]?.scan_id);
      if (findings.length === 0) return;
      setError(null);
      // Retest based on the scan_id of the first finding (since they share scan)
      const scanId = findings[0].scan_id;
      if (!scanId) return;
      showToast.retestStarted(target?.name || 'target');
      const res = await api.triggerRetest(scanId);
      setActiveScanId(res.retest_scan_id);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to trigger retest.');
      showToast.error(err.response?.data?.detail || 'Failed to trigger retest');
    }
  };

  const handleGenerateApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (!targetId) return;
      setError(null);
      const res = await api.createApiKey(targetId, keyLabel, mgmtToken);
      setGeneratedKey(res);
      setMgmtToken('');
      showToast.apiKeyCreated();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create API key.');
      showToast.error(err.response?.data?.detail || 'Failed to create API key');
    }
  };

  // Severity aggregations
  const critical = findings.filter((f) => f.severity === 'critical').length;
  const high = findings.filter((f) => f.severity === 'high').length;
  const medium = findings.filter((f) => f.severity === 'medium').length;
  const low = findings.filter((f) => f.severity === 'low').length;

  if (!targetId) {
    return (
      <div className="text-center py-20 text-ink-soft">
        No target selected. <Link to="/dashboard/scanner" className="text-accent-indigo underline">Go to the scanner dashboard</Link> to choose one.
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-4 py-8">
      {/* Back button */}
      <Link to="/dashboard/scanner" className="text-sm font-semibold text-ink-soft hover:text-ink transition flex items-center space-x-1.5 mb-6">
        <span>← Back to Scanner Dashboard</span>
      </Link>

      {/* Target Details Header */}
      {target && (
        <div className="p-6 rounded-2xl bg-white border border-border shadow-sm mb-8 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-2xl font-bold text-ink">{target.name}</h1>
              <span className="px-2 py-0.5 text-[10px] uppercase font-bold bg-canvas border border-border rounded-full text-ink-soft">
                {target.environment}
              </span>
            </div>
            <code className="text-ink-soft text-sm block mt-1">{target.url}</code>
          </div>

          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => setShowKeyModal(true)}
              className="px-4 py-2.5 rounded-lg text-xs font-semibold bg-canvas hover:bg-black/[0.04] text-ink border border-border transition"
            >
              🔑 Manage CI/CD Keys
            </button>

            {/* PDF Report Download Button - show if scan exists */}
            {findings.length > 0 && findings[0].scan_id && (
              <a
                href={`http://localhost:8001/api/v1/reports/scans/${findings[0].scan_id}/pdf`}
                download
                className="px-4 py-2.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white transition shadow-sm"
              >
                📄 Download PDF Report
              </a>
            )}

            {findings.length > 0 ? (
              <button
                onClick={() => {
                  console.log('🔘 Button clicked! activeScanId:', activeScanId, 'scanStatus:', scanStatus, 'disabled:', activeScanId !== null && scanStatus !== 'done');
                  handleRetest();
                }}
                disabled={activeScanId !== null && scanStatus !== 'done'}
                className="px-4 py-2.5 rounded-lg text-xs font-semibold bg-accent-purple hover:opacity-90 text-white transition shadow-sm disabled:opacity-50"
              >
                🔄 Retest Open Vulnerabilities
              </button>
            ) : (
              <button
                onClick={handleStartScan}
                disabled={activeScanId !== null && scanStatus !== 'done'}
                className="px-5 py-2.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-accent-indigo to-accent-purple hover:opacity-90 text-white transition shadow-sm disabled:opacity-50"
              >
                🛡️ Launch Full scan
              </button>
            )}
          </div>
        </div>
      )}

      {error && (
        <div className="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-600 text-sm">
          ⚠️ {error}
        </div>
      )}

      {/* SSE Scan Progress Bar */}
      {activeScanId && (
        <div className="mb-8 p-6 rounded-2xl bg-indigo-50 border border-accent-indigo/30 shadow-sm relative overflow-hidden">
          <div className="flex justify-between items-center mb-3">
            <div>
              <span className="text-sm font-bold text-accent-indigo uppercase tracking-wider">
                {scanStatus === 'connecting' && '🔄 Establishing Connection...'}
                {scanStatus === 'running' && '⚡ Scanning Chatbot Vulnerabilities...'}
                {scanStatus === 'done' && '✅ Scan Completed!'}
                {scanStatus === 'fully_secure' && '🛡️ System Fully Secured!'}
                {scanStatus === 'failed' && '❌ Scan Failed'}
              </span>
            </div>
            <span className="text-xs text-accent-indigo font-mono">
              {completedAttacks} / {totalAttacks} Attacks
            </span>
          </div>

          <div className="w-full h-3 bg-white rounded-full overflow-hidden border border-border p-0.5">
            <div
              className="h-full bg-gradient-to-r from-accent-indigo to-accent-purple rounded-full transition-all duration-300"
              style={{ width: `${(completedAttacks / totalAttacks) * 100}%` }}
            ></div>
          </div>
        </div>
      )}

      {/* Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <div className="p-4 rounded-xl bg-white border border-border shadow-sm flex flex-col justify-center">
          <span className="text-[10px] uppercase font-bold text-ink-soft tracking-wider">Critical</span>
          <span className={`text-2xl font-black ${critical > 0 ? 'text-red-600' : 'text-ink-soft/50'}`}>{critical}</span>
        </div>
        <div className="p-4 rounded-xl bg-white border border-border shadow-sm flex flex-col justify-center">
          <span className="text-[10px] uppercase font-bold text-ink-soft tracking-wider">High</span>
          <span className={`text-2xl font-black ${high > 0 ? 'text-orange-500' : 'text-ink-soft/50'}`}>{high}</span>
        </div>
        <div className="p-4 rounded-xl bg-white border border-border shadow-sm flex flex-col justify-center">
          <span className="text-[10px] uppercase font-bold text-ink-soft tracking-wider">Medium</span>
          <span className={`text-2xl font-black ${medium > 0 ? 'text-amber-500' : 'text-ink-soft/50'}`}>{medium}</span>
        </div>
        <div className="p-4 rounded-xl bg-white border border-border shadow-sm flex flex-col justify-center">
          <span className="text-[10px] uppercase font-bold text-ink-soft tracking-wider">Low & Info</span>
          <span className={`text-2xl font-black ${low > 0 ? 'text-blue-500' : 'text-ink-soft/50'}`}>{low}</span>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex border-b border-border mb-6">
        <button
          onClick={() => setStatusFilter('open')}
          className={`pb-3 px-4 font-semibold text-sm transition ${
            statusFilter === 'open' ? 'text-accent-indigo border-b-2 border-accent-indigo' : 'text-ink-soft hover:text-ink'
          }`}
        >
          Open Vulnerabilities
        </button>
        <button
          onClick={() => setStatusFilter('all')}
          className={`pb-3 px-4 font-semibold text-sm transition ${
            statusFilter === 'all' ? 'text-accent-indigo border-b-2 border-accent-indigo' : 'text-ink-soft hover:text-ink'
          }`}
        >
          All Audit History
        </button>
      </div>

      {/* Findings List */}
      {loading ? (
        <div className="space-y-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="p-5 rounded-xl bg-white border border-border shadow-sm animate-pulse">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="h-5 bg-border rounded w-20"></div>
                    <div className="h-6 bg-border rounded w-48"></div>
                  </div>
                  <div className="h-4 bg-border rounded w-full mb-2"></div>
                  <div className="h-4 bg-border rounded w-3/4"></div>
                </div>
                <div className="flex gap-2">
                  <div className="h-9 bg-border rounded w-24"></div>
                  <div className="h-9 bg-border rounded w-24"></div>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : findings.length === 0 ? (
        <div className="text-center py-20 rounded-2xl border border-dashed border-border text-ink-soft bg-white/60">
          🌱 No vulnerabilities found in this view. Chatbot is secure!
        </div>
      ) : (
        <div className="space-y-4">
          {findings.map((f) => (
            <div
              key={f.id}
              onClick={async () => {
                try {
                  const detail = await api.getFinding(f.id);
                  setSelectedFinding(detail);
                } catch (err) {
                  setSelectedFinding(f);
                }
              }}
              className={`p-5 rounded-xl bg-white border shadow-sm hover:shadow-md transition cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-4 ${
                f.status === 'resolved' 
                  ? 'border-emerald-300 bg-emerald-50/30 animate-[flip_0.6s_ease-in-out]' 
                  : 'border-border hover:border-accent-indigo/40'
              }`}
            >
              <div>
                <div className="flex items-center space-x-3">
                  <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                    f.severity === 'critical' ? 'bg-red-100 text-red-600 border border-red-200' :
                    f.severity === 'high' ? 'bg-orange-100 text-orange-600 border border-orange-200' :
                    f.severity === 'medium' ? 'bg-amber-100 text-amber-600 border border-amber-200' :
                    'bg-canvas text-ink-soft border border-border'
                  }`}>
                    {f.severity}
                  </span>
                  <h3 className="font-bold text-ink text-lg capitalize">
                    {f.attack_type.replace(/_/g, ' ')}
                  </h3>
                  {f.status === 'resolved' && (
                    <span className="text-emerald-600 text-xl animate-bounce">✅</span>
                  )}
                </div>
                <p className="text-ink-soft text-sm mt-1.5">{f.owasp_category}</p>
              </div>

              <div className="flex items-center space-x-4">
                <span className={`px-2.5 py-1 text-xs rounded-full font-bold uppercase ${
                  f.status === 'open' ? 'bg-red-50 text-red-600' :
                  f.status === 'resolved' ? 'bg-emerald-50 text-emerald-600' :
                  'bg-amber-50 text-amber-600'
                }`}>
                  {f.status === 'resolved' ? '✅ RESOLVED' : f.status.toUpperCase()}
                </span>
                <span className="text-accent-indigo text-xs font-bold">Review Fix →</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Selected Finding Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm overflow-y-auto">
          <div className="w-full max-w-3xl rounded-2xl bg-white border border-border shadow-2xl p-6 relative my-8 max-h-[85vh] overflow-y-auto">
            <button
              onClick={() => setSelectedFinding(null)}
              className="absolute top-4 right-4 text-ink-soft hover:text-ink"
            >
              ✕
            </button>

            <div className="flex items-center space-x-3 mb-6">
              <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                selectedFinding.severity === 'critical' ? 'bg-red-100 text-red-600 border border-red-200' :
                selectedFinding.severity === 'high' ? 'bg-orange-100 text-orange-600 border border-orange-200' :
                selectedFinding.severity === 'medium' ? 'bg-amber-100 text-amber-600 border border-amber-200' :
                'bg-canvas text-ink-soft border border-border'
              }`}>
                {selectedFinding.severity}
              </span>
              <h2 className="text-2xl font-bold text-ink capitalize">
                {selectedFinding.attack_type.replace(/_/g, ' ')}
              </h2>
            </div>

            <div className="space-y-6">
              {/* Payload & Response */}
              {selectedFinding.attack_payload && (
                <div>
                  <h4 className="text-xs font-bold text-ink-soft uppercase tracking-wider mb-2">Adversarial Probe Payload</h4>
                  <pre className="p-3.5 rounded-lg bg-canvas border border-border text-ink font-mono text-sm overflow-x-auto whitespace-pre-wrap select-all">
                    {selectedFinding.attack_payload}
                  </pre>
                </div>
              )}

              {selectedFinding.attack_response && (
                <div>
                  <h4 className="text-xs font-bold text-ink-soft uppercase tracking-wider mb-2">Chatbot Response</h4>
                  <pre className="p-3.5 rounded-lg bg-canvas border border-border text-ink font-mono text-sm overflow-x-auto whitespace-pre-wrap select-all">
                    {selectedFinding.attack_response}
                  </pre>
                </div>
              )}

              {/* Recommendation */}
              {selectedFinding.fix_recommendation && (
                <div>
                  <h4 className="text-xs font-bold text-ink-soft uppercase tracking-wider mb-2">Fix Recommendation</h4>
                  <p className="text-ink-soft text-sm leading-relaxed">{selectedFinding.fix_recommendation}</p>
                </div>
              )}

              {/* Code Snippet */}
              {selectedFinding.fix_code_snippet && (
                <div>
                  <h4 className="text-xs font-bold text-ink-soft uppercase tracking-wider mb-2">Suggested Code Fix Patch</h4>
                  <pre className="p-4 rounded-lg bg-[#0B0E14] border border-border text-emerald-400 font-mono text-sm overflow-x-auto select-all">
                    {selectedFinding.fix_code_snippet}
                  </pre>
                </div>
              )}

              {/* Compliance & Regulatory Mappings */}
              {selectedFinding.compliance && (
                <div className="p-4 rounded-xl bg-canvas border border-border">
                  <h4 className="text-xs font-bold text-accent-indigo uppercase tracking-wider mb-3">Compliance & Regulatory Mapping</h4>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-ink-soft mb-4">
                    <div>
                      <span className="block font-bold text-ink mb-0.5">EU AI Act</span>
                      <span>{selectedFinding.compliance.eu_ai_act}</span>
                    </div>
                    <div>
                      <span className="block font-bold text-ink mb-0.5">ISO 42001</span>
                      <span>{selectedFinding.compliance.iso_42001}</span>
                    </div>
                    <div>
                      <span className="block font-bold text-ink mb-0.5">NIST AI RMF</span>
                      <span>{selectedFinding.compliance.nist_ai_rmf}</span>
                    </div>
                  </div>

                  {/* Mandatory legal disclaimer badge */}
                  {selectedFinding.compliance.guidance_only && (
                    <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-[11px] text-amber-700 font-medium">
                      ⚠️ {selectedFinding.compliance.disclaimer}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* CI/CD API Key Generation Modal */}
      {showKeyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl bg-white border border-border shadow-2xl p-6 relative">
            <button
              onClick={() => {
                setShowKeyModal(false);
                setGeneratedKey(null);
              }}
              className="absolute top-4 right-4 text-ink-soft hover:text-ink"
            >
              ✕
            </button>

            <h2 className="text-xl font-bold mb-4 text-ink">CI/CD API Keys</h2>
            <p className="text-ink-soft text-xs mb-6">Create API Keys for authorization in Github Actions security workflows.</p>

            {generatedKey ? (
              <div className="space-y-4">
                <div className="p-4 rounded bg-indigo-50 border border-accent-indigo/30 text-xs text-accent-indigo">
                  <p className="font-bold text-amber-600 mb-2">⚠️ {generatedKey.warning || 'Store securely!'}</p>
                  <code className="block p-2 rounded bg-white border border-border text-emerald-600 font-mono text-sm break-all select-all select-none">
                    {generatedKey.api_key}
                  </code>
                </div>
                <button
                  onClick={() => {
                    setShowKeyModal(false);
                    setGeneratedKey(null);
                  }}
                  className="w-full py-2.5 rounded-lg bg-gradient-to-r from-accent-indigo to-accent-purple hover:opacity-90 text-white font-semibold text-xs transition"
                >
                  Done
                </button>
              </div>
            ) : (
              <form onSubmit={handleGenerateApiKey} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-ink-soft uppercase tracking-wider mb-2">
                    Key Label / Description
                  </label>
                  <input
                    type="text"
                    required
                    value={keyLabel}
                    onChange={(e) => setKeyLabel(e.target.value)}
                    className="w-full px-4 py-2.5 rounded-lg bg-canvas border border-border text-ink placeholder-ink-soft/50 focus:outline-none focus:border-accent-indigo transition text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-ink-soft uppercase tracking-wider mb-2">
                    Target Management Token
                  </label>
                  <input
                    type="password"
                    required
                    placeholder="Enter management token to authorize"
                    value={mgmtToken}
                    onChange={(e) => setMgmtToken(e.target.value)}
                    className="w-full px-4 py-2.5 rounded-lg bg-canvas border border-border text-ink placeholder-ink-soft/50 focus:outline-none focus:border-accent-indigo transition text-sm"
                  />
                </div>
                <button
                  type="submit"
                  className="w-full py-2.5 rounded-lg bg-gradient-to-r from-accent-indigo to-accent-purple hover:opacity-90 text-white font-semibold text-xs transition shadow-sm"
                >
                  Generate Key
                </button>
              </form>
            )}
          </div>
        </div>
      )}

    </div>
  );
}
