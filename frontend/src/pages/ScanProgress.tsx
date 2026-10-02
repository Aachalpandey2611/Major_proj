import { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { api, Scan } from '../api';
import { showToast } from '../utils/toast';

// Attack type display names and order
const ATTACK_LAYERS = [
  { type: 'prompt_injection', name: 'Layer 1 — Prompt Injection' },
  { type: 'jailbreak', name: 'Layer 2 — Jailbreak' },
  { type: 'system_prompt_leak', name: 'Layer 3 — System Prompt Leak' },
  { type: 'data_leakage', name: 'Layer 4 — Data Leakage' },
  { type: 'role_override', name: 'Layer 5 — Role Override' },
  { type: 'indirect_injection', name: 'Layer 6 — Indirect Injection' },
  { type: 'rag_poisoning', name: 'Layer 7 — RAG Poisoning' },
  { type: 'tool_abuse', name: 'Layer 8 — Tool Abuse' },
  { type: 'denial_of_wallet', name: 'Layer 9 — Denial of Wallet' },
  { type: 'sql_injection', name: 'Layer 10 — SQL Injection' },
  { type: 'api_abuse', name: 'Layer 11 — API Abuse' },
  { type: 'context_manipulation', name: 'Layer 12 — Context Manipulation' },
  { type: 'training_data_extraction', name: 'Layer 13 — Training Data Extraction' },
  { type: 'sponge_attack', name: 'Layer 14 — Sponge Attack' },
  { type: 'few_shot_leakage', name: 'Layer 15 — Few-Shot Leakage' },
];

type AttackStatus = 'queued' | 'testing' | 'passed' | 'failed';

interface AttackState {
  status: AttackStatus;
  promptsTested?: number;
  totalPrompts?: number;
  confidence?: number;
  severity?: string;
}

export default function ScanProgress() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const scanId = searchParams.get('scan_id');
  const targetId = searchParams.get('target_id');

  const [scan, setScan] = useState<Scan | null>(null);
  const [attacks, setAttacks] = useState<Record<string, AttackState>>({});
  const [startTime] = useState(Date.now());
  const [elapsedTime, setElapsedTime] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [scanComplete, setScanComplete] = useState(false);

  // Initialize all attacks as queued
  useEffect(() => {
    const initialState: Record<string, AttackState> = {};
    ATTACK_LAYERS.forEach((layer) => {
      initialState[layer.type] = { status: 'queued' };
    });
    setAttacks(initialState);
  }, []);

  // Timer for elapsed time
  useEffect(() => {
    if (scanComplete) return; // Don't start timer if scan is already complete
    
    const interval = setInterval(() => {
      setElapsedTime(Math.floor((Date.now() - startTime) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [startTime, scanComplete]);

  // SSE Connection
  useEffect(() => {
    if (!scanId) return;

    // Get auth token from localStorage for SSE (EventSource doesn't support headers)
    const token = localStorage.getItem('sentinelloop_auth_token');
    if (!token) {
      setError('Authentication required');
      return;
    }

    const eventSource = new EventSource(`http://localhost:8001/api/v1/scans/${scanId}/stream?token=${token}`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        switch (data.event_type) {
          case 'connected':
            console.log('SSE connected');
            break;

          case 'scan_started':
            console.log('Scan started');
            break;

          case 'attack_complete': {
            const { attack_type, success, confidence } = data.data;
            setAttacks((prev) => ({
              ...prev,
              [attack_type]: {
                status: success ? 'failed' : 'passed', // success means vulnerability found
                confidence: confidence || 0,
                promptsTested: 10, // Updated to match MAX_PROMPTS_PER_TYPE
              },
            }));
            break;
          }

          case 'finding_discovered': {
            const { attack_type, severity } = data.data;
            setAttacks((prev) => ({
              ...prev,
              [attack_type]: {
                ...prev[attack_type],
                status: 'failed',
                severity,
              },
            }));
            // Show toast for critical/high findings
            if (severity === 'critical') {
              showToast.criticalFound(attack_type);
            } else if (severity === 'high') {
              showToast.highFound(attack_type);
            }
            break;
          }

          case 'scan_done':
            console.log('Scan complete');
            setScanComplete(true); // Stop the timer
            // Fetch final scan data and redirect to appropriate page based on findings
            if (scanId && targetId) {
              Promise.all([
                api.getScan(scanId),
                api.getFindings(targetId, 'open')
              ]).then(([finalScan, findingsData]) => {
                setScan(finalScan);
                
                // Filter findings for this specific scan
                const scanFindings = findingsData.filter((f: any) => f.scan_id === scanId);
                const failedCount = scanFindings.length;
                
                console.log(`🔍 Scan ${scanId} complete: ${failedCount} vulnerabilities found`);
                
                // Show completion toast
                showToast.scanComplete(failedCount, 'Scan');
                
                // Redirect to unified results page (it will show secure vs insecure based on findings)
                setTimeout(() => {
                  navigate(`/dashboard/fully-secure?target_id=${targetId}&scan_id=${scanId}`);
                }, 2000);
              }).catch((err) => {
                console.error('Error fetching scan results:', err);
                // Still redirect even if API fails
                setTimeout(() => {
                  navigate(`/dashboard/fully-secure?target_id=${targetId}&scan_id=${scanId}`);
                }, 2000);
              });
            }
            // Close SSE after 2 seconds
            setTimeout(() => {
              eventSource.close();
            }, 2000);
            break;

          case 'scan_failed':
            setError('Scan failed: ' + (data.data?.error || 'Unknown error'));
            showToast.scanFailed(data.data?.error);
            eventSource.close();
            break;

          case 'fully_secure':
            console.log('Target is fully secure!');
            // Show celebration toast
            showToast.fullySecured('Target');
            // Redirect to celebration page
            setTimeout(() => {
              navigate(`/dashboard/fully-secure?target_id=${targetId}&scan_id=${scanId}`);
            }, 1000);
            break;

          default:
            console.log('Unknown event:', data.event_type);
        }
      } catch (err) {
        console.error('Failed to parse SSE event:', err);
      }
    };

    eventSource.onerror = (err) => {
      console.error('SSE error:', err);
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [scanId]);

  // Fetch initial scan data
  useEffect(() => {
    if (!scanId) return;
    api.getScan(scanId).then(setScan).catch((err) => {
      setError('Failed to load scan: ' + err.message);
    });
  }, [scanId]);

  const getStatusIcon = (status: AttackStatus) => {
    switch (status) {
      case 'passed':
        return '✅';
      case 'failed':
        return '❌';
      case 'testing':
        return '⏳';
      default:
        return '⬜';
    }
  };

  const getStatusText = (attack: AttackState) => {
    switch (attack.status) {
      case 'passed':
        return `BLOCKED${attack.promptsTested ? ` (${attack.promptsTested} prompts tested)` : ''}`;
      case 'failed':
        return `VULNERABILITY${attack.severity ? ` (${attack.severity.toUpperCase()})` : ''}`;
      case 'testing':
        return attack.promptsTested && attack.totalPrompts
          ? `Testing prompt ${attack.promptsTested}/${attack.totalPrompts}...`
          : 'Testing...';
      default:
        return 'Queued';
    }
  };

  const completedCount = Object.values(attacks).filter((a) => a.status === 'passed' || a.status === 'failed').length;
  const totalCount = ATTACK_LAYERS.length;
  const progressPercent = Math.floor((completedCount / totalCount) * 100);

  if (!scanId) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-8">
        <div className="p-6 rounded-2xl bg-red-50 border border-red-200 text-red-600">
          Error: No scan ID provided
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-extrabold tracking-tight bg-gradient-to-r from-accent-indigo via-accent-purple to-accent-pink bg-clip-text text-transparent">
          Scan in Progress
        </h1>
        <p className="text-ink-soft mt-2">
          Testing 15 attack vectors with up to 85 prompts each...
        </p>
      </div>

      {error && (
        <div className="mb-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-600 text-sm">
          ⚠️ {error}
        </div>
      )}

      {/* Progress Overview */}
      <div className="mb-8 p-6 rounded-2xl bg-white border border-border shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="text-sm text-ink-soft mb-1">Progress</div>
            <div className="text-2xl font-bold text-ink">
              {completedCount}/{totalCount} attacks complete
            </div>
          </div>
          <div className="text-right">
            <div className="text-sm text-ink-soft mb-1">Elapsed Time</div>
            <div className="text-2xl font-bold text-ink">
              {Math.floor(elapsedTime / 60)}:{(elapsedTime % 60).toString().padStart(2, '0')}
            </div>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="w-full h-3 bg-canvas rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-accent-indigo via-accent-purple to-accent-pink transition-all duration-500"
            style={{ width: `${progressPercent}%` }}
          />
        </div>
        <div className="text-xs text-ink-soft text-right mt-1">{progressPercent}%</div>
      </div>

      {/* Attack Status List */}
      <div className="p-6 rounded-2xl bg-white border border-border shadow-sm">
        <h2 className="text-xl font-bold mb-6 text-ink">Attack Layers</h2>
        <div className="space-y-3">
          {ATTACK_LAYERS.map((layer) => {
            const attack = attacks[layer.type] || { status: 'queued' };
            const statusColor =
              attack.status === 'passed'
                ? 'text-emerald-600'
                : attack.status === 'failed'
                ? 'text-red-600'
                : attack.status === 'testing'
                ? 'text-amber-600'
                : 'text-ink-soft';

            return (
              <div
                key={layer.type}
                className={`p-4 rounded-lg border transition ${
                  attack.status === 'testing'
                    ? 'border-amber-300 bg-amber-50/50 animate-pulse'
                    : 'border-border bg-canvas'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className="text-2xl">{getStatusIcon(attack.status)}</span>
                    <div>
                      <div className="font-semibold text-ink">{layer.name}</div>
                      <div className={`text-sm ${statusColor}`}>{getStatusText(attack)}</div>
                    </div>
                  </div>
                  {attack.confidence !== undefined && (
                    <div className="text-xs text-ink-soft">
                      Confidence: {Math.round(attack.confidence * 100)}%
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Action Buttons */}
      {scan && scan.status === 'done' && (
        <div className="mt-8 flex justify-center space-x-4">
          <button
            onClick={() => navigate(`/dashboard/findings?target_id=${targetId}&scan_id=${scanId}`)}
            className="px-6 py-3 rounded-lg font-semibold bg-gradient-to-r from-accent-indigo to-accent-purple hover:opacity-90 text-white shadow-md transition"
          >
            View Results
          </button>
          <button
            onClick={() => navigate('/dashboard/scanner')}
            className="px-6 py-3 rounded-lg font-semibold border border-border hover:border-accent-indigo bg-white text-ink transition"
          >
            Back to Scanner
          </button>
        </div>
      )}
    </div>
  );
}
