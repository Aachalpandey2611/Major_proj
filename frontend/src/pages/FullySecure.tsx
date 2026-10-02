import { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import confetti from 'canvas-confetti';
import { api, Finding, Scan } from '../api';

interface ScanData {
  id: string;
  total_attacks: number;
  completed_attacks: number;
  status: string;
}

export default function FullySecure() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const targetId = searchParams.get('target_id');
  const scanId = searchParams.get('scan_id');

  const [targetName, setTargetName] = useState<string>('');
  const [scan, setScan] = useState<ScanData | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Force cache bust on mount
  useEffect(() => {
    console.log('🔍 FullySecure page mounted - Cache bust v2.1 - ' + new Date().toISOString());
  }, []);

  // Calculate security metrics
  const vulnerabilityCount = findings.length;
  const isSecure = vulnerabilityCount === 0;
  
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;
  const lowCount = findings.filter(f => f.severity === 'low').length;
  
  // Calculate security score (0-100%)
  const totalAttacks = scan?.total_attacks || 15;
  const passedAttacks = totalAttacks - vulnerabilityCount;
  const securityScore = Math.round((passedAttacks / totalAttacks) * 100);
  
  // Calculate average confidence of vulnerabilities (for insecurity score)
  const avgConfidence = findings.length > 0
    ? Math.round(findings.reduce((sum, f) => sum + (f.confidence || 0), 0) / findings.length * 100)
    : 0;

  useEffect(() => {
    const fetchData = async () => {
      try {
        console.log('🔍 FullySecure: Fetching data for targetId:', targetId, 'scanId:', scanId);
        
        // Fetch target details
        if (targetId) {
          const target = await api.getTarget(targetId);
          setTargetName(target.name);
          console.log('✅ Target fetched:', target.name);
        }
        
        // Fetch scan details
        if (scanId) {
          const scanData = await api.getScan(scanId);
          setScan(scanData);
          console.log('✅ Scan fetched:', scanData.status, 'attacks:', scanData.total_attacks);
          
          // Fetch findings for this scan
          const findingsData = await api.getFindings(targetId || '', 'open');
          console.log('📊 Total findings fetched:', findingsData.length);
          
          const scanFindings = findingsData.filter((f: any) => f.scan_id === scanId);
          console.log('🎯 Findings for this scan:', scanFindings.length);
          console.log('🚨 Vulnerability breakdown:', {
            critical: scanFindings.filter((f: any) => f.severity === 'critical').length,
            high: scanFindings.filter((f: any) => f.severity === 'high').length,
            medium: scanFindings.filter((f: any) => f.severity === 'medium').length,
            low: scanFindings.filter((f: any) => f.severity === 'low').length,
          });
          
          setFindings(scanFindings);
          
          // Log final state
          const isVulnerable = scanFindings.length > 0;
          console.log(isVulnerable ? '🔴 VULNERABLE CHATBOT - Should show RED OOPS page' : '🟢 SECURE CHATBOT - Should show GREEN page');
        }
        
        setLoading(false);
      } catch (err) {
        console.error('❌ Failed to fetch data:', err);
        setTargetName('Your chatbot');
        setLoading(false);
      }
    };
    
    fetchData();
  }, [targetId, scanId]);

  useEffect(() => {
    // Only fire confetti if the chatbot is SECURE
    if (!isSecure || loading) return;
    
    // Fire confetti celebration
    const duration = 3000;
    const animationEnd = Date.now() + duration;
    const defaults = { startVelocity: 30, spread: 360, ticks: 60, zIndex: 0 };

    function randomInRange(min: number, max: number) {
      return Math.random() * (max - min) + min;
    }

    const interval = setInterval(function () {
      const timeLeft = animationEnd - Date.now();

      if (timeLeft <= 0) {
        return clearInterval(interval);
      }

      const particleCount = 50 * (timeLeft / duration);

      // Launch confetti from two sides
      confetti({
        ...defaults,
        particleCount,
        origin: { x: randomInRange(0.1, 0.3), y: Math.random() - 0.2 },
      });
      confetti({
        ...defaults,
        particleCount,
        origin: { x: randomInRange(0.7, 0.9), y: Math.random() - 0.2 },
      });
    }, 250);

    return () => clearInterval(interval);
  }, [isSecure, loading]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-emerald-50 via-white to-cyan-50">
        <div className="text-lg text-ink-soft">Loading...</div>
      </div>
    );
  }

  return (
    <div className={`min-h-screen flex items-center justify-center p-6 ${
      isSecure 
        ? 'bg-gradient-to-br from-emerald-50 via-white to-cyan-50' 
        : 'bg-gradient-to-br from-red-50 via-white to-orange-50'
    }`}>
      <div className="max-w-2xl w-full text-center">
        {/* Icon */}
        <div className={`mb-8 ${isSecure ? 'animate-bounce' : 'animate-pulse'}`}>
          <div className={`inline-flex items-center justify-center w-32 h-32 rounded-full shadow-2xl ${
            isSecure
              ? 'bg-gradient-to-br from-emerald-400 to-cyan-500'
              : 'bg-gradient-to-br from-red-400 to-orange-500'
          }`}>
            <span className="text-7xl">{isSecure ? '🛡️' : '⚠️'}</span>
          </div>
        </div>

        {/* Title */}
        <h1 className={`text-5xl font-extrabold tracking-tight mb-4 ${
          isSecure
            ? 'bg-gradient-to-r from-emerald-600 via-cyan-600 to-blue-600'
            : 'bg-gradient-to-r from-red-600 via-orange-600 to-yellow-600'
        } bg-clip-text text-transparent`}>
          {isSecure ? 'Fully Secured!' : 'OOPS! Not Secured'}
        </h1>

        <p className="text-2xl text-ink mb-8">
          <span className="font-bold">{targetName}</span> 
          {isSecure 
            ? ' is protected against all known vulnerabilities.'
            : ` has ${vulnerabilityCount} vulnerabilit${vulnerabilityCount === 1 ? 'y' : 'ies'} that need attention.`
          }
        </p>

        {/* Statistics */}
        <div className={`mb-12 p-8 rounded-2xl bg-white/80 backdrop-blur-sm border shadow-lg ${
          isSecure ? 'border-emerald-200' : 'border-red-200'
        }`}>
          <div className="grid grid-cols-3 gap-6 text-center">
            <div>
              <div className={`text-4xl font-bold ${isSecure ? 'text-emerald-600' : 'text-red-600'}`}>
                {scan ? `${passedAttacks}/${scan.total_attacks}` : `${15 - vulnerabilityCount}/15`}
              </div>
              <div className="text-sm text-ink-soft mt-1">Attack Layers</div>
              <div className="text-xs text-ink-soft">{isSecure ? 'Passed' : 'Passed/Failed'}</div>
            </div>
            <div>
              <div className={`text-4xl font-bold ${isSecure ? 'text-emerald-600' : 'text-red-600'}`}>
                {vulnerabilityCount}
              </div>
              <div className="text-sm text-ink-soft mt-1">Open</div>
              <div className="text-xs text-ink-soft">Vulnerabilities</div>
            </div>
            <div>
              <div className={`text-4xl font-bold ${isSecure ? 'text-emerald-600' : 'text-red-600'}`}>
                {securityScore}%
              </div>
              <div className="text-sm text-ink-soft mt-1">Security</div>
              <div className="text-xs text-ink-soft">Score</div>
            </div>
          </div>
          
          {/* Vulnerability Breakdown for Insecure Chatbots */}
          {!isSecure && (
            <div className="mt-6 pt-6 border-t border-gray-200">
              <div className="grid grid-cols-4 gap-4 text-center text-sm">
                <div>
                  <div className="text-2xl font-bold text-red-600">{criticalCount}</div>
                  <div className="text-xs text-ink-soft mt-1">Critical</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-orange-600">{highCount}</div>
                  <div className="text-xs text-ink-soft mt-1">High</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-yellow-600">{mediumCount}</div>
                  <div className="text-xs text-ink-soft mt-1">Medium</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-blue-600">{lowCount}</div>
                  <div className="text-xs text-ink-soft mt-1">Low</div>
                </div>
              </div>
              {avgConfidence > 0 && (
                <div className="mt-4 text-center">
                  <span className="text-sm text-ink-soft">Average Confidence: </span>
                  <span className="text-lg font-bold text-red-600">{avgConfidence}%</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Achievement Badges or Warning */}
        {isSecure ? (
          <div className="mb-12 flex flex-wrap justify-center gap-3">
            <div className="px-4 py-2 rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500 text-white text-sm font-semibold shadow-md">
              ✅ OWASP LLM Top 10 Compliant
            </div>
            <div className="px-4 py-2 rounded-full bg-gradient-to-r from-blue-500 to-indigo-500 text-white text-sm font-semibold shadow-md">
              ✅ EU AI Act Ready
            </div>
            <div className="px-4 py-2 rounded-full bg-gradient-to-r from-purple-500 to-pink-500 text-white text-sm font-semibold shadow-md">
              ✅ NIST AI RMF Aligned
            </div>
          </div>
        ) : (
          <div className="mb-12 p-6 rounded-xl bg-red-50 border-2 border-red-300">
            <div className="flex items-start space-x-3">
              <span className="text-3xl">🚨</span>
              <div className="text-left flex-1">
                <div className="font-bold text-red-700 text-lg mb-2">Immediate Action Required</div>
                <div className="text-sm text-red-600">
                  Your chatbot has {criticalCount + highCount} critical/high severity vulnerabilities that could be exploited. 
                  Review the detailed findings below and apply the recommended fixes immediately.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <a
            href={`http://localhost:8001/api/v1/reports/scans/${scanId}/pdf`}
            download
            className={`px-8 py-4 rounded-lg font-semibold shadow-lg transition transform hover:scale-105 text-center ${
              isSecure
                ? 'bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-600 hover:to-cyan-600 text-white'
                : 'bg-gradient-to-r from-red-500 to-orange-500 hover:from-red-600 hover:to-orange-600 text-white'
            }`}
          >
            📊 Download {isSecure ? 'Security' : 'Vulnerability'} Report (PDF)
          </a>
          <button
            onClick={() => navigate(`/dashboard/findings?target_id=${targetId}&scan_id=${scanId}`)}
            className={`px-8 py-4 rounded-lg font-semibold border-2 bg-white transition transform hover:scale-105 ${
              isSecure
                ? 'border-emerald-500 hover:border-emerald-600 text-emerald-600 hover:text-emerald-700'
                : 'border-red-500 hover:border-red-600 text-red-600 hover:text-red-700'
            }`}
          >
            {isSecure ? '📋 View Audit Trail' : '🔍 View Detailed Findings & Fixes'}
          </button>
          <button
            onClick={() => navigate('/dashboard/home')}
            className={`px-8 py-4 rounded-lg font-semibold border-2 bg-white transition transform hover:scale-105 ${
              isSecure
                ? 'border-emerald-500 hover:border-emerald-600 text-emerald-600 hover:text-emerald-700'
                : 'border-red-500 hover:border-red-600 text-red-600 hover:text-red-700'
            }`}
          >
            🏠 Back to Dashboard
          </button>
        </div>

        {/* Continuous Monitoring Note */}
        <div className={`mt-12 p-6 rounded-xl border ${
          isSecure 
            ? 'bg-cyan-50 border-cyan-200' 
            : 'bg-orange-50 border-orange-200'
        }`}>
          <div className="flex items-start space-x-3">
            <span className="text-2xl">🔄</span>
            <div className="text-left">
              <div className="font-semibold text-ink mb-1">
                {isSecure ? 'Continuous Monitoring Active' : 'Fix & Retest'}
              </div>
              <div className="text-sm text-ink-soft">
                {isSecure 
                  ? "We'll automatically retest your chatbot every 5 minutes and alert you immediately if any vulnerabilities are detected."
                  : "Apply the recommended fixes from the detailed findings page, then click 'Retest' to verify your improvements. We'll monitor your chatbot continuously after it's secured."
                }
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
