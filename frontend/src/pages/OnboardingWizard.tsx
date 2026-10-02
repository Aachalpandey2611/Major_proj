import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  CheckCircle, 
  Globe, 
  Shield, 
  Search, 
  Rocket,
  ChevronRight,
  ChevronLeft,
  Loader2,
  Copy,
  Check,
  AlertCircle
} from 'lucide-react';
import { client } from '../api';
import { showToast } from '../utils/toast';

interface OnboardingWizardProps {
  onComplete: () => void;
}

const STEPS = [
  { id: 1, title: 'Register Chatbot', icon: Globe },
  { id: 2, title: 'Verify Ownership', icon: Shield },
  { id: 3, title: 'Start First Scan', icon: Search },
  { id: 4, title: 'View Results', icon: CheckCircle },
  { id: 5, title: 'All Set!', icon: Rocket }
];

export default function OnboardingWizard({ onComplete }: OnboardingWizardProps) {
  const navigate = useNavigate();
  const [currentStep, setCurrentStep] = useState(1);
  
  // Step 1: Register chatbot
  const [chatbotName, setChatbotName] = useState('');
  const [chatbotUrl, setChatbotUrl] = useState('');
  const [chatbotEnvironment, setChatbotEnvironment] = useState('staging');
  const [registering, setRegistering] = useState(false);
  
  // Step 2: Verify ownership
  const [targetId, setTargetId] = useState('');
  const [verificationToken, setVerificationToken] = useState('');
  const [verificationContent, setVerificationContent] = useState('');
  const [tokenCopied, setTokenCopied] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [autoVerifyAttempts, setAutoVerifyAttempts] = useState(0);
  
  // Step 3: Start scan
  const [scanId, setScanId] = useState('');
  const [scanStarting, setScanStarting] = useState(false);
  
  // Step 4: View results
  const [scanComplete, setScanComplete] = useState(false);
  const [scanStats, setScanStats] = useState({ total: 15, critical: 0, high: 0, medium: 0, low: 0 });

  const handleRegister = async () => {
    if (!chatbotName.trim() || !chatbotUrl.trim()) {
      showToast.error('Please fill in all required fields');
      return;
    }

    // Validate URL format
    try {
      new URL(chatbotUrl);
    } catch {
      showToast.error('Please enter a valid URL (e.g., http://localhost:9000)');
      return;
    }

    setRegistering(true);
    try {
      const response = await client.post('/targets/', null, {
        params: {
          name: chatbotName,
          url: chatbotUrl,
          environment: chatbotEnvironment
        }
      });

      setTargetId(response.data.id);
      setVerificationToken(response.data.verification_token);
      setVerificationContent(response.data.verification_content);
      
      showToast.success(`Chatbot "${chatbotName}" registered successfully!`);
      setCurrentStep(2);
      
      // Start auto-verification attempts
      setTimeout(() => autoVerify(response.data.id, response.data.verification_token), 3000);
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Failed to register chatbot');
    } finally {
      setRegistering(false);
    }
  };

  const autoVerify = async (tid: string, token: string) => {
    if (autoVerifyAttempts >= 5) return; // Max 5 attempts
    
    setAutoVerifyAttempts(prev => prev + 1);
    
    try {
      const response = await client.post(`/targets/${tid}/verify`, null, {
        params: { verification_token: token }
      });
      
      if (response.data.ownership_verified) {
        showToast.success('Ownership verified automatically!');
        setTimeout(() => setCurrentStep(3), 1000);
      } else {
        // Retry after 5 seconds
        setTimeout(() => autoVerify(tid, token), 5000);
      }
    } catch {
      // Retry after 5 seconds
      setTimeout(() => autoVerify(tid, token), 5000);
    }
  };

  const handleManualVerify = async () => {
    setVerifying(true);
    try {
      const response = await client.post(`/targets/${targetId}/verify`, null, {
        params: { verification_token: verificationToken }
      });

      if (response.data.ownership_verified) {
        showToast.success('Ownership verified successfully!');
        setTimeout(() => setCurrentStep(3), 1000);
      } else {
        showToast.error('Verification file not found. Please check the URL.');
      }
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Verification failed');
    } finally {
      setVerifying(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setTokenCopied(true);
    showToast.success('Copied to clipboard!');
    setTimeout(() => setTokenCopied(false), 2000);
  };

  const handleStartScan = async () => {
    setScanStarting(true);
    try {
      const response = await client.post(`/scans/?target_id=${targetId}`);
      setScanId(response.data.id);
      showToast.scanStarted(chatbotName);
      
      // Start polling scan status
      pollScanStatus(response.data.id);
      setCurrentStep(4);
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Failed to start scan');
    } finally {
      setScanStarting(false);
    }
  };

  const pollScanStatus = async (sid: string) => {
    try {
      const response = await client.get(`/scans/${sid}`);
      const scan = response.data;

      if (scan.status === 'completed') {
        setScanComplete(true);
        
        // Count severity levels
        const findings = scan.findings || [];
        const stats = {
          total: findings.length,
          critical: findings.filter((f: any) => f.severity === 'critical').length,
          high: findings.filter((f: any) => f.severity === 'high').length,
          medium: findings.filter((f: any) => f.severity === 'medium').length,
          low: findings.filter((f: any) => f.severity === 'low').length
        };
        setScanStats(stats);

        if (findings.length === 0) {
          showToast.fullySecured(chatbotName);
        } else if (stats.critical > 0) {
          showToast.criticalFound(stats.critical);
        } else if (stats.high > 0) {
          showToast.highFound(stats.high);
        }
        
        setTimeout(() => setCurrentStep(5), 2000);
      } else if (scan.status === 'failed') {
        showToast.scanFailed('Scan failed');
      } else {
        // Keep polling
        setTimeout(() => pollScanStatus(sid), 3000);
      }
    } catch (error) {
      console.error('Failed to poll scan status:', error);
    }
  };

  const handleComplete = () => {
    localStorage.setItem('onboarding_completed', 'true');
    showToast.success('Welcome to SentinelLoop! 🎉');
    onComplete();
    
    // Navigate to findings if scan had results
    if (scanId && scanStats.total > 0) {
      navigate(`/findings/${scanId}`);
    } else if (scanId) {
      navigate(`/fully-secure/${scanId}`);
    } else {
      navigate('/');
    }
  };

  const handleSkip = () => {
    if (window.confirm('Skip onboarding? You can always register a chatbot from the dashboard.')) {
      localStorage.setItem('onboarding_completed', 'true');
      onComplete();
      navigate('/');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-4xl bg-slate-900/50 backdrop-blur-sm border border-slate-700/50 rounded-2xl shadow-2xl overflow-hidden"
      >
        {/* Progress Bar */}
        <div className="bg-slate-900/80 px-8 py-6 border-b border-slate-700/50">
          <div className="flex items-center justify-between mb-6">
            <h1 className="text-2xl font-bold text-white">Getting Started</h1>
            <button
              onClick={handleSkip}
              className="text-sm text-slate-400 hover:text-slate-300 transition-colors"
            >
              Skip for now
            </button>
          </div>
          
          <div className="flex items-center justify-between relative">
            {/* Progress line background */}
            <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-slate-700 -translate-y-1/2" />
            
            {/* Progress line filled */}
            <motion.div
              className="absolute top-1/2 left-0 h-0.5 bg-blue-500 -translate-y-1/2"
              initial={{ width: '0%' }}
              animate={{ width: `${((currentStep - 1) / (STEPS.length - 1)) * 100}%` }}
              transition={{ duration: 0.5 }}
            />
            
            {STEPS.map((step) => {
              const Icon = step.icon;
              const isCompleted = currentStep > step.id;
              const isCurrent = currentStep === step.id;
              
              return (
                <div key={step.id} className="relative z-10 flex flex-col items-center">
                  <motion.div
                    className={`w-12 h-12 rounded-full flex items-center justify-center mb-2 transition-all ${
                      isCompleted
                        ? 'bg-green-500/20 border-2 border-green-500'
                        : isCurrent
                        ? 'bg-blue-500/20 border-2 border-blue-500'
                        : 'bg-slate-800 border-2 border-slate-700'
                    }`}
                    whileHover={{ scale: 1.05 }}
                  >
                    <Icon
                      className={`w-5 h-5 ${
                        isCompleted
                          ? 'text-green-400'
                          : isCurrent
                          ? 'text-blue-400'
                          : 'text-slate-500'
                      }`}
                    />
                  </motion.div>
                  <span
                    className={`text-xs font-medium ${
                      isCompleted || isCurrent ? 'text-white' : 'text-slate-500'
                    }`}
                  >
                    {step.title}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Step Content */}
        <div className="p-8">
          <AnimatePresence mode="wait">
            {/* Step 1: Register Chatbot */}
            {currentStep === 1 && (
              <motion.div
                key="step1"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="space-y-6"
              >
                <div>
                  <h2 className="text-xl font-bold text-white mb-2">Register Your Chatbot</h2>
                  <p className="text-slate-400 text-sm">
                    Let's start by registering the LLM chatbot or API you want to test for vulnerabilities.
                  </p>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Chatbot Name *
                    </label>
                    <input
                      type="text"
                      value={chatbotName}
                      onChange={(e) => setChatbotName(e.target.value)}
                      placeholder="e.g., Customer Support Bot"
                      className="w-full px-4 py-3 bg-slate-800/50 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      API Endpoint URL *
                    </label>
                    <input
                      type="url"
                      value={chatbotUrl}
                      onChange={(e) => setChatbotUrl(e.target.value)}
                      placeholder="http://localhost:9000"
                      className="w-full px-4 py-3 bg-slate-800/50 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <p className="mt-1 text-xs text-slate-500">
                      The URL where your chatbot accepts POST requests with OpenAI-compatible format
                    </p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Environment
                    </label>
                    <select
                      value={chatbotEnvironment}
                      onChange={(e) => setChatbotEnvironment(e.target.value)}
                      className="w-full px-4 py-3 bg-slate-800/50 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="staging">Staging</option>
                      <option value="production">Production</option>
                      <option value="development">Development</option>
                    </select>
                  </div>
                </div>

                <div className="flex justify-end pt-4">
                  <button
                    onClick={handleRegister}
                    disabled={registering}
                    className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {registering ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Registering...
                      </>
                    ) : (
                      <>
                        Next
                        <ChevronRight className="w-4 h-4" />
                      </>
                    )}
                  </button>
                </div>
              </motion.div>
            )}

            {/* Step 2: Verify Ownership */}
            {currentStep === 2 && (
              <motion.div
                key="step2"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="space-y-6"
              >
                <div>
                  <h2 className="text-xl font-bold text-white mb-2">Verify Ownership</h2>
                  <p className="text-slate-400 text-sm">
                    To confirm you control this chatbot, place a verification file at the URL below.
                  </p>
                </div>

                <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                  <div className="flex items-start gap-3">
                    <AlertCircle className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
                    <div className="flex-1 text-sm text-blue-200">
                      <p className="font-medium mb-1">Auto-verification in progress...</p>
                      <p className="text-blue-300/80">
                        We're checking if the verification file is accessible. This may take a few moments.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Place this file:
                    </label>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 px-4 py-3 bg-slate-800 border border-slate-700 rounded-lg text-green-400 font-mono text-sm">
                        {chatbotUrl}/.well-known/sentinelloop-verify.txt
                      </code>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      With this content:
                    </label>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 px-4 py-3 bg-slate-800 border border-slate-700 rounded-lg text-green-400 font-mono text-sm break-all">
                        {verificationContent}
                      </code>
                      <button
                        onClick={() => copyToClipboard(verificationContent)}
                        className="px-4 py-3 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors flex-shrink-0"
                        title="Copy to clipboard"
                      >
                        {tokenCopied ? (
                          <Check className="w-4 h-4 text-green-400" />
                        ) : (
                          <Copy className="w-4 h-4 text-slate-300" />
                        )}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                  <p className="text-sm text-slate-400 mb-2">
                    <strong className="text-slate-300">Example:</strong> If your chatbot is at{' '}
                    <code className="text-green-400">http://localhost:9000</code>, create:
                  </p>
                  <code className="text-xs text-slate-500">
                    http://localhost:9000/.well-known/sentinelloop-verify.txt
                  </code>
                </div>

                <div className="flex justify-between pt-4">
                  <button
                    onClick={() => setCurrentStep(1)}
                    className="px-6 py-3 bg-slate-700 hover:bg-slate-600 text-white rounded-lg font-medium transition-colors flex items-center gap-2"
                  >
                    <ChevronLeft className="w-4 h-4" />
                    Back
                  </button>
                  
                  <button
                    onClick={handleManualVerify}
                    disabled={verifying}
                    className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {verifying ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Verifying...
                      </>
                    ) : (
                      <>
                        Verify Now
                        <ChevronRight className="w-4 h-4" />
                      </>
                    )}
                  </button>
                </div>
              </motion.div>
            )}

            {/* Step 3: Start First Scan */}
            {currentStep === 3 && (
              <motion.div
                key="step3"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="space-y-6"
              >
                <div>
                  <h2 className="text-xl font-bold text-white mb-2">Launch Your First Scan</h2>
                  <p className="text-slate-400 text-sm">
                    Great! Now let's run a comprehensive security scan with 15 different attack types.
                  </p>
                </div>

                <div className="bg-gradient-to-br from-blue-500/10 to-purple-500/10 border border-blue-500/30 rounded-xl p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">What We'll Test:</h3>
                  <div className="grid grid-cols-2 gap-3">
                    {[
                      'Prompt Injection',
                      'Jailbreak Attempts',
                      'Data Leakage',
                      'System Prompt Leak',
                      'Context Manipulation',
                      'Tool Abuse',
                      'SQL Injection',
                      'API Abuse',
                      'RAG Poisoning',
                      'Role Override',
                      'Training Data Extraction',
                      'Few-Shot Leakage',
                      'Indirect Injection',
                      'Denial of Wallet',
                      'Sponge Attacks'
                    ].map((attack) => (
                      <div key={attack} className="flex items-center gap-2 text-sm">
                        <div className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                        <span className="text-slate-300">{attack}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                  <p className="text-sm text-slate-400">
                    ⏱️ The scan typically takes <strong className="text-white">2-3 minutes</strong> to complete.
                    You'll see real-time progress for each attack type.
                  </p>
                </div>

                <div className="flex justify-between pt-4">
                  <button
                    onClick={() => setCurrentStep(2)}
                    className="px-6 py-3 bg-slate-700 hover:bg-slate-600 text-white rounded-lg font-medium transition-colors flex items-center gap-2"
                  >
                    <ChevronLeft className="w-4 h-4" />
                    Back
                  </button>
                  
                  <button
                    onClick={handleStartScan}
                    disabled={scanStarting}
                    className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-lg font-medium transition-all flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-blue-500/20"
                  >
                    {scanStarting ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Starting Scan...
                      </>
                    ) : (
                      <>
                        <Search className="w-4 h-4" />
                        Start Scan
                      </>
                    )}
                  </button>
                </div>
              </motion.div>
            )}

            {/* Step 4: View Results */}
            {currentStep === 4 && (
              <motion.div
                key="step4"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="space-y-6"
              >
                <div>
                  <h2 className="text-xl font-bold text-white mb-2">
                    {scanComplete ? 'Scan Complete!' : 'Scan in Progress...'}
                  </h2>
                  <p className="text-slate-400 text-sm">
                    {scanComplete
                      ? 'Your security scan has finished. Here\'s what we found:'
                      : 'Running 15 attack types against your chatbot. This will take a few minutes...'}
                  </p>
                </div>

                {!scanComplete ? (
                  <div className="flex flex-col items-center justify-center py-12">
                    <div className="relative">
                      <div className="w-20 h-20 border-4 border-slate-700 rounded-full" />
                      <div className="absolute inset-0 w-20 h-20 border-4 border-blue-500 rounded-full animate-spin border-t-transparent" />
                    </div>
                    <p className="mt-6 text-slate-400 animate-pulse">Analyzing security...</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {/* Results Summary */}
                    <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700 rounded-xl p-6">
                      <div className="grid grid-cols-5 gap-4">
                        <div className="text-center">
                          <div className="text-3xl font-bold text-white mb-1">{scanStats.total}</div>
                          <div className="text-xs text-slate-400">Total Findings</div>
                        </div>
                        <div className="text-center">
                          <div className="text-3xl font-bold text-red-400 mb-1">{scanStats.critical}</div>
                          <div className="text-xs text-red-300">Critical</div>
                        </div>
                        <div className="text-center">
                          <div className="text-3xl font-bold text-orange-400 mb-1">{scanStats.high}</div>
                          <div className="text-xs text-orange-300">High</div>
                        </div>
                        <div className="text-center">
                          <div className="text-3xl font-bold text-yellow-400 mb-1">{scanStats.medium}</div>
                          <div className="text-xs text-yellow-300">Medium</div>
                        </div>
                        <div className="text-center">
                          <div className="text-3xl font-bold text-blue-400 mb-1">{scanStats.low}</div>
                          <div className="text-xs text-blue-300">Low</div>
                        </div>
                      </div>
                    </div>

                    {scanStats.total === 0 ? (
                      <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-6 text-center">
                        <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-3" />
                        <h3 className="text-lg font-semibold text-green-300 mb-2">
                          No Vulnerabilities Found! 🎉
                        </h3>
                        <p className="text-sm text-green-400/80">
                          Your chatbot passed all 15 security tests with flying colors.
                        </p>
                      </div>
                    ) : (
                      <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                        <p className="text-sm text-blue-200">
                          <strong className="text-blue-100">What's Next:</strong> Review each finding to see
                          the exact payload used, the chatbot's response, and copy-paste code fixes.
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </motion.div>
            )}

            {/* Step 5: All Set! */}
            {currentStep === 5 && (
              <motion.div
                key="step5"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="space-y-6 text-center py-8"
              >
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: 'spring', delay: 0.2 }}
                  className="inline-block"
                >
                  <div className="w-24 h-24 bg-gradient-to-br from-green-500 to-blue-500 rounded-full flex items-center justify-center mx-auto mb-6">
                    <Rocket className="w-12 h-12 text-white" />
                  </div>
                </motion.div>

                <div>
                  <h2 className="text-3xl font-bold text-white mb-3">You're All Set!</h2>
                  <p className="text-slate-400 text-lg max-w-md mx-auto">
                    Your first scan is complete. You can now explore the findings and secure your chatbot.
                  </p>
                </div>

                <div className="bg-gradient-to-br from-blue-500/10 to-purple-500/10 border border-blue-500/30 rounded-xl p-6 max-w-2xl mx-auto">
                  <h3 className="text-lg font-semibold text-white mb-4">What You Can Do Next:</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-left">
                    <div className="flex gap-3">
                      <div className="w-8 h-8 bg-blue-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                        <span className="text-blue-400 font-bold">1</span>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-white">View Detailed Findings</p>
                        <p className="text-xs text-slate-400 mt-1">
                          See exact payloads, responses, and severity levels
                        </p>
                      </div>
                    </div>
                    <div className="flex gap-3">
                      <div className="w-8 h-8 bg-purple-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                        <span className="text-purple-400 font-bold">2</span>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-white">Apply Code Fixes</p>
                        <p className="text-xs text-slate-400 mt-1">
                          Copy-paste ready patches for each vulnerability
                        </p>
                      </div>
                    </div>
                    <div className="flex gap-3">
                      <div className="w-8 h-8 bg-green-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                        <span className="text-green-400 font-bold">3</span>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-white">Monitor Changes</p>
                        <p className="text-xs text-slate-400 mt-1">
                          Auto-detect deployments and trigger retests
                        </p>
                      </div>
                    </div>
                    <div className="flex gap-3">
                      <div className="w-8 h-8 bg-orange-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                        <span className="text-orange-400 font-bold">4</span>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-white">Generate Reports</p>
                        <p className="text-xs text-slate-400 mt-1">
                          Export PDF reports with compliance mapping
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="pt-6">
                  <button
                    onClick={handleComplete}
                    className="px-8 py-4 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white text-lg rounded-xl font-semibold transition-all shadow-lg shadow-blue-500/30 hover:shadow-blue-500/50"
                  >
                    Go to Dashboard
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </motion.div>
    </div>
  );
}
