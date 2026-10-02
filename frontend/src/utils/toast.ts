/**
 * toast.ts — Toast notification utilities
 * 
 * Provides consistent toast notifications across the app for:
 * - Scan events (started, completed, failed)
 * - Vulnerability discoveries
 * - Deployment detection
 * - Security milestones
 */

import toast from 'react-hot-toast';

export const showToast = {
  // Scan events
  scanStarted: (targetName: string) => {
    toast.loading(`🔄 Starting security scan on ${targetName}...`, {
      id: 'scan-started',
      duration: 3000,
    });
  },

  scanComplete: (findingsCount: number, targetName: string) => {
    if (findingsCount === 0) {
      toast.success(`✅ Scan complete — ${targetName} is secure! No vulnerabilities found.`, {
        id: 'scan-complete',
        duration: 5000,
        icon: '🛡️',
      });
    } else {
      toast.success(`✅ Scan complete — ${findingsCount} finding${findingsCount > 1 ? 's' : ''} detected`, {
        id: 'scan-complete',
        duration: 5000,
      });
    }
  },

  scanFailed: (reason?: string) => {
    toast.error(`❌ Scan failed${reason ? ': ' + reason : ''}`, {
      id: 'scan-failed',
      duration: 6000,
    });
  },

  // Vulnerability discoveries
  criticalFound: (attackType: string) => {
    toast.error(`🚨 CRITICAL: ${attackType.replace(/_/g, ' ')} vulnerability found!`, {
      duration: 8000,
      icon: '🔴',
      style: {
        background: '#fee',
        color: '#b91c1c',
        border: '2px solid #ef4444',
        fontWeight: 'bold',
      },
    });
  },

  highFound: (attackType: string) => {
    toast.error(`⚠️ HIGH RISK: ${attackType.replace(/_/g, ' ')} vulnerability detected`, {
      duration: 6000,
      icon: '🟠',
      style: {
        background: '#fef3c7',
        color: '#92400e',
        border: '2px solid #f59e0b',
      },
    });
  },

  // Deployment & retest events
  deploymentDetected: (targetName: string) => {
    toast.loading(`🔄 Deployment detected — retesting ${targetName}...`, {
      id: 'deployment-detected',
      duration: 4000,
      icon: '🚀',
      style: {
        background: '#dbeafe',
        color: '#1e40af',
        border: '2px solid #3b82f6',
      },
    });
  },

  retestStarted: (targetName: string) => {
    toast.loading(`🔄 Retesting open vulnerabilities on ${targetName}...`, {
      id: 'retest-started',
      duration: 3000,
    });
  },

  retestComplete: (resolvedCount: number, totalCount: number) => {
    if (resolvedCount === totalCount) {
      toast.success(`🛡️ All ${totalCount} vulnerabilities resolved!`, {
        id: 'retest-complete',
        duration: 6000,
        icon: '✅',
        style: {
          background: '#d1fae5',
          color: '#065f46',
          border: '2px solid #10b981',
          fontWeight: 'bold',
        },
      });
    } else {
      toast.success(`🔄 Retest complete: ${resolvedCount}/${totalCount} vulnerabilities resolved`, {
        id: 'retest-complete',
        duration: 5000,
      });
    }
  },

  // Security milestones
  fullySecured: (targetName: string) => {
    toast.success(`🛡️ ${targetName} is now fully secured against all known vulnerabilities!`, {
      duration: 8000,
      icon: '🎉',
      style: {
        background: '#d1fae5',
        color: '#065f46',
        border: '2px solid #10b981',
        fontWeight: 'bold',
        fontSize: '15px',
      },
    });
  },

  // Target management
  targetRegistered: (targetName: string) => {
    toast.success(`✅ ${targetName} registered successfully`, {
      duration: 4000,
    });
  },

  targetVerified: (targetName: string) => {
    toast.success(`✅ ${targetName} ownership verified`, {
      duration: 4000,
      icon: '🔐',
    });
  },

  // API key management
  apiKeyCreated: () => {
    toast.success(`🔑 API key created — save it now! It won't be shown again.`, {
      duration: 8000,
      icon: '⚠️',
      style: {
        background: '#fef3c7',
        color: '#92400e',
        border: '2px solid #f59e0b',
        fontWeight: 'bold',
      },
    });
  },

  // Generic
  success: (message: string) => {
    toast.success(message, { duration: 4000 });
  },

  error: (message: string) => {
    toast.error(message, { duration: 5000 });
  },

  loading: (message: string) => {
    return toast.loading(message);
  },

  dismiss: (toastId?: string) => {
    toast.dismiss(toastId);
  },
};

// Export the base toast for custom use cases
export { toast };
