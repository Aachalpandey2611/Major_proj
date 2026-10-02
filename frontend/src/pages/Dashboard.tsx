import { useEffect, useState } from 'react';
import { api, Target, Scan, Finding } from '../api';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f59e0b',
  medium: '#fbbf24',
  low: '#60a5fa',
};

export default function Dashboard() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const targetsData = await api.getTargets();
      setTargets(targetsData);

      // Fetch scans for all targets
      const allScans: Scan[] = [];
      const allFindings: Finding[] = [];

      for (const target of targetsData) {
        try {
          // TODO: Add getScans endpoint to fetch multiple scans
          // const targetScans = await api.getScans(target.id);
          // allScans.push(...targetScans);

          // Fetch findings for each target
          const targetFindings = await api.getFindings(target.id);
          allFindings.push(...targetFindings);
        } catch (err) {
          console.error(`Failed to fetch data for target ${target.id}`, err);
        }
      }

      setScans(allScans);
      setFindings(allFindings);
    } catch (err) {
      console.error('Failed to fetch dashboard data', err);
    } finally {
      setLoading(false);
    }
  };

  // Calculate statistics
  const scansThisMonth = scans.filter((scan) => {
    const scanDate = new Date(scan.created_at);
    const now = new Date();
    return (
      scanDate.getMonth() === now.getMonth() &&
      scanDate.getFullYear() === now.getFullYear()
    );
  }).length;

  const findingsBySeverity = {
    critical: findings.filter((f) => f.severity === 'critical' && f.status === 'open').length,
    high: findings.filter((f) => f.severity === 'high' && f.status === 'open').length,
    medium: findings.filter((f) => f.severity === 'medium' && f.status === 'open').length,
    low: findings.filter((f) => f.severity === 'low' && f.status === 'open').length,
  };

  // Calculate average confidence score across all vulnerabilities
  const openFindings = findings.filter((f) => f.status === 'open');
  const avgConfidenceScore = openFindings.length > 0
    ? Math.round((openFindings.reduce((sum, f) => sum + (f.confidence || 0), 0) / openFindings.length) * 100)
    : 0;

  // Calculate overall security posture (0-100, higher is better)
  const totalPossibleVulnerabilities = targets.length * 15; // 15 attack types per target
  const actualVulnerabilities = openFindings.length;
  const overallSecurityScore = totalPossibleVulnerabilities > 0
    ? Math.round((1 - (actualVulnerabilities / totalPossibleVulnerabilities)) * 100)
    : 100;

  const severityChartData = [
    { name: 'Critical', value: findingsBySeverity.critical, color: SEVERITY_COLORS.critical },
    { name: 'High', value: findingsBySeverity.high, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: findingsBySeverity.medium, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: findingsBySeverity.low, color: SEVERITY_COLORS.low },
  ].filter((item) => item.value > 0);

  // Confidence score distribution
  const confidenceRanges = {
    'High (80-100%)': openFindings.filter((f) => (f.confidence || 0) >= 0.8).length,
    'Medium (60-79%)': openFindings.filter((f) => (f.confidence || 0) >= 0.6 && (f.confidence || 0) < 0.8).length,
    'Low (40-59%)': openFindings.filter((f) => (f.confidence || 0) >= 0.4 && (f.confidence || 0) < 0.6).length,
    'Very Low (<40%)': openFindings.filter((f) => (f.confidence || 0) < 0.4).length,
  };

  const confidenceChartData = [
    { name: 'High (80-100%)', value: confidenceRanges['High (80-100%)'], color: '#ef4444' },
    { name: 'Medium (60-79%)', value: confidenceRanges['Medium (60-79%)'], color: '#f59e0b' },
    { name: 'Low (40-59%)', value: confidenceRanges['Low (40-59%)'], color: '#fbbf24' },
    { name: 'Very Low (<40%)', value: confidenceRanges['Very Low (<40%)'], color: '#60a5fa' },
  ].filter((item) => item.value > 0);

  // Attack types bar chart
  const attackTypeCounts: Record<string, number> = {};
  findings.forEach((finding) => {
    const attackType = finding.attack_type.replace(/_/g, ' ');
    attackTypeCounts[attackType] = (attackTypeCounts[attackType] || 0) + 1;
  });

  const attackTypeChartData = Object.entries(attackTypeCounts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // Security score per target (0-100)
  const targetScores = targets.map((target) => {
    const targetFindings = findings.filter((f) => f.target_id === target.id && f.status === 'open');
    const criticalCount = targetFindings.filter((f) => f.severity === 'critical').length;
    const highCount = targetFindings.filter((f) => f.severity === 'high').length;
    const mediumCount = targetFindings.filter((f) => f.severity === 'medium').length;
    const lowCount = targetFindings.filter((f) => f.severity === 'low').length;

    // Calculate score: start at 100, deduct points for vulnerabilities
    let score = 100;
    score -= criticalCount * 25; // -25 per critical
    score -= highCount * 15; // -15 per high
    score -= mediumCount * 5; // -5 per medium
    score -= lowCount * 2; // -2 per low
    score = Math.max(0, score); // Floor at 0

    return {
      name: target.name,
      score,
      findings: targetFindings.length,
    };
  });

  // Detection rate over time (last 7 days)
  const last7Days = Array.from({ length: 7 }, (_, i) => {
    const date = new Date();
    date.setDate(date.getDate() - (6 - i));
    return date.toISOString().split('T')[0];
  });

  const detectionRateData = last7Days.map((date) => {
    const dateScans = scans.filter((scan) => scan.created_at.startsWith(date));
    const dateFindings = dateScans.flatMap((scan) =>
      findings.filter((f) => f.scan_id === scan.id)
    );
    const detectionRate =
      dateScans.length > 0 ? (dateFindings.length / (dateScans.length * 15)) * 100 : 0;

    return {
      date: new Date(date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      rate: Math.round(detectionRate),
      scans: dateScans.length,
    };
  });

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="text-center py-20 text-ink-soft">Loading dashboard analytics...</div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="mb-10">
        <h1 className="text-4xl font-extrabold tracking-tight bg-gradient-to-r from-accent-indigo via-accent-purple to-accent-pink bg-clip-text text-transparent">
          Security Dashboard
        </h1>
        <p className="text-ink-soft mt-2">Overview of your security posture and testing activity</p>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-6 mb-8">
        <div className="p-6 rounded-2xl bg-white border border-border shadow-sm">
          <div className="text-sm text-ink-soft mb-1">Targets Monitored</div>
          <div className="text-3xl font-bold text-ink">{targets.length}</div>
        </div>
        <div className="p-6 rounded-2xl bg-white border border-border shadow-sm">
          <div className="text-sm text-ink-soft mb-1">Overall Security</div>
          <div className={`text-3xl font-bold ${
            overallSecurityScore >= 80 ? 'text-emerald-600' : 
            overallSecurityScore >= 60 ? 'text-amber-600' : 'text-red-600'
          }`}>
            {overallSecurityScore}%
          </div>
        </div>
        <div className="p-6 rounded-2xl bg-white border border-border shadow-sm">
          <div className="text-sm text-ink-soft mb-1">Avg Confidence</div>
          <div className="text-3xl font-bold text-accent-purple">{avgConfidenceScore}%</div>
          <div className="text-xs text-ink-soft mt-1">of vulnerabilities</div>
        </div>
        <div className="p-6 rounded-2xl bg-white border border-border shadow-sm">
          <div className="text-sm text-ink-soft mb-1">Open Vulnerabilities</div>
          <div className="text-3xl font-bold text-red-600">
            {openFindings.length}
          </div>
        </div>
        <div className="p-6 rounded-2xl bg-white border border-border shadow-sm">
          <div className="text-sm text-ink-soft mb-1">Total Scans</div>
          <div className="text-3xl font-bold text-ink">{scansThisMonth}</div>
          <div className="text-xs text-ink-soft mt-1">this month</div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Findings by Severity (Pie Chart) */}
        <div className="p-6 rounded-2xl bg-white border border-border shadow-sm">
          <h2 className="text-xl font-bold mb-6 text-ink">Findings by Severity</h2>
          {severityChartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={severityChartData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, value }) => `${name}: ${value}`}
                  outerRadius={100}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {severityChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[300px] flex items-center justify-center text-ink-soft">
              No findings to display
            </div>
          )}
        </div>

        {/* Confidence Score Distribution */}
        <div className="p-6 rounded-2xl bg-white border border-border shadow-sm">
          <h2 className="text-xl font-bold mb-6 text-ink">Confidence Distribution</h2>
          {confidenceChartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={confidenceChartData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, value }) => `${value}`}
                  outerRadius={100}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {confidenceChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[300px] flex items-center justify-center text-ink-soft">
              No confidence data
            </div>
          )}
        </div>

        {/* Detection Rate Over Time (Line Chart) */}
        <div className="p-6 rounded-2xl bg-white border border-border shadow-sm">
          <h2 className="text-xl font-bold mb-6 text-ink">Detection Rate (7 Days)</h2>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={detectionRateData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line
                type="monotone"
                dataKey="rate"
                stroke="#6366f1"
                strokeWidth={2}
                name="Detection Rate %"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Most Common Attack Types (Bar Chart) */}
      <div className="p-6 rounded-2xl bg-white border border-border shadow-sm mb-8">
        <h2 className="text-xl font-bold mb-6 text-ink">Most Common Attack Types</h2>
        {attackTypeChartData.length > 0 ? (
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={attackTypeChartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="count" fill="#6366f1" name="Vulnerabilities Found" />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="h-[300px] flex items-center justify-center text-ink-soft">
            No attack data to display
          </div>
        )}
      </div>

      {/* Security Score per Target */}
      <div className="p-6 rounded-2xl bg-white border border-border shadow-sm">
        <h2 className="text-xl font-bold mb-6 text-ink">Security Score per Target</h2>
        <div className="space-y-4">
          {targetScores.map((target) => (
            <div key={target.name} className="flex items-center justify-between">
              <div className="flex-1">
                <div className="text-sm font-semibold text-ink mb-1">{target.name}</div>
                <div className="w-full bg-canvas rounded-full h-3 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${
                      target.score >= 80
                        ? 'bg-emerald-500'
                        : target.score >= 60
                        ? 'bg-amber-500'
                        : 'bg-red-500'
                    }`}
                    style={{ width: `${target.score}%` }}
                  />
                </div>
              </div>
              <div className="ml-6 text-right">
                <div className="text-2xl font-bold text-ink">{target.score}</div>
                <div className="text-xs text-ink-soft">{target.findings} findings</div>
              </div>
            </div>
          ))}
          {targetScores.length === 0 && (
            <div className="text-center py-10 text-ink-soft">No targets to display</div>
          )}
        </div>
      </div>
    </div>
  );
}
