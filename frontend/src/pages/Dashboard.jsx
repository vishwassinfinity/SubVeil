import { useState, useEffect } from 'react';
import { AlertTriangle, Shield, Search, Clock, TrendingUp, TrendingDown, Activity, CheckCircle } from 'lucide-react';
import StatCard from '../components/StatCard';
import { Card, CardHeader, CardTitle, CardContent } from '../components/Card';
import Badge from '../components/Badge';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line, AreaChart, Area } from 'recharts';
import { api } from '../utils/api';

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalSubdomains: 0,
    vulnerableSubdomains: 0,
    activeScans: 0,
    lastScanTime: '-',
    resolvedThisWeek: 0,
    avgResolutionTime: '-',
    scansConducted: 0,
    riskScore: 0,
  });

  const [recentFindings, setRecentFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [statsResponse, findingsResponse] = await Promise.all([
        api.getStats(),
        api.getFindings({ limit: 3 })
      ]);

      const apiStats = statsResponse.data;
      setStats({
        totalSubdomains: apiStats.totalSubdomains || 0,
        vulnerableSubdomains: apiStats.totalFindings || 0,
        activeScans: apiStats.activeScans || 0,
        lastScanTime: apiStats.lastScanTime || '-',
        resolvedThisWeek: apiStats.resolvedThisWeek || 0,
        avgResolutionTime: apiStats.avgResolutionTime || '-',
        scansConducted: apiStats.totalScans || 0,
        riskScore: apiStats.riskScore || 0,
      });

      setRecentFindings(findingsResponse.data.slice(0, 3));
      setLoading(false);
      setError(null);
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
      setError('Failed to load dashboard data');
      setLoading(false);
    }
  };

  const severityData = [
    { name: 'Critical', value: 5, color: '#DC2626' },
    { name: 'High', value: 8, color: '#EA580C' },
    { name: 'Medium', value: 7, color: '#F59E0B' },
    { name: 'Low', value: 3, color: '#3B82F6' },
  ];

  const providerData = [
    { provider: 'GitHub Pages', count: 8 },
    { provider: 'AWS S3', count: 6 },
    { provider: 'Heroku', count: 4 },
    { provider: 'Azure', count: 3 },
    { provider: 'Vercel', count: 2 },
  ];

  const trendData = [
    { date: 'Nov 14', vulnerabilities: 32, scans: 8, resolved: 5 },
    { date: 'Nov 15', vulnerabilities: 28, scans: 12, resolved: 8 },
    { date: 'Nov 16', vulnerabilities: 30, scans: 10, resolved: 6 },
    { date: 'Nov 17', vulnerabilities: 25, scans: 15, resolved: 10 },
    { date: 'Nov 18', vulnerabilities: 27, scans: 11, resolved: 7 },
    { date: 'Nov 19', vulnerabilities: 24, scans: 14, resolved: 9 },
    { date: 'Nov 20', vulnerabilities: 23, scans: 16, resolved: 11 },
  ];

  const riskTrendData = [
    { month: 'Jun', score: 85 },
    { month: 'Jul', score: 82 },
    { month: 'Aug', score: 78 },
    { month: 'Sep', score: 75 },
    { month: 'Oct', score: 74 },
    { month: 'Nov', score: 72 },
  ];

  const domainActivityData = [
    { domain: 'example.com', subdomains: 847, vulnerable: 15 },
    { domain: 'testsite.org', subdomains: 234, vulnerable: 5 },
    { domain: 'myapp.io', subdomains: 166, vulnerable: 3 },
  ];

  const getSeverityBadge = (severity) => {
    return <Badge variant={severity}>{severity.toUpperCase()}</Badge>;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <AlertTriangle className="h-12 w-12 text-red-600 mx-auto mb-4" />
          <p className="text-gray-900 font-semibold">{error}</p>
          <button 
            onClick={fetchDashboardData}
            className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Dashboard</h2>
        <p className="mt-1 text-sm text-gray-500">
          Overview of your subdomain security posture
        </p>
      </div>

      {/* Stats Grid - 3x3 Layout with Domain Activity on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Left Side: 3x3 Stats Grid */}
        <div className="lg:col-span-3 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <StatCard
            title="Total Subdomains"
            value={stats.totalSubdomains.toLocaleString()}
            icon={Shield}
            color="blue"
            trend="+12% from last scan"
          />
          <StatCard
            title="Vulnerable"
            value={stats.vulnerableSubdomains}
            icon={AlertTriangle}
            color="red"
            trend="Requires attention"
          />
          <StatCard
            title="Active Scans"
            value={stats.activeScans}
            icon={Search}
            color="orange"
            trend="Running now"
          />
          <StatCard
            title="Last Scan"
            value={stats.lastScanTime}
            icon={Clock}
            color="green"
          />
          <StatCard
            title="Resolved This Week"
            value={stats.resolvedThisWeek}
            icon={CheckCircle}
            color="green"
            trend="+5 from last week"
          />
          <StatCard
            title="Avg Resolution Time"
            value={stats.avgResolutionTime}
            icon={Activity}
            color="blue"
            trend="-0.8 days improvement"
          />
          <StatCard
            title="Scans Conducted"
            value={stats.scansConducted}
            icon={TrendingUp}
            color="purple"
            trend="Last 30 days"
          />
          <StatCard
            title="Risk Score"
            value={stats.riskScore}
            icon={TrendingDown}
            color="orange"
            trend="↓ 3 points (Good)"
          />
        </div>

        {/* Right Side: Domain Activity */}
        <Card className="lg:col-span-2 lg:row-span-3">
          <CardHeader>
            <CardTitle>Domain Activity Overview</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {domainActivityData.map((domain, index) => (
                <div key={index} className="border-b border-gray-200 pb-4 last:border-0">
                  <div className="flex justify-between items-center mb-2">
                    <span className="font-medium text-gray-900">{domain.domain}</span>
                    <Badge variant={domain.vulnerable > 10 ? 'critical' : domain.vulnerable > 5 ? 'high' : 'medium'}>
                      {domain.vulnerable} vulnerable
                    </Badge>
                  </div>
                  <div className="flex items-center space-x-4 text-sm text-gray-600">
                    <div className="flex items-center">
                      <Shield className="h-4 w-4 mr-1 text-blue-600" />
                      {domain.subdomains} subdomains
                    </div>
                    <div className="flex-1 bg-gray-200 rounded-full h-2">
                      <div 
                        className="bg-red-600 h-2 rounded-full" 
                        style={{ width: `${(domain.vulnerable / domain.subdomains) * 100}%` }}
                      ></div>
                    </div>
                    <span className="text-xs font-medium">
                      {((domain.vulnerable / domain.subdomains) * 100).toFixed(1)}% at risk
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <Card>
          <CardHeader>
            <CardTitle>Severity Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Vulnerabilities by Provider */}
        <Card>
          <CardHeader>
            <CardTitle>Vulnerabilities by Provider</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={providerData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="provider" angle={-45} textAnchor="end" height={100} />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#3B82F6" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Risk Score Trend */}
        <Card>
          <CardHeader>
            <CardTitle>6-Month Risk Score Trend</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={riskTrendData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="month" />
                <YAxis domain={[0, 100]} />
                <Tooltip />
                <Area type="monotone" dataKey="score" stroke="#EA580C" fill="#FED7AA" name="Risk Score" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Trend Analysis - Full Width */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 7-Day Trend */}
        <Card>
          <CardHeader>
            <CardTitle>7-Day Vulnerability Trend</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="vulnerabilities" stroke="#DC2626" strokeWidth={2} name="Vulnerabilities" />
                <Line type="monotone" dataKey="scans" stroke="#3B82F6" strokeWidth={2} name="Scans" />
                <Line type="monotone" dataKey="resolved" stroke="#16A34A" strokeWidth={2} name="Resolved" />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Recent Findings */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Recent Findings</CardTitle>
            <a href="/findings" className="text-sm text-blue-600 hover:text-blue-700">
              View all →
            </a>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Subdomain
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Provider
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Severity
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Discovered
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {recentFindings.map((finding) => (
                    <tr key={finding.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm font-medium text-gray-900">
                          {finding.subdomain}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm text-gray-500">{finding.provider}</div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {getSeverityBadge(finding.severity)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {finding.discovered}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Dashboard;
