import { useState } from 'react';
import { FileText, Download, Calendar, Filter } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';

const Reports = () => {
  const [reports, setReports] = useState([
    {
      id: 1,
      title: 'Full Security Scan - example.com',
      date: '2024-11-20',
      type: 'Full Scan',
      findings: 23,
      domains: 1,
      status: 'completed',
      format: 'PDF',
    },
    {
      id: 2,
      title: 'Weekly Summary Report',
      date: '2024-11-18',
      type: 'Summary',
      findings: 45,
      domains: 3,
      status: 'completed',
      format: 'HTML',
    },
    {
      id: 3,
      title: 'Monthly Compliance Report',
      date: '2024-11-01',
      type: 'Compliance',
      findings: 67,
      domains: 5,
      status: 'completed',
      format: 'PDF',
    },
  ]);

  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [newReport, setNewReport] = useState({
    title: '',
    type: 'Full Scan',
    format: 'PDF',
  });

  const handleDownload = (reportId, format) => {
    // Simulate download with actual file creation
    const report = reports.find(r => r.id === reportId);
    if (report) {
      const blob = new Blob([`Report: ${report.title}\nFindings: ${report.findings}\nDate: ${report.date}`], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${report.title.replace(/\s+/g, '_')}.${format.toLowerCase()}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    }
  };

  const handleGenerateReport = () => {
    setShowGenerateModal(true);
  };

  const handleSubmitReport = (e) => {
    e.preventDefault();
    const newReportItem = {
      id: reports.length + 1,
      title: newReport.title,
      date: new Date().toISOString().split('T')[0],
      type: newReport.type,
      findings: Math.floor(Math.random() * 50),
      domains: Math.floor(Math.random() * 5) + 1,
      status: 'completed',
      format: newReport.format,
    };
    setReports([newReportItem, ...reports]);
    setShowGenerateModal(false);
    setNewReport({ title: '', type: 'Full Scan', format: 'PDF' });
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Reports</h2>
          <p className="mt-1 text-sm text-gray-500">
            Generate and download security reports
          </p>
        </div>
        <Button onClick={handleGenerateReport}>
          <FileText className="h-4 w-4 mr-2 inline" />
          Generate Report
        </Button>
      </div>

      {/* Report Types */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card 
          className="cursor-pointer hover:shadow-md transition-shadow"
          onClick={() => {
            setNewReport({ ...newReport, type: 'Full Scan', title: 'Full Security Scan' });
            setShowGenerateModal(true);
          }}
        >
          <CardContent className="text-center py-6">
            <FileText className="h-12 w-12 text-blue-600 mx-auto mb-3" />
            <h3 className="text-lg font-semibold text-gray-900 mb-2">
              Full Scan Report
            </h3>
            <p className="text-sm text-gray-500">
              Comprehensive analysis with all findings and evidence
            </p>
          </CardContent>
        </Card>

        <Card 
          className="cursor-pointer hover:shadow-md transition-shadow"
          onClick={() => {
            setNewReport({ ...newReport, type: 'Summary', title: 'Summary Report' });
            setShowGenerateModal(true);
          }}
        >
          <CardContent className="text-center py-6">
            <Calendar className="h-12 w-12 text-green-600 mx-auto mb-3" />
            <h3 className="text-lg font-semibold text-gray-900 mb-2">
              Summary Report
            </h3>
            <p className="text-sm text-gray-500">
              Executive summary with key metrics and trends
            </p>
          </CardContent>
        </Card>

        <Card 
          className="cursor-pointer hover:shadow-md transition-shadow"
          onClick={() => {
            setNewReport({ ...newReport, type: 'Custom', title: 'Custom Report' });
            setShowGenerateModal(true);
          }}
        >
          <CardContent className="text-center py-6">
            <Filter className="h-12 w-12 text-purple-600 mx-auto mb-3" />
            <h3 className="text-lg font-semibold text-gray-900 mb-2">
              Custom Report
            </h3>
            <p className="text-sm text-gray-500">
              Build a custom report with selected data
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Previous Reports */}
      <Card>
        <CardHeader>
          <CardTitle>Previous Reports</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Report
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Date
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Findings
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Domains
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {reports.map((report) => (
                  <tr key={report.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        <FileText className="h-5 w-5 text-gray-400 mr-3" />
                        <div>
                          <div className="text-sm font-medium text-gray-900">
                            {report.title}
                          </div>
                          <div className="text-xs text-gray-500">
                            {report.format} format
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {report.date}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <Badge variant="default">{report.type}</Badge>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`text-sm font-medium ${
                        report.findings > 0 ? 'text-red-600' : 'text-green-600'
                      }`}>
                        {report.findings}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {report.domains}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <Badge variant="success">{report.status}</Badge>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleDownload(report.id, report.format)}
                      >
                        <Download className="h-4 w-4 mr-1 inline" />
                        Download
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Report Template Info */}
      <Card>
        <CardHeader>
          <CardTitle>Report Includes</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="text-sm font-semibold text-gray-900 mb-2">
                Executive Summary
              </h4>
              <ul className="text-sm text-gray-600 space-y-1 list-disc list-inside">
                <li>Overall security posture</li>
                <li>Key metrics and statistics</li>
                <li>Severity distribution</li>
                <li>Trending analysis</li>
              </ul>
            </div>
            <div>
              <h4 className="text-sm font-semibold text-gray-900 mb-2">
                Detailed Findings
              </h4>
              <ul className="text-sm text-gray-600 space-y-1 list-disc list-inside">
                <li>Vulnerable subdomain listings</li>
                <li>DNS and HTTP evidence</li>
                <li>Provider-specific patterns</li>
                <li>Remediation recommendations</li>
              </ul>
            </div>
            <div>
              <h4 className="text-sm font-semibold text-gray-900 mb-2">
                Technical Details
              </h4>
              <ul className="text-sm text-gray-600 space-y-1 list-disc list-inside">
                <li>CNAME records analysis</li>
                <li>Provider fingerprint matches</li>
                <li>Confidence scoring details</li>
                <li>Scan methodology</li>
              </ul>
            </div>
            <div>
              <h4 className="text-sm font-semibold text-gray-900 mb-2">
                Compliance & Best Practices
              </h4>
              <ul className="text-sm text-gray-600 space-y-1 list-disc list-inside">
                <li>Security recommendations</li>
                <li>Industry best practices</li>
                <li>Prevention guidelines</li>
                <li>Monitoring suggestions</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Generate Report Modal */}
      {showGenerateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg max-w-md w-full p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Generate New Report
            </h3>
            <form onSubmit={handleSubmitReport}>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Report Title
                  </label>
                  <input
                    type="text"
                    value={newReport.title}
                    onChange={(e) => setNewReport({ ...newReport, title: e.target.value })}
                    placeholder="e.g., Security Scan - domain.com"
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Report Type
                  </label>
                  <select
                    value={newReport.type}
                    onChange={(e) => setNewReport({ ...newReport, type: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    <option value="Full Scan">Full Scan</option>
                    <option value="Summary">Summary</option>
                    <option value="Compliance">Compliance</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Format
                  </label>
                  <select
                    value={newReport.format}
                    onChange={(e) => setNewReport({ ...newReport, format: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    <option value="PDF">PDF</option>
                    <option value="HTML">HTML</option>
                    <option value="JSON">JSON</option>
                    <option value="CSV">CSV</option>
                  </select>
                </div>
              </div>
              <div className="flex justify-end space-x-3 mt-6">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setShowGenerateModal(false);
                    setNewReport({ title: '', type: 'Full Scan', format: 'PDF' });
                  }}
                >
                  Cancel
                </Button>
                <Button type="submit">
                  Generate Report
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Reports;
