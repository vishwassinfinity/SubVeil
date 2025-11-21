import { useState, useEffect } from 'react';
import { AlertTriangle, ExternalLink, ChevronDown, ChevronRight, Filter, Download } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import { api } from '../utils/api';

const Findings = () => {
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchFindings();
  }, []);

  const fetchFindings = async () => {
    try {
      const response = await api.getFindings();
      setFindings(response.data);
      setLoading(false);
      setError(null);
    } catch (err) {
      console.error('Error fetching findings:', err);
      setError('Failed to load findings');
      setLoading(false);
    }
  };

  const filteredFindings = filterSeverity === 'all' 
    ? findings 
    : findings.filter(f => f.severity === filterSeverity);

  const toggleExpand = (id) => {
    setExpandedFinding(expandedFinding === id ? null : id);
  };

  const exportFindings = async () => {
    try {
      const response = await api.exportFindings({ format: 'json' });
      const dataStr = JSON.stringify(response.data, null, 2);
      const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
      const exportFileDefaultName = `findings-${new Date().toISOString().split('T')[0]}.json`;
      
      const linkElement = document.createElement('a');
      linkElement.setAttribute('href', dataUri);
      linkElement.setAttribute('download', exportFileDefaultName);
      linkElement.click();
    } catch (err) {
      console.error('Error exporting findings:', err);
      alert('Failed to export findings');
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleString();
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Vulnerability Findings</h2>
          <p className="mt-1 text-sm text-gray-500">
            Detected subdomain takeover vulnerabilities with evidence
          </p>
        </div>
        <Button onClick={exportFindings} variant="outline">
          <Download className="h-4 w-4 mr-2 inline" />
          Export
        </Button>
      </div>

      {/* Filters */}
      <Card>
        <CardContent>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Filter className="h-5 w-5 text-gray-400" />
              <div className="flex items-center space-x-2">
                <span className="text-sm font-medium text-gray-700">Severity:</span>
                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="all">All</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
            </div>
            <div className="text-sm text-gray-600 font-medium">
              Showing {filteredFindings.length} of {findings.length} findings
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Findings List */}
      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          <span className="ml-3 text-gray-600">Loading findings...</span>
        </div>
      ) : error ? (
        <div className="flex items-center justify-center py-12">
          <AlertTriangle className="h-12 w-12 text-red-600 mx-auto mb-4" />
          <p className="text-red-600">{error}</p>
        </div>
      ) : (
      <div className="space-y-4">
        {filteredFindings.map((finding) => (
          <Card key={finding.id} className="overflow-hidden hover:shadow-lg transition-shadow">
            <div
              className="px-6 py-5 cursor-pointer hover:bg-gray-50 transition-colors"
              onClick={() => toggleExpand(finding.id)}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3">
                    {expandedFinding === finding.id ? (
                      <ChevronDown className="h-5 w-5 text-gray-400" />
                    ) : (
                      <ChevronRight className="h-5 w-5 text-gray-400" />
                    )}
                    <AlertTriangle className="h-5 w-5 text-red-600" />
                    <h3 className="text-lg font-semibold text-gray-900">
                      {finding.subdomain}
                    </h3>
                    <Badge variant={finding.severity}>
                      {finding.severity.toUpperCase()}
                    </Badge>
                    <Badge variant="default">
                      {finding.confidence}% confidence
                    </Badge>
                  </div>
                  <div className="ml-10 mt-2 flex items-center space-x-4 text-sm text-gray-500">
                    <span>Provider: <span className="font-medium">{finding.provider}</span></span>
                    <span>•</span>
                    <span>CNAME: <span className="font-mono">{finding.cnameRecord}</span></span>
                    <span>•</span>
                    <span>Discovered: {formatDate(finding.createdAt)}</span>
                  </div>
                </div>
                <a
                  href={`https://${finding.subdomain}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:text-blue-700"
                  onClick={(e) => e.stopPropagation()}
                >
                  <ExternalLink className="h-5 w-5" />
                </a>
              </div>
            </div>

            {/* Expanded Details */}
            {expandedFinding === finding.id && (
              <div className="border-t border-gray-200 bg-gradient-to-br from-gray-50 to-white px-6 py-5">
                <div className="space-y-6">
                  {/* DNS Evidence */}
                  <div>
                    <h4 className="text-sm font-semibold text-gray-900 mb-3 flex items-center">
                      <span className="w-1 h-4 bg-blue-600 mr-2 rounded"></span>
                      DNS Evidence
                    </h4>
                    <div className="bg-white p-4 rounded-lg border border-gray-200 shadow-sm">
                      <div className="font-mono text-sm space-y-2">
                        <div className="flex items-start">
                          <span className="text-gray-600 min-w-24">CNAME:</span>{' '}
                          <span className="text-blue-600 font-medium">{finding.cnameRecord}</span>
                        </div>
                        <div className="flex items-start">
                          <span className="text-gray-600 min-w-24">A Records:</span>{' '}
                          <span className="text-gray-500">
                            {finding.evidence?.dnsRecords?.aRecords?.length > 0 
                              ? finding.evidence.dnsRecords.aRecords.join(', ') 
                              : 'None'}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* HTTP Response */}
                  <div>
                    <h4 className="text-sm font-semibold text-gray-900 mb-3 flex items-center">
                      <span className="w-1 h-4 bg-orange-600 mr-2 rounded"></span>
                      HTTP Response
                    </h4>
                    <div className="bg-white p-4 rounded-lg border border-gray-200 shadow-sm">
                      <div className="space-y-3 text-sm">
                        <div className="flex items-start">
                          <span className="text-gray-600 min-w-32">Status Code:</span>{' '}
                          <span className="font-semibold text-orange-600">
                            {finding.httpStatusCode || finding.evidence?.httpResponse?.statusCode || 'N/A'}
                          </span>
                        </div>
                        <div className="flex items-start">
                          <span className="text-gray-600 min-w-32">Title:</span>{' '}
                          <span className="text-gray-900 font-medium">
                            {finding.evidence?.httpResponse?.title || 'N/A'}
                          </span>
                        </div>
                        <div className="flex items-start">
                          <span className="text-gray-600 min-w-32">Body:</span>{' '}
                          <span className="text-gray-700 italic">
                            {finding.evidence?.httpResponse?.body || 'N/A'}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Provider Pattern */}
                  <div>
                    <h4 className="text-sm font-semibold text-gray-900 mb-3 flex items-center">
                      <span className="w-1 h-4 bg-purple-600 mr-2 rounded"></span>
                      Matched Pattern
                    </h4>
                    <div className="bg-white p-4 rounded-lg border border-gray-200 shadow-sm">
                      <Badge variant="info">
                        {finding.provider} - {finding.evidence?.providerPattern || 'Takeover Detected'}
                      </Badge>
                    </div>
                  </div>

                  {/* Remediation Steps */}
                  <div>
                    <h4 className="text-sm font-semibold text-gray-900 mb-3 flex items-center">
                      <span className="w-1 h-4 bg-green-600 mr-2 rounded"></span>
                      Remediation Steps
                    </h4>
                    <div className="bg-white p-4 rounded-lg border border-gray-200 shadow-sm">
                      <ol className="list-decimal list-inside space-y-2 text-sm text-gray-700">
                        {(finding.remediation?.steps || [
                          `Remove the CNAME DNS record pointing to ${finding.cnameRecord}`,
                          'Or claim the resource on the provider',
                          'Verify no sensitive data is exposed on this subdomain'
                        ]).map((step, index) => (
                          <li key={index} className="pl-2">{step}</li>
                        ))}
                      </ol>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </Card>
        ))}
      </div>
      )}

      {!loading && !error && filteredFindings.length === 0 && (
        <Card>
          <CardContent className="text-center py-12">
            <AlertTriangle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              No findings match your filters
            </h3>
            <p className="text-sm text-gray-500">
              Try adjusting your filter criteria
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default Findings;
