import { useState } from 'react';
import { AlertTriangle, ExternalLink, ChevronDown, ChevronRight, Filter, Download } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';

const Findings = () => {
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('all');

  const [findings] = useState([
    {
      id: 1,
      subdomain: 'blog.example.com',
      provider: 'GitHub Pages',
      severity: 'critical',
      confidence: 95,
      discovered: '2024-11-20 10:30',
      cname: 'username.github.io',
      evidence: {
        dnsRecords: {
          cname: 'username.github.io',
          aRecords: [],
        },
        httpResponse: {
          statusCode: 404,
          title: 'There isn\'t a GitHub Pages site here.',
          body: 'If you\'re trying to publish one...',
        },
        providerPattern: 'GitHub Pages - Unclaimed repository',
      },
      remediation: [
        'Remove the CNAME DNS record pointing to username.github.io',
        'Or create the GitHub Pages repository to claim the subdomain',
        'Verify no sensitive data is exposed on this subdomain',
      ],
    },
    {
      id: 2,
      subdomain: 'docs.example.com',
      provider: 'AWS S3',
      severity: 'high',
      confidence: 88,
      discovered: '2024-11-20 09:15',
      cname: 'docs-bucket.s3.amazonaws.com',
      evidence: {
        dnsRecords: {
          cname: 'docs-bucket.s3.amazonaws.com',
          aRecords: [],
        },
        httpResponse: {
          statusCode: 404,
          title: 'NoSuchBucket',
          body: 'The specified bucket does not exist',
        },
        providerPattern: 'AWS S3 - Bucket not found',
      },
      remediation: [
        'Remove the CNAME DNS record',
        'Or create the S3 bucket with the exact name',
        'Enable S3 bucket blocking public access policies',
      ],
    },
    {
      id: 3,
      subdomain: 'staging.example.com',
      provider: 'Heroku',
      severity: 'medium',
      confidence: 75,
      discovered: '2024-11-19 16:45',
      cname: 'old-app-12345.herokuapp.com',
      evidence: {
        dnsRecords: {
          cname: 'old-app-12345.herokuapp.com',
          aRecords: [],
        },
        httpResponse: {
          statusCode: 404,
          title: 'No such app',
          body: 'There is no app configured at that hostname.',
        },
        providerPattern: 'Heroku - App not found',
      },
      remediation: [
        'Remove the CNAME DNS record',
        'Or recreate the Heroku app with the same name',
        'Review all staging environments regularly',
      ],
    },
  ]);

  const filteredFindings = filterSeverity === 'all' 
    ? findings 
    : findings.filter(f => f.severity === filterSeverity);

  const toggleExpand = (id) => {
    setExpandedFinding(expandedFinding === id ? null : id);
  };

  const exportFindings = () => {
    const dataStr = JSON.stringify(findings, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    const exportFileDefaultName = `findings-${new Date().toISOString().split('T')[0]}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
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
                    <span>CNAME: <span className="font-mono">{finding.cname}</span></span>
                    <span>•</span>
                    <span>Discovered: {finding.discovered}</span>
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
                          <span className="text-blue-600 font-medium">{finding.evidence.dnsRecords.cname}</span>
                        </div>
                        <div className="flex items-start">
                          <span className="text-gray-600 min-w-24">A Records:</span>{' '}
                          <span className="text-gray-500">
                            {finding.evidence.dnsRecords.aRecords.length > 0 
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
                            {finding.evidence.httpResponse.statusCode}
                          </span>
                        </div>
                        <div className="flex items-start">
                          <span className="text-gray-600 min-w-32">Title:</span>{' '}
                          <span className="text-gray-900 font-medium">{finding.evidence.httpResponse.title}</span>
                        </div>
                        <div className="flex items-start">
                          <span className="text-gray-600 min-w-32">Body:</span>{' '}
                          <span className="text-gray-700 italic">{finding.evidence.httpResponse.body}</span>
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
                      <Badge variant="info">{finding.evidence.providerPattern}</Badge>
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
                        {finding.remediation.map((step, index) => (
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

      {filteredFindings.length === 0 && (
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
