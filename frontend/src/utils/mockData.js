// Mock data for development and testing

export const mockStats = {
  totalSubdomains: 1247,
  vulnerableSubdomains: 23,
  activeScans: 3,
  lastScanTime: '2 hours ago',
};

export const mockScans = [
  {
    id: 1,
    domain: 'example.com',
    status: 'completed',
    startTime: '2024-11-20 08:00',
    endTime: '2024-11-20 08:15',
    subdomainsFound: 1247,
    vulnerabilitiesFound: 23,
  },
  {
    id: 2,
    domain: 'testdomain.com',
    status: 'running',
    startTime: '2024-11-20 10:30',
    endTime: null,
    subdomainsFound: 543,
    vulnerabilitiesFound: 8,
  },
];

export const mockFindings = [
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
        title: "There isn't a GitHub Pages site here.",
        body: "If you're trying to publish one...",
      },
      providerPattern: 'GitHub Pages - Unclaimed repository',
    },
    remediation: [
      'Remove the CNAME DNS record pointing to username.github.io',
      'Or create the GitHub Pages repository to claim the subdomain',
      'Verify no sensitive data is exposed on this subdomain',
    ],
  },
];

export const mockProviders = [
  {
    id: 1,
    name: 'GitHub Pages',
    cname: '*.github.io',
    fingerprints: [
      "There isn't a GitHub Pages site here.",
      'For root URLs (like http://example.com/) you must provide an index.html file',
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 8,
  },
  {
    id: 2,
    name: 'AWS S3',
    cname: '*.s3.amazonaws.com',
    fingerprints: ['NoSuchBucket', 'The specified bucket does not exist'],
    httpCodes: [404, 403],
    active: true,
    detectionsCount: 6,
  },
];

export const mockReports = [
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
];
