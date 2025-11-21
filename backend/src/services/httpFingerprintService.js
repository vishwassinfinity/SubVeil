import axios from 'axios';

class HTTPFingerprintService {
  constructor() {
    this.timeout = parseInt(process.env.HTTP_TIMEOUT_MS) || 10000;
    this.userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
  }

  /**
   * Fetch HTTP response for a subdomain
   */
  async fetchSubdomain(subdomain) {
    const urls = [
      `https://${subdomain}`,
      `http://${subdomain}`
    ];

    for (const url of urls) {
      try {
        const response = await axios.get(url, {
          timeout: this.timeout,
          maxRedirects: 5,
          validateStatus: () => true, // Accept any status code
          headers: {
            'User-Agent': this.userAgent
          }
        });

        // Extract title from HTML
        let title = null;
        if (response.data && typeof response.data === 'string') {
          const titleMatch = response.data.match(/<title[^>]*>(.*?)<\/title>/i);
          if (titleMatch) {
            title = titleMatch[1].trim();
          }
        }

        return {
          statusCode: response.status,
          headers: response.headers,
          body: response.data ? response.data.substring(0, 5000) : '', // First 5000 chars
          title,
          protocol: url.startsWith('https') ? 'https' : 'http',
          finalUrl: response.request?.res?.responseUrl || url
        };
      } catch (error) {
        // Try next protocol
        if (url === urls[urls.length - 1]) {
          return {
            statusCode: 0,
            headers: {},
            body: '',
            title: null,
            protocol: null,
            error: error.message
          };
        }
      }
    }
  }

  /**
   * Match HTTP response against provider fingerprints
   */
  matchFingerprints(httpResponse, provider) {
    if (!httpResponse || !httpResponse.body) {
      return { matched: false, confidence: 0 };
    }

    const fingerprints = JSON.parse(provider.fingerprints || '[]');
    const httpCodes = JSON.parse(provider.httpCodes || '[]');
    
    let matches = 0;
    let totalChecks = 0;

    // Check HTTP status code
    totalChecks++;
    if (httpCodes.includes(httpResponse.statusCode)) {
      matches++;
    }

    // Check fingerprints in body and title
    const searchText = `${httpResponse.body} ${httpResponse.title || ''}`.toLowerCase();
    
    fingerprints.forEach(fingerprint => {
      totalChecks++;
      if (searchText.includes(fingerprint.toLowerCase())) {
        matches++;
      }
    });

    const confidence = totalChecks > 0 ? Math.round((matches / totalChecks) * 100) : 0;
    const matched = confidence >= 50; // At least 50% match

    return {
      matched,
      confidence,
      matchedFingerprints: fingerprints.filter(fp => 
        searchText.includes(fp.toLowerCase())
      )
    };
  }

  /**
   * Detect subdomain takeover vulnerability
   */
  async detectTakeover(subdomain, dnsData, providers) {
    try {
      // First check if there's a dangling CNAME
      if (!dnsData.isDangling || !dnsData.cname) {
        return null;
      }

      // Fetch HTTP response
      const httpResponse = await this.fetchSubdomain(subdomain);
      
      if (!httpResponse || httpResponse.statusCode === 0) {
        return null;
      }

      // Try to match against providers
      for (const provider of providers) {
        const cnamePattern = provider.cname.replace(/\*/g, '.*');
        const cnameRegex = new RegExp(cnamePattern, 'i');

        // Check if CNAME matches provider
        if (cnameRegex.test(dnsData.cname)) {
          const fingerprintMatch = this.matchFingerprints(httpResponse, provider);

          if (fingerprintMatch.matched) {
            return {
              provider: provider.name,
              severity: this.calculateSeverity(fingerprintMatch.confidence, httpResponse.statusCode),
              confidence: fingerprintMatch.confidence,
              httpResponse,
              matchedFingerprints: fingerprintMatch.matchedFingerprints,
              providerPattern: provider.cname
            };
          }
        }
      }

      return null;
    } catch (error) {
      console.error(`Takeover detection failed for ${subdomain}:`, error.message);
      return null;
    }
  }

  /**
   * Calculate severity based on confidence and HTTP status
   */
  calculateSeverity(confidence, httpStatusCode) {
    if (confidence >= 90 && [404, 410].includes(httpStatusCode)) {
      return 'critical';
    } else if (confidence >= 75 && [404, 410, 403].includes(httpStatusCode)) {
      return 'high';
    } else if (confidence >= 60) {
      return 'medium';
    } else {
      return 'low';
    }
  }

  /**
   * Batch HTTP checks with concurrency control
   */
  async batchCheck(subdomains, dnsResults, providers, concurrency = 5) {
    const results = [];
    const queue = [...subdomains];

    const worker = async () => {
      while (queue.length > 0) {
        const subdomain = queue.shift();
        if (subdomain) {
          const dnsData = dnsResults.find(d => d.subdomain === subdomain);
          if (dnsData) {
            const vulnerability = await this.detectTakeover(subdomain, dnsData, providers);
            if (vulnerability) {
              results.push({
                subdomain,
                ...vulnerability
              });
            }
          }
        }
      }
    };

    const workers = Array(Math.min(concurrency, subdomains.length))
      .fill(null)
      .map(() => worker());

    await Promise.all(workers);
    return results;
  }
}

export default new HTTPFingerprintService();
