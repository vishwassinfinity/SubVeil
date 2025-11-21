import axios from 'axios';
import dnsService from './dnsService.js';

class SubdomainEnumerationService {
  constructor() {
    this.commonSubdomains = [
      'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
      'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'app', 'm', 'dev', 'staging',
      'api', 'cdn', 'admin', 'portal', 'blog', 'shop', 'forum', 'support', 'helpdesk',
      'test', 'beta', 'alpha', 'demo', 'docs', 'help', 'status', 'dashboard', 'static',
      'assets', 'images', 'img', 'css', 'js', 'media', 'files', 'download', 'uploads',
      'secure', 'vpn', 'remote', 'cloud', 'store', 'git', 'gitlab', 'jenkins', 'ci',
      'build', 'deploy', 'prod', 'production', 'uat', 'qa', 'sandbox', 'old', 'new',
      'legacy', 'v1', 'v2', 'v3', 'mobile', 'ios', 'android', 'app', 'apps', 'preview'
    ];
  }

  /**
   * Enumerate subdomains using common names
   */
  async bruteForceSubdomains(domain) {
    const subdomains = this.commonSubdomains.map(sub => `${sub}.${domain}`);
    const validSubdomains = [];

    // Check which subdomains resolve
    for (const subdomain of subdomains) {
      const result = await dnsService.lookupSubdomain(subdomain);
      if (result.hasRecords) {
        validSubdomains.push(subdomain);
      }
    }

    return validSubdomains;
  }

  /**
   * Enumerate subdomains using Certificate Transparency logs
   */
  async certificateTransparency(domain) {
    try {
      const response = await axios.get(`https://crt.sh/?q=%.${domain}&output=json`, {
        timeout: 30000,
        headers: {
          'User-Agent': 'SubVeil/1.0'
        }
      });

      if (!response.data || !Array.isArray(response.data)) {
        return [];
      }

      // Extract unique subdomains
      const subdomains = new Set();
      
      response.data.forEach(cert => {
        if (cert.name_value) {
          const names = cert.name_value.split('\n');
          names.forEach(name => {
            name = name.trim().toLowerCase();
            // Remove wildcards and ensure it's for this domain
            name = name.replace('*.', '');
            if (name.endsWith(domain) && name !== domain) {
              subdomains.add(name);
            }
          });
        }
      });

      return Array.from(subdomains);
    } catch (error) {
      console.error('Certificate Transparency lookup failed:', error.message);
      return [];
    }
  }

  /**
   * Try subdomain permutations
   */
  generatePermutations(domain, keywords = []) {
    const permutations = new Set();
    const baseKeywords = ['dev', 'staging', 'test', 'prod', 'admin', 'api', 'beta'];
    const allKeywords = [...baseKeywords, ...keywords];

    allKeywords.forEach(keyword => {
      permutations.add(`${keyword}.${domain}`);
      permutations.add(`${keyword}-${domain}`);
      permutations.add(`${keyword}1.${domain}`);
      permutations.add(`${keyword}2.${domain}`);
    });

    return Array.from(permutations);
  }

  /**
   * Main enumeration function - combines all methods
   */
  async enumerateSubdomains(domain, options = {}) {
    const {
      useBruteForce = true,
      useCertificateTransparency = true,
      usePermutations = true,
      keywords = []
    } = options;

    const allSubdomains = new Set();
    const results = {
      total: 0,
      sources: {
        bruteForce: 0,
        certificateTransparency: 0,
        permutations: 0
      }
    };

    try {
      // 1. Brute force common names
      if (useBruteForce) {
        console.log(`[Enumeration] Starting brute force for ${domain}...`);
        const bruteForceResults = await this.bruteForceSubdomains(domain);
        bruteForceResults.forEach(sub => allSubdomains.add(sub));
        results.sources.bruteForce = bruteForceResults.length;
        console.log(`[Enumeration] Found ${bruteForceResults.length} via brute force`);
      }

      // 2. Certificate Transparency
      if (useCertificateTransparency) {
        console.log(`[Enumeration] Querying Certificate Transparency logs...`);
        const ctResults = await this.certificateTransparency(domain);
        let newFromCT = 0;
        ctResults.forEach(sub => {
          if (!allSubdomains.has(sub)) {
            allSubdomains.add(sub);
            newFromCT++;
          }
        });
        results.sources.certificateTransparency = newFromCT;
        console.log(`[Enumeration] Found ${newFromCT} new subdomains via CT logs`);
      }

      // 3. Permutations
      if (usePermutations) {
        console.log(`[Enumeration] Generating permutations...`);
        const permutations = this.generatePermutations(domain, keywords);
        
        // Check permutations (sample only to avoid too many requests)
        const permutationsToCheck = permutations.slice(0, 50);
        let newFromPerm = 0;
        
        for (const subdomain of permutationsToCheck) {
          if (!allSubdomains.has(subdomain)) {
            const result = await dnsService.lookupSubdomain(subdomain);
            if (result.hasRecords) {
              allSubdomains.add(subdomain);
              newFromPerm++;
            }
          }
        }
        results.sources.permutations = newFromPerm;
        console.log(`[Enumeration] Found ${newFromPerm} via permutations`);
      }

      results.total = allSubdomains.size;
      
      return {
        subdomains: Array.from(allSubdomains),
        stats: results
      };
    } catch (error) {
      console.error('Subdomain enumeration error:', error);
      throw error;
    }
  }

  /**
   * Quick enumeration (fast mode)
   */
  async quickEnumerate(domain) {
    return this.enumerateSubdomains(domain, {
      useBruteForce: true,
      useCertificateTransparency: true,
      usePermutations: false
    });
  }

  /**
   * Deep enumeration (comprehensive mode)
   */
  async deepEnumerate(domain, keywords = []) {
    return this.enumerateSubdomains(domain, {
      useBruteForce: true,
      useCertificateTransparency: true,
      usePermutations: true,
      keywords
    });
  }
}

export default new SubdomainEnumerationService();
