import dns from 'dns';
import { promisify } from 'util';

const resolveCname = promisify(dns.resolveCname);
const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);
const resolveTxt = promisify(dns.resolveTxt);

class DNSService {
  constructor() {
    this.timeout = parseInt(process.env.DNS_TIMEOUT_MS) || 5000;
  }

  /**
   * Resolve CNAME records for a subdomain
   */
  async getCNAME(subdomain) {
    try {
      const cnames = await Promise.race([
        resolveCname(subdomain),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('DNS timeout')), this.timeout)
        )
      ]);
      return cnames && cnames.length > 0 ? cnames[0] : null;
    } catch (error) {
      if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
        return null;
      }
      throw error;
    }
  }

  /**
   * Resolve A records (IPv4)
   */
  async getARecords(subdomain) {
    try {
      const records = await Promise.race([
        resolve4(subdomain),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('DNS timeout')), this.timeout)
        )
      ]);
      return records || [];
    } catch (error) {
      if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
        return [];
      }
      return [];
    }
  }

  /**
   * Resolve AAAA records (IPv6)
   */
  async getAAAARecords(subdomain) {
    try {
      const records = await Promise.race([
        resolve6(subdomain),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('DNS timeout')), this.timeout)
        )
      ]);
      return records || [];
    } catch (error) {
      if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
        return [];
      }
      return [];
    }
  }

  /**
   * Comprehensive DNS lookup for subdomain
   */
  async lookupSubdomain(subdomain) {
    try {
      const [cname, aRecords, aaaaRecords] = await Promise.all([
        this.getCNAME(subdomain),
        this.getARecords(subdomain),
        this.getAAAARecords(subdomain)
      ]);

      return {
        subdomain,
        cname,
        aRecords,
        aaaaRecords,
        hasRecords: !!(cname || aRecords.length > 0 || aaaaRecords.length > 0),
        isDangling: !!(cname && aRecords.length === 0 && aaaaRecords.length === 0)
      };
    } catch (error) {
      console.error(`DNS lookup failed for ${subdomain}:`, error.message);
      return {
        subdomain,
        cname: null,
        aRecords: [],
        aaaaRecords: [],
        hasRecords: false,
        isDangling: false,
        error: error.message
      };
    }
  }

  /**
   * Check if CNAME points to a known vulnerable service
   */
  isVulnerableCNAME(cname, providers) {
    if (!cname) return null;

    for (const provider of providers) {
      const pattern = provider.cname.replace(/\*/g, '.*');
      const regex = new RegExp(pattern, 'i');
      
      if (regex.test(cname)) {
        return provider;
      }
    }

    return null;
  }

  /**
   * Batch DNS lookups with concurrency control
   */
  async batchLookup(subdomains, concurrency = 10) {
    const results = [];
    const queue = [...subdomains];

    const worker = async () => {
      while (queue.length > 0) {
        const subdomain = queue.shift();
        if (subdomain) {
          const result = await this.lookupSubdomain(subdomain);
          results.push(result);
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

export default new DNSService();
