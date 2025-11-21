import { PrismaClient } from '@prisma/client';
import subdomainService from './subdomainService.js';
import dnsService from './dnsService.js';
import httpFingerprintService from './httpFingerprintService.js';

const prisma = new PrismaClient();

class ScanService {
  constructor() {
    this.activeScans = new Map(); // Store active scan states
    this.maxConcurrent = parseInt(process.env.MAX_CONCURRENT_SCANS) || 5;
  }

  /**
   * Create a new scan
   */
  async createScan(domain) {
    try {
      const scan = await prisma.scan.create({
        data: {
          domain,
          status: 'scheduled',
          progress: 0
        }
      });

      return scan;
    } catch (error) {
      console.error('Failed to create scan:', error);
      throw error;
    }
  }

  /**
   * Start a scan
   */
  async startScan(scanId) {
    try {
      const scan = await prisma.scan.findUnique({ where: { id: scanId } });
      
      if (!scan) {
        throw new Error('Scan not found');
      }

      if (scan.status === 'running') {
        throw new Error('Scan is already running');
      }

      // Update scan status
      await prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'running',
          startTime: new Date(),
          progress: 0
        }
      });

      // Start the scan process in background
      this.runScan(scanId, scan.domain);

      return { success: true, message: 'Scan started' };
    } catch (error) {
      console.error('Failed to start scan:', error);
      throw error;
    }
  }

  /**
   * Main scan execution logic
   */
  async runScan(scanId, domain) {
    console.log(`[Scan ${scanId}] Starting scan for ${domain}`);
    
    try {
      // Store scan state
      this.activeScans.set(scanId, {
        paused: false,
        progress: 0
      });

      // Step 1: Enumerate subdomains
      console.log(`[Scan ${scanId}] Step 1: Enumerating subdomains...`);
      const { subdomains } = await subdomainService.enumerateSubdomains(domain);
      
      await prisma.scan.update({
        where: { id: scanId },
        data: {
          totalSubdomains: subdomains.length,
          progress: 20
        }
      });

      if (this.isScanPaused(scanId)) {
        console.log(`[Scan ${scanId}] Scan paused during enumeration`);
        return;
      }

      console.log(`[Scan ${scanId}] Found ${subdomains.length} subdomains`);

      // Step 2: DNS Analysis
      console.log(`[Scan ${scanId}] Step 2: Analyzing DNS records...`);
      const dnsResults = await dnsService.batchLookup(subdomains, 10);
      
      // Save subdomains to database
      for (const dnsData of dnsResults) {
        await prisma.subdomain.create({
          data: {
            scanId,
            subdomain: dnsData.subdomain,
            cnameRecord: dnsData.cname,
            aRecords: JSON.stringify(dnsData.aRecords)
          }
        });
      }

      await prisma.scan.update({
        where: { id: scanId },
        data: {
          subdomainsFound: dnsResults.filter(d => d.hasRecords).length,
          progress: 50
        }
      });

      if (this.isScanPaused(scanId)) {
        console.log(`[Scan ${scanId}] Scan paused during DNS analysis`);
        return;
      }

      // Step 3: Find dangling CNAMEs
      const danglingSubdomains = dnsResults.filter(d => d.isDangling);
      console.log(`[Scan ${scanId}] Found ${danglingSubdomains.length} potential dangling CNAMEs`);

      await prisma.scan.update({
        where: { id: scanId },
        data: { progress: 60 }
      });

      if (danglingSubdomains.length === 0) {
        console.log(`[Scan ${scanId}] No dangling CNAMEs found. Scan complete.`);
        await this.completeScan(scanId, 0);
        return;
      }

      // Step 4: Get active providers
      const providers = await prisma.provider.findMany({
        where: { active: true }
      });

      console.log(`[Scan ${scanId}] Step 3: Checking for takeover vulnerabilities...`);

      // Step 5: HTTP Fingerprinting
      const vulnerabilities = await httpFingerprintService.batchCheck(
        danglingSubdomains.map(d => d.subdomain),
        dnsResults,
        providers,
        5
      );

      await prisma.scan.update({
        where: { id: scanId },
        data: { progress: 90 }
      });

      if (this.isScanPaused(scanId)) {
        console.log(`[Scan ${scanId}] Scan paused during HTTP checks`);
        return;
      }

      console.log(`[Scan ${scanId}] Found ${vulnerabilities.length} vulnerabilities`);

      // Step 6: Save findings
      for (const vuln of vulnerabilities) {
        const dnsData = dnsResults.find(d => d.subdomain === vuln.subdomain);
        
        await prisma.finding.create({
          data: {
            scanId,
            subdomain: vuln.subdomain,
            provider: vuln.provider,
            severity: vuln.severity,
            confidence: vuln.confidence,
            cnameRecord: dnsData.cname || '',
            aRecords: JSON.stringify(dnsData.aRecords),
            httpStatusCode: vuln.httpResponse.statusCode,
            httpTitle: vuln.httpResponse.title,
            httpBody: vuln.httpResponse.body?.substring(0, 1000),
            providerPattern: vuln.providerPattern,
            fingerprints: JSON.stringify(vuln.matchedFingerprints),
            evidence: JSON.stringify({
              dnsRecords: {
                cname: dnsData.cname,
                aRecords: dnsData.aRecords
              },
              httpResponse: {
                statusCode: vuln.httpResponse.statusCode,
                title: vuln.httpResponse.title,
                body: vuln.httpResponse.body?.substring(0, 500)
              },
              providerPattern: vuln.providerPattern
            }),
            remediation: JSON.stringify([
              `Remove the CNAME DNS record pointing to ${dnsData.cname}`,
              `Or claim/recreate the service at ${dnsData.cname}`,
              'Verify no sensitive data is exposed on this subdomain',
              'Monitor for unauthorized changes'
            ])
          }
        });

        // Update subdomain as vulnerable
        await prisma.subdomain.updateMany({
          where: {
            scanId,
            subdomain: vuln.subdomain
          },
          data: {
            isVulnerable: true,
            httpStatusCode: vuln.httpResponse.statusCode,
            httpTitle: vuln.httpResponse.title,
            httpBody: vuln.httpResponse.body?.substring(0, 500)
          }
        });

        // Increment provider detection count
        await prisma.provider.updateMany({
          where: { name: vuln.provider },
          data: {
            detectionsCount: {
              increment: 1
            }
          }
        });
      }

      // Complete scan
      await this.completeScan(scanId, vulnerabilities.length);
      
      console.log(`[Scan ${scanId}] Scan completed successfully!`);
    } catch (error) {
      console.error(`[Scan ${scanId}] Scan failed:`, error);
      await this.failScan(scanId, error.message);
    } finally {
      this.activeScans.delete(scanId);
    }
  }

  /**
   * Complete a scan
   */
  async completeScan(scanId, vulnerableCount) {
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'completed',
        endTime: new Date(),
        vulnerableCount,
        progress: 100
      }
    });
  }

  /**
   * Fail a scan
   */
  async failScan(scanId, errorMessage) {
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'failed',
        endTime: new Date()
      }
    });
  }

  /**
   * Pause a scan
   */
  async pauseScan(scanId) {
    const scanState = this.activeScans.get(scanId);
    if (scanState) {
      scanState.paused = true;
    }

    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'paused' }
    });

    return { success: true, message: 'Scan paused' };
  }

  /**
   * Resume a scan
   */
  async resumeScan(scanId) {
    const scan = await prisma.scan.findUnique({ where: { id: scanId } });
    
    if (!scan) {
      throw new Error('Scan not found');
    }

    if (scan.status !== 'paused') {
      throw new Error('Scan is not paused');
    }

    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'running' }
    });

    // Restart the scan
    this.runScan(scanId, scan.domain);

    return { success: true, message: 'Scan resumed' };
  }

  /**
   * Check if scan is paused
   */
  isScanPaused(scanId) {
    const scanState = this.activeScans.get(scanId);
    return scanState?.paused || false;
  }

  /**
   * Delete a scan
   */
  async deleteScan(scanId) {
    await prisma.scan.delete({
      where: { id: scanId }
    });

    this.activeScans.delete(scanId);

    return { success: true, message: 'Scan deleted' };
  }

  /**
   * Get all scans
   */
  async getAllScans(filters = {}) {
    const scans = await prisma.scan.findMany({
      where: filters,
      orderBy: { createdAt: 'desc' },
      include: {
        _count: {
          select: {
            findings: true,
            subdomains: true
          }
        }
      }
    });

    return scans;
  }

  /**
   * Get scan by ID
   */
  async getScanById(scanId) {
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: {
        findings: true,
        subdomains: true
      }
    });

    return scan;
  }
}

export default new ScanService();
