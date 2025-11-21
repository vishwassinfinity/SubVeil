import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export const statsController = {
  /**
   * Get dashboard statistics
   */
  async getStats(req, res) {
    try {
      // Get counts
      const [
        scansCount,
        findingsCount,
        resolvedCount,
        activeScansCount
      ] = await Promise.all([
        prisma.scan.count(),
        prisma.finding.count(),
        prisma.finding.count({ where: { resolved: true } }),
        prisma.scan.count({ where: { status: 'running' } })
      ]);

      // Get latest scan
      const latestScan = await prisma.scan.findFirst({
        orderBy: { createdAt: 'desc' }
      });

      // Get severity distribution
      const severityDistribution = await prisma.finding.groupBy({
        by: ['severity'],
        _count: true
      });

      // Get provider distribution
      const providerDistribution = await prisma.finding.groupBy({
        by: ['provider'],
        _count: true,
        orderBy: {
          _count: {
            provider: 'desc'
          }
        },
        take: 10
      });

      // Calculate total subdomains from all scans
      const scans = await prisma.scan.findMany({
        select: { subdomainsFound: true }
      });
      const totalSubdomains = scans.reduce((sum, scan) => sum + scan.subdomainsFound, 0);

      // Calculate risk score (0-100)
      const riskScore = findingsCount > 0 
        ? Math.min(100, Math.round((findingsCount / Math.max(totalSubdomains, 1)) * 1000))
        : 0;

      // Get recent findings
      const recentFindings = await prisma.finding.findMany({
        take: 5,
        orderBy: { discovered: 'desc' },
        include: {
          scan: {
            select: { domain: true }
          }
        }
      });

      // Get trend data (last 7 days)
      const sevenDaysAgo = new Date();
      sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

      const trendData = await prisma.finding.groupBy({
        by: ['discovered'],
        _count: true,
        where: {
          discovered: {
            gte: sevenDaysAgo
          }
        }
      });

      res.json({
        totalSubdomains,
        vulnerableSubdomains: findingsCount,
        activeScans: activeScansCount,
        lastScanTime: latestScan ? latestScan.createdAt : null,
        resolvedThisWeek: resolvedCount,
        scansConducted: scansCount,
        riskScore,
        severityDistribution: severityDistribution.map(s => ({
          severity: s.severity,
          count: s._count
        })),
        providerDistribution: providerDistribution.map(p => ({
          provider: p.provider,
          count: p._count
        })),
        recentFindings: recentFindings.map(f => ({
          id: f.id,
          subdomain: f.subdomain,
          provider: f.provider,
          severity: f.severity,
          discovered: f.discovered,
          domain: f.scan.domain
        })),
        trendData
      });
    } catch (error) {
      console.error('Get stats error:', error);
      res.status(500).json({ error: error.message });
    }
  }
};
