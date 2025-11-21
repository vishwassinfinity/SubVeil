import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export const findingController = {
  /**
   * Get all findings
   */
  async getAllFindings(req, res) {
    try {
      const { severity, resolved, scanId } = req.query;
      
      const where = {};
      if (severity) where.severity = severity;
      if (resolved !== undefined) where.resolved = resolved === 'true';
      if (scanId) where.scanId = scanId;

      const findings = await prisma.finding.findMany({
        where,
        orderBy: { discovered: 'desc' },
        include: {
          scan: {
            select: {
              domain: true
            }
          }
        }
      });

      res.json(findings);
    } catch (error) {
      console.error('Get findings error:', error);
      res.status(500).json({ error: error.message });
    }
  },

  /**
   * Get finding by ID
   */
  async getFindingById(req, res) {
    try {
      const { id } = req.params;
      
      const finding = await prisma.finding.findUnique({
        where: { id },
        include: {
          scan: true
        }
      });

      if (!finding) {
        return res.status(404).json({ error: 'Finding not found' });
      }

      res.json(finding);
    } catch (error) {
      console.error('Get finding error:', error);
      res.status(500).json({ error: error.message });
    }
  },

  /**
   * Export findings
   */
  async exportFindings(req, res) {
    try {
      const { format = 'json', severity } = req.query;
      
      const where = severity ? { severity } : {};
      const findings = await prisma.finding.findMany({
        where,
        include: {
          scan: {
            select: {
              domain: true
            }
          }
        }
      });

      if (format === 'json') {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', 'attachment; filename=findings.json');
        res.json(findings);
      } else if (format === 'csv') {
        // Simple CSV export
        const csv = [
          'Subdomain,Provider,Severity,Confidence,CNAME,HTTP Status,Discovered',
          ...findings.map(f => 
            `${f.subdomain},${f.provider},${f.severity},${f.confidence},${f.cnameRecord},${f.httpStatusCode},${f.discovered}`
          )
        ].join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=findings.csv');
        res.send(csv);
      } else {
        res.status(400).json({ error: 'Invalid format' });
      }
    } catch (error) {
      console.error('Export findings error:', error);
      res.status(500).json({ error: error.message });
    }
  },

  /**
   * Mark finding as resolved
   */
  async resolveFinding(req, res) {
    try {
      const { id } = req.params;
      
      const finding = await prisma.finding.update({
        where: { id },
        data: {
          resolved: true,
          resolvedAt: new Date()
        }
      });

      res.json(finding);
    } catch (error) {
      console.error('Resolve finding error:', error);
      res.status(500).json({ error: error.message });
    }
  }
};
