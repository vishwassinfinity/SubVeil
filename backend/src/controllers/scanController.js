import scanService from '../services/scanService.js';

export const scanController = {
  /**
   * Create a new scan
   */
  async createScan(req, res) {
    try {
      const { domain } = req.body;

      if (!domain) {
        return res.status(400).json({ error: 'Domain is required' });
      }

      const scan = await scanService.createScan(domain);
      
      // Auto-start the scan
      await scanService.startScan(scan.id);

      res.status(201).json(scan);
    } catch (error) {
      console.error('Create scan error:', error);
      res.status(500).json({ error: error.message });
    }
  },

  /**
   * Get all scans
   */
  async getAllScans(req, res) {
    try {
      const { status } = req.query;
      const filters = status ? { status } : {};

      const scans = await scanService.getAllScans(filters);
      res.json(scans);
    } catch (error) {
      console.error('Get scans error:', error);
      res.status(500).json({ error: error.message });
    }
  },

  /**
   * Get scan by ID
   */
  async getScanById(req, res) {
    try {
      const { id } = req.params;
      const scan = await scanService.getScanById(id);

      if (!scan) {
        return res.status(404).json({ error: 'Scan not found' });
      }

      res.json(scan);
    } catch (error) {
      console.error('Get scan error:', error);
      res.status(500).json({ error: error.message });
    }
  },

  /**
   * Pause a scan
   */
  async pauseScan(req, res) {
    try {
      const { id } = req.params;
      const result = await scanService.pauseScan(id);
      res.json(result);
    } catch (error) {
      console.error('Pause scan error:', error);
      res.status(500).json({ error: error.message });
    }
  },

  /**
   * Resume a scan
   */
  async resumeScan(req, res) {
    try {
      const { id } = req.params;
      const result = await scanService.resumeScan(id);
      res.json(result);
    } catch (error) {
      console.error('Resume scan error:', error);
      res.status(500).json({ error: error.message });
    }
  },

  /**
   * Delete a scan
   */
  async deleteScan(req, res) {
    try {
      const { id } = req.params;
      const result = await scanService.deleteScan(id);
      res.json(result);
    } catch (error) {
      console.error('Delete scan error:', error);
      res.status(500).json({ error: error.message });
    }
  }
};
