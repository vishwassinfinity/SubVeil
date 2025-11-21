import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export const providerController = {
  /**
   * Get all providers
   */
  async getAllProviders(req, res) {
    try {
      const providers = await prisma.provider.findMany({
        orderBy: { detectionsCount: 'desc' }
      });

      res.json(providers);
    } catch (error) {
      console.error('Get providers error:', error);
      res.status(500).json({ error: error.message });
    }
  },

  /**
   * Get provider by ID
   */
  async getProviderById(req, res) {
    try {
      const { id } = req.params;
      
      const provider = await prisma.provider.findUnique({
        where: { id }
      });

      if (!provider) {
        return res.status(404).json({ error: 'Provider not found' });
      }

      res.json(provider);
    } catch (error) {
      console.error('Get provider error:', error);
      res.status(500).json({ error: error.message });
    }
  },

  /**
   * Create a new provider
   */
  async createProvider(req, res) {
    try {
      const { name, cname, fingerprints, httpCodes } = req.body;

      const provider = await prisma.provider.create({
        data: {
          name,
          cname,
          fingerprints: JSON.stringify(fingerprints),
          httpCodes: JSON.stringify(httpCodes),
          active: true
        }
      });

      res.status(201).json(provider);
    } catch (error) {
      console.error('Create provider error:', error);
      res.status(500).json({ error: error.message });
    }
  },

  /**
   * Update a provider
   */
  async updateProvider(req, res) {
    try {
      const { id } = req.params;
      const { name, cname, fingerprints, httpCodes, active } = req.body;

      const data = {};
      if (name) data.name = name;
      if (cname) data.cname = cname;
      if (fingerprints) data.fingerprints = JSON.stringify(fingerprints);
      if (httpCodes) data.httpCodes = JSON.stringify(httpCodes);
      if (active !== undefined) data.active = active;

      const provider = await prisma.provider.update({
        where: { id },
        data
      });

      res.json(provider);
    } catch (error) {
      console.error('Update provider error:', error);
      res.status(500).json({ error: error.message });
    }
  },

  /**
   * Delete a provider
   */
  async deleteProvider(req, res) {
    try {
      const { id } = req.params;

      await prisma.provider.delete({
        where: { id }
      });

      res.json({ success: true, message: 'Provider deleted' });
    } catch (error) {
      console.error('Delete provider error:', error);
      res.status(500).json({ error: error.message });
    }
  }
};
