import express from 'express';
import { providerController } from '../controllers/providerController.js';

const router = express.Router();

// Get all providers
router.get('/', providerController.getAllProviders);

// Create a new provider
router.post('/', providerController.createProvider);

// Get provider by ID
router.get('/:id', providerController.getProviderById);

// Update provider
router.put('/:id', providerController.updateProvider);

// Delete provider
router.delete('/:id', providerController.deleteProvider);

export default router;
