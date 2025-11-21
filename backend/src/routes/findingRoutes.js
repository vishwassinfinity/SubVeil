import express from 'express';
import { findingController } from '../controllers/findingController.js';

const router = express.Router();

// Get all findings
router.get('/', findingController.getAllFindings);

// Export findings
router.get('/export', findingController.exportFindings);

// Get finding by ID
router.get('/:id', findingController.getFindingById);

// Mark finding as resolved
router.post('/:id/resolve', findingController.resolveFinding);

export default router;
