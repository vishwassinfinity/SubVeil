import express from 'express';
import { scanController } from '../controllers/scanController.js';

const router = express.Router();

// Get all scans
router.get('/', scanController.getAllScans);

// Create a new scan
router.post('/', scanController.createScan);

// Get scan by ID
router.get('/:id', scanController.getScanById);

// Pause scan
router.post('/:id/pause', scanController.pauseScan);

// Resume scan
router.post('/:id/resume', scanController.resumeScan);

// Delete scan
router.delete('/:id', scanController.deleteScan);

export default router;
