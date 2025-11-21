import express from 'express';
import { statsController } from '../controllers/statsController.js';

const router = express.Router();

// Get dashboard statistics
router.get('/', statsController.getStats);

export default router;
