import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';

// Import routes
import scanRoutes from './routes/scanRoutes.js';
import findingRoutes from './routes/findingRoutes.js';
import providerRoutes from './routes/providerRoutes.js';
import statsRoutes from './routes/statsRoutes.js';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
  credentials: true
}));
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API Routes
app.use('/api/scans', scanRoutes);
app.use('/api/findings', findingRoutes);
app.use('/api/providers', providerRoutes);
app.use('/api/stats', statsRoutes);

// Root route
app.get('/', (req, res) => {
  res.json({
    name: 'SubVeil API',
    version: '1.0.0',
    description: 'Subdomain Takeover Detection Backend',
    endpoints: {
      health: '/health',
      stats: '/api/stats',
      scans: '/api/scans',
      findings: '/api/findings',
      providers: '/api/providers'
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║   🛡️  SubVeil API Server                              ║
║                                                       ║
║   Status: Running                                     ║
║   Port: ${PORT}                                        ║
║   Environment: ${process.env.NODE_ENV || 'development'}                              ║
║   CORS Origin: ${process.env.CORS_ORIGIN || 'http://localhost:5173'}      ║
║                                                       ║
║   Endpoints:                                          ║
║   - GET  /health                                      ║
║   - GET  /api/stats                                   ║
║   - GET  /api/scans                                   ║
║   - POST /api/scans                                   ║
║   - GET  /api/findings                                ║
║   - GET  /api/providers                               ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
  `);
});

export default app;
