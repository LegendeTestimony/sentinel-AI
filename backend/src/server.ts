import express from 'express';
import cors from 'cors';
import multer from 'multer';
import dotenv from 'dotenv';
import { analyzeFile } from './services/file-analyzer.js';
import { analyzeURL } from './services/url-analyzer.js';
import { MarathonAgent } from './services/marathon-agent.js';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5050;

// Marathon agent instance (global for this demo)
let marathonAgent: MarathonAgent | null = null;

// Configure multer for file uploads (store in memory)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE || '10485760'), // 10MB default
  },
});

// Middleware
// CORS configuration - allows frontend to communicate with backend
const corsOptions = {
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));
app.use(express.json());

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: Date.now(),
    service: 'Sentinel AI Security Backend',
  });
});

// File analysis endpoint
app.post('/api/analyze', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        error: 'No file uploaded',
      });
    }

    console.log(`Analyzing file: ${req.file.originalname} (${req.file.size} bytes)`);

    // Perform analysis
    const result = await analyzeFile(req.file);

    console.log(`Analysis complete: ${result.threat.level} (${result.threat.confidence}% confidence)`);

    res.json(result);
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({
      error: 'Analysis failed',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// URL analysis endpoint
app.post('/api/analyze-url', async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string') {
      return res.status(400).json({
        error: 'Invalid request',
        message: 'URL is required',
      });
    }

    console.log(`Analyzing URL: ${url}`);

    // Perform URL analysis
    const result = await analyzeURL(url);

    console.log(`URL analysis complete: ${result.threat.level} (${result.threat.confidence}% confidence)`);

    res.json(result);
  } catch (error) {
    console.error('URL analysis error:', error);
    res.status(500).json({
      error: 'URL analysis failed',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// ===== MARATHON AGENT ENDPOINTS =====

// Start marathon monitoring
app.post('/api/marathon/start', async (req, res) => {
  try {
    if (marathonAgent) {
      return res.status(400).json({
        error: 'Marathon already running',
        metrics: marathonAgent.getMetrics()
      });
    }

    const { watchPath, duration } = req.body;

    if (!watchPath) {
      return res.status(400).json({
        error: 'watchPath is required'
      });
    }

    marathonAgent = new MarathonAgent({
      watchPath,
      checkInterval: 5000, // 5 seconds
      maxRuntime: duration || 3600000, // 1 hour default for demo
      learningEnabled: true,
      autoQuarantine: true,
      reportInterval: 60000 // 1 minute
    });

    // Start in background
    marathonAgent.start().catch(err => {
      console.error('Marathon error:', err);
    });

    res.json({
      message: 'Marathon agent started',
      config: {
        watchPath,
        duration: duration || 3600000,
        features: ['continuous-monitoring', 'auto-quarantine', 'self-learning']
      }
    });

  } catch (error) {
    console.error('Marathon start error:', error);
    res.status(500).json({
      error: 'Failed to start marathon',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Stop marathon monitoring
app.post('/api/marathon/stop', async (req, res) => {
  try {
    if (!marathonAgent) {
      return res.status(400).json({
        error: 'No marathon running'
      });
    }

    const finalMetrics = marathonAgent.getMetrics();
    await marathonAgent.stop();
    marathonAgent = null;

    res.json({
      message: 'Marathon agent stopped',
      finalMetrics
    });

  } catch (error) {
    console.error('Marathon stop error:', error);
    res.status(500).json({
      error: 'Failed to stop marathon',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Get marathon status
app.get('/api/marathon/status', (req, res) => {
  if (!marathonAgent) {
    return res.json({
      running: false,
      message: 'No marathon currently active'
    });
  }

  res.json({
    running: true,
    metrics: marathonAgent.getMetrics()
  });
});

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        error: 'File too large',
        message: 'Maximum file size is 10MB',
      });
    }
  }

  console.error('Server error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message,
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🛡️  Sentinel AI Backend running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔒 Analysis endpoint: http://localhost:${PORT}/api/analyze`);

  if (!process.env.GEMINI_API_KEY) {
    console.warn('⚠️  WARNING: GEMINI_API_KEY not set in environment variables');
  }
});

export default app;
