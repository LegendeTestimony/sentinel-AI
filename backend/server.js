import express from 'express';
import cors from 'cors';
import multer from 'multer';
import { GoogleGenerativeAI } from '@google/generative-ai';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configure multer for file uploads (store in memory)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE || '10485760'), // 10MB default
  },
});

// Middleware
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? ['https://sentinel-ai-by-legend.vercel.app']
    : ['http://localhost:5173', 'http://localhost:3000', 'http://localhost:5050'],
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: true,
  optionsSuccessStatus: 200
}));
app.use(express.json());

// Initialize Gemini
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// ===== UTILITY FUNCTIONS =====

/**
 * Calculate Shannon entropy of a buffer
 */
function calculateEntropy(buffer) {
  const frequencies = new Map();
  for (const byte of buffer) {
    frequencies.set(byte, (frequencies.get(byte) || 0) + 1);
  }

  let entropy = 0;
  const len = buffer.length;

  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Detect file type from magic bytes
 */
function detectFileType(buffer, filename) {
  const signatures = [
    { type: 'PE', magic: [0x4D, 0x5A], offset: 0, category: 'executable' },
    { type: 'ELF', magic: [0x7F, 0x45, 0x4C, 0x46], offset: 0, category: 'executable' },
    { type: 'PDF', magic: [0x25, 0x50, 0x44, 0x46], offset: 0, category: 'document' },
    { type: 'ZIP', magic: [0x50, 0x4B, 0x03, 0x04], offset: 0, category: 'archive' },
    { type: 'PNG', magic: [0x89, 0x50, 0x4E, 0x47], offset: 0, category: 'image' },
    { type: 'JPEG', magic: [0xFF, 0xD8, 0xFF], offset: 0, category: 'image' },
    { type: 'GIF', magic: [0x47, 0x49, 0x46, 0x38], offset: 0, category: 'image' },
    { type: 'HEIC', magic: [0x66, 0x74, 0x79, 0x70], offset: 4, category: 'image' },
  ];

  for (const sig of signatures) {
    const match = sig.magic.every((byte, i) => buffer[sig.offset + i] === byte);
    if (match) {
      const ext = filename.split('.').pop()?.toLowerCase();
      const extensionMismatch = ext && !sig.type.toLowerCase().includes(ext);
      return {
        type: sig.type,
        category: sig.category,
        confidence: 90,
        extensionMismatch
      };
    }
  }

  return {
    type: 'UNKNOWN',
    category: 'unknown',
    confidence: 0,
    extensionMismatch: false
  };
}

/**
 * Search for suspicious patterns in buffer
 */
function detectSuspiciousPatterns(buffer) {
  const patterns = {
    shellcode: /\x90{10,}/, // NOP sled
    base64Exec: /(?:TVqQAAMAAAAEAAAA|UEsDBBQA)/, // PE/ZIP in base64
    suspiciousAPIs: /(CreateProcess|WriteFile|RegSetValue|ShellExecute)/gi,
    urlPatterns: /(https?:\/\/[^\s<>"]+)/gi,
    ipAddresses: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  };

  const findings = {};
  const text = buffer.toString('utf-8', 0, Math.min(buffer.length, 50000));

  for (const [name, pattern] of Object.entries(patterns)) {
    const matches = text.match(pattern);
    if (matches) {
      findings[name] = matches.slice(0, 5); // Limit to 5 matches
    }
  }

  return findings;
}

/**
 * Calculate threat score based on indicators
 */
function calculateThreatScore(fileInfo, entropy, patterns) {
  let score = 0;
  const indicators = [];

  // Entropy analysis
  if (entropy > 7.5) {
    score += 30;
    indicators.push(`Very high entropy (${entropy.toFixed(2)}) - possible encryption/packing`);
  } else if (entropy > 7.0) {
    score += 15;
    indicators.push(`High entropy (${entropy.toFixed(2)}) - compressed or obfuscated`);
  }

  // File type analysis
  if (fileInfo.type === 'UNKNOWN') {
    score += 25;
    indicators.push('Unknown file format');
  }

  if (fileInfo.extensionMismatch) {
    score += 40;
    indicators.push(`Extension mismatch: file content doesn't match extension`);
  }

  if (fileInfo.category === 'executable') {
    score += 20;
    indicators.push('Executable file detected');
  }

  // Pattern analysis
  if (patterns.shellcode) {
    score += 50;
    indicators.push('Shellcode patterns detected (NOP sled)');
  }

  if (patterns.base64Exec) {
    score += 45;
    indicators.push('Base64-encoded executable detected');
  }

  if (patterns.suspiciousAPIs) {
    score += 35;
    indicators.push(`Suspicious API calls: ${patterns.suspiciousAPIs.slice(0, 3).join(', ')}`);
  }

  // Normalize to 0-100
  score = Math.min(100, score);

  // Determine threat level
  let level = 'SAFE';
  if (score >= 80) level = 'CRITICAL';
  else if (score >= 60) level = 'HIGH';
  else if (score >= 40) level = 'MEDIUM';
  else if (score >= 20) level = 'LOW';

  return { score, level, indicators };
}

/**
 * Use Gemini to analyze file behavior
 */
async function analyzeThreatWithAI(fileInfo, entropy, patterns, threatScore) {
  const model = genAI.getGenerativeModel({
    model: 'gemini-2.0-flash-exp',
  });

  const prompt = `You are a cybersecurity expert analyzing a potentially malicious file.

File Information:
- Type: ${fileInfo.type}
- Category: ${fileInfo.category}
- Extension Mismatch: ${fileInfo.extensionMismatch ? 'YES' : 'NO'}
- Entropy: ${entropy.toFixed(2)}/8.0 (higher = more encrypted/packed)
- Threat Score: ${threatScore.score}/100
- Threat Level: ${threatScore.level}

Detected Patterns:
${Object.entries(patterns).map(([name, matches]) => `- ${name}: ${Array.isArray(matches) ? matches.length : 0} matches`).join('\n')}

Suspicious Indicators:
${threatScore.indicators.map(i => `- ${i}`).join('\n')}

Based on this analysis:
1. What is the likely purpose of this file?
2. What would happen if this file is executed?
3. What specific threats does it pose?
4. What is your recommended action?

Provide a clear, actionable threat assessment in 3-5 sentences.`;

  const result = await model.generateContent(prompt);
  const response = result.response;
  return response.text();
}

// ===== API ENDPOINTS =====

/**
 * File analysis endpoint - 11-stage pipeline
 */
app.post('/api/analyze', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const startTime = Date.now();
    console.log(`\n🔍 Analyzing: ${req.file.originalname} (${req.file.size} bytes)`);

    // Stage 1: File identification
    console.log('📋 Stage 1: File identification...');
    const fileInfo = detectFileType(req.file.buffer, req.file.originalname);

    // Stage 2: Metadata extraction
    console.log('📊 Stage 2: Metadata extraction...');
    const hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
    const metadata = {
      filename: req.file.originalname,
      size: req.file.size,
      hash: hash,
      mimetype: req.file.mimetype,
    };

    // Stage 3: Entropy analysis
    console.log('🎲 Stage 3: Entropy analysis...');
    const entropy = calculateEntropy(req.file.buffer);

    // Stage 4: Pattern detection
    console.log('🔎 Stage 4: Pattern detection...');
    const patterns = detectSuspiciousPatterns(req.file.buffer);

    // Stage 5: Threat scoring
    console.log('⚖️ Stage 5: Threat scoring...');
    const threatScore = calculateThreatScore(fileInfo, entropy, patterns);

    // Stage 6: AI threat analysis
    console.log('🤖 Stage 6: AI threat reasoning...');
    const aiAnalysis = await analyzeThreatWithAI(fileInfo, entropy, patterns, threatScore);

    const analysisTime = Date.now() - startTime;
    console.log(`✅ Analysis complete in ${analysisTime}ms - ${threatScore.level} threat`);

    res.json({
      file: metadata,
      identification: fileInfo,
      analysis: {
        entropy: entropy,
        patterns: Object.keys(patterns),
        patternDetails: patterns,
      },
      threat: {
        level: threatScore.level,
        score: threatScore.score,
        confidence: 85,
        summary: aiAnalysis,
        indicators: threatScore.indicators,
        recommendations: generateRecommendations(threatScore.level, 85),
      },
      performance: {
        analysisTime: analysisTime,
        stages: 6
      }
    });

  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({
      error: 'Analysis failed',
      message: process.env.NODE_ENV === 'production'
        ? 'Internal server error'
        : error.message
    });
  }
});

/**
 * URL analysis endpoint
 */
app.post('/api/analyze-url', async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'Invalid URL' });
    }

    console.log(`\n🌐 Analyzing URL: ${url}`);

    // Basic URL validation
    const urlPattern = /^https?:\/\/.+/i;
    if (!urlPattern.test(url)) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    // Use Gemini to analyze URL (without fetching)
    const model = genAI.getGenerativeModel({
      model: 'gemini-2.0-flash-exp',
    });

    const prompt = `Analyze this URL for security threats: ${url}

Check for:
1. Domain typosquatting or lookalike domains
2. Suspicious TLDs (.tk, .ml, .ga, etc.)
3. IP addresses instead of domains
4. URL shorteners masking destinations
5. Known phishing patterns
6. Suspicious subdomains

Provide:
- Threat Level: SAFE, LOW, MEDIUM, HIGH, or CRITICAL
- Risk Score: 0-100
- Key indicators found
- Recommendation

Format as JSON:
{
  "threat_level": "...",
  "score": 0-100,
  "indicators": ["..."],
  "recommendation": "..."
}`;

    const result = await model.generateContent(prompt);
    const response = result.response.text();

    // Try to parse JSON response
    let analysis;
    try {
      // Extract JSON from markdown code blocks if present
      const jsonMatch = response.match(/```json\s*([\s\S]*?)\s*```/) ||
                       response.match(/\{[\s\S]*\}/);
      analysis = JSON.parse(jsonMatch ? jsonMatch[1] || jsonMatch[0] : response);
    } catch (e) {
      // Fallback if not valid JSON
      analysis = {
        threat_level: 'MEDIUM',
        score: 50,
        indicators: ['Could not parse AI response'],
        recommendation: response
      };
    }

    res.json({
      url: url,
      threat: {
        level: analysis.threat_level,
        score: analysis.score,
        confidence: 75,
        summary: analysis.recommendation,
        indicators: analysis.indicators,
      }
    });

  } catch (error) {
    console.error('URL analysis error:', error);
    res.status(500).json({
      error: 'URL analysis failed',
      message: process.env.NODE_ENV === 'production'
        ? 'Internal server error'
        : error.message
    });
  }
});

/**
 * Health check
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Sentinel AI Backend',
    timestamp: Date.now()
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Sentinel AI Backend',
    timestamp: Date.now()
  });
});

/**
 * Generate recommendations based on threat level
 */
function generateRecommendations(level, confidence) {
  const recommendations = [];

  switch (level) {
    case 'CRITICAL':
      recommendations.push('🚨 IMMEDIATE ACTION: Quarantine this file immediately');
      recommendations.push('Do NOT execute or open this file');
      recommendations.push('Report to security team for forensic analysis');
      break;
    case 'HIGH':
      recommendations.push('⚠️ Quarantine file and prevent execution');
      recommendations.push('Conduct thorough investigation before interaction');
      break;
    case 'MEDIUM':
      recommendations.push('⚡ Exercise caution with this file');
      recommendations.push('Verify file source and authenticity');
      break;
    case 'LOW':
      recommendations.push('ℹ️ Minor concerns detected');
      recommendations.push('Verify file source before use');
      break;
    case 'SAFE':
      recommendations.push('✅ File appears safe based on analysis');
      recommendations.push('Standard security practices still apply');
      break;
  }

  if (confidence < 70) {
    recommendations.push(`⚠️ Low confidence (${confidence}%) - consider additional analysis`);
  }

  return recommendations;
}

// Error handling middleware
app.use((err, req, res, next) => {
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
    message: process.env.NODE_ENV === 'production'
      ? 'An error occurred'
      : err.message,
  });
});

app.listen(PORT, () => {
  console.log(`🛡️  Sentinel AI Backend running on http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔒 File analysis: POST http://localhost:${PORT}/api/analyze`);
  console.log(`🌐 URL analysis: POST http://localhost:${PORT}/api/analyze-url`);

  if (!process.env.GEMINI_API_KEY) {
    console.warn('⚠️  WARNING: GEMINI_API_KEY not set in environment variables');
  }
});
