const express = require('express');
const cors = require('cors');
const { GoogleGenerativeAI } = require('@google/generative-ai');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Initialize Gemini
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// System prompt for email analysis
const SYSTEM_PROMPT = `You are Sentinel AI, an expert cybersecurity analyst specializing in detecting phishing, fraud, manipulation, and scam emails.

Analyze the provided email and return a JSON response with the following structure:
{
  "risk_level": "SAFE" | "SUSPICIOUS" | "HIGH_RISK",
  "score": 0-100 (higher = more dangerous),
  "summary": "Brief explanation of the analysis",
  "signals": ["Array of specific red flags or safe indicators"],
  "recommendation": "Clear actionable advice for the user"
}

Look for:
- Phishing indicators (fake domains, impersonation, spoofing)
- Urgency tactics (time pressure, threats, fear)
- Authority manipulation (fake officials, false credentials)
- Financial scams (wire transfers, gift cards, crypto)
- Emotional manipulation (guilt, fear, greed)
- Technical signs (mismatched URLs, suspicious attachments)

Be thorough but concise. If the email is safe, say so clearly.`;

// Analysis endpoint
app.post('/api/analyze', async (req, res) => {
  try {
    const { subject, sender, body } = req.body;

    if (!subject || !sender || !body) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Construct the email payload
    const emailText = `
SUBJECT: ${subject}
FROM: ${sender}
BODY:
${body}
    `.trim();

    // Call Gemini
    const model = genAI.getGenerativeModel({ 
      model: 'gemini-1.5-flash',
      generationConfig: {
        responseMimeType: 'application/json'
      }
    });

    const result = await model.generateContent([
      { text: SYSTEM_PROMPT },
      { text: `\n\nAnalyze this email:\n\n${emailText}` }
    ]);

    const response = result.response;
    const analysisText = response.text();
    
    // Parse the JSON response
    const analysis = JSON.parse(analysisText);

    res.json(analysis);
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ 
      error: 'Analysis failed',
      message: error.message 
    });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'Sentinel AI Backend' });
});

app.listen(PORT, () => {
  console.log(`🛡️  Sentinel AI Backend running on http://localhost:${PORT}`);
});
