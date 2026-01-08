# 🛡️ SENTINEL

**AI-Powered Predictive File Security**

*"Security that thinks like an attacker, before the attack happens."*

Sentinel uses Google's Gemini AI to analyze files and predict potential security threats BEFORE they execute, using behavioral reasoning and pattern analysis.

## 🎯 Features

- **Behavioral Prediction**: Analyzes how files interact with systems and predicts attack vectors before execution
- **Zero-Day Detection**: Identifies novel exploitation techniques through AI reasoning, even without known signatures
- **Explainable Security**: Provides clear, technical explanations of threats with natural language reasoning
- **Multi-Layer Analysis**: Combines entropy calculation, header validation, structure parsing, and AI threat modeling

## 🏗️ Architecture

```
sentinel-AI/
├── frontend/          # React + TypeScript + Tailwind 4
│   ├── src/
│   │   ├── components/    # FileUpload, ThreatCard, AnalysisPipeline
│   │   ├── hooks/         # useFileAnalysis
│   │   ├── types/         # TypeScript definitions
│   │   └── api/           # Backend API client
│   └── ...
│
├── backend/           # Node.js + Express + TypeScript
│   ├── src/
│   │   ├── analyzers/     # Metadata, Entropy, Header validation
│   │   ├── services/      # File analyzer, Gemini client
│   │   ├── config/        # System prompts
│   │   └── server.ts      # Express server
│   └── ...
│
└── package.json       # Monorepo root
```

## 🚀 Quick Start

### Prerequisites

- Node.js 18+
- npm or yarn
- Google Gemini API key

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/sentinel-AI.git
cd sentinel-AI
```

2. Install dependencies:
```bash
npm install
cd frontend && npm install
cd ../backend && npm install
```

3. Set up environment variables:

Backend (`.env`):
```env
PORT=5000
GEMINI_API_KEY=your_gemini_api_key_here
NODE_ENV=development
MAX_FILE_SIZE=10485760
```

Frontend (`.env`):
```env
VITE_API_URL=/api
```

### Running the Application

**Development mode (both frontend and backend):**
```bash
npm run dev
```

**Or run separately:**

Backend:
```bash
cd backend
npm run dev
```

Frontend:
```bash
cd frontend
npm run dev
```

The frontend will be available at `http://localhost:3000`
The backend API at `http://localhost:5000`

## 🧪 How It Works

1. **Upload**: User uploads a file through the web interface
2. **Metadata Extraction**: Extract file metadata, timestamps, hash
3. **Entropy Analysis**: Calculate Shannon entropy to detect encryption/obfuscation
4. **Header Validation**: Check if file headers match the claimed file type
5. **Structure Parsing**: Extract strings, detect suspicious API calls
6. **AI Analysis**: Gemini AI performs behavioral threat prediction
7. **Results**: Display threat level, confidence, attack vectors, and recommendations

## 📊 Analysis Pipeline

```
File Upload
    ↓
Metadata Extraction (SHA-256, timestamps)
    ↓
Entropy Calculation (0-8 scale)
    ↓
Header Validation (magic numbers)
    ↓
Structure Parsing (API detection, strings)
    ↓
Gemini AI Threat Analysis
    ↓
Threat Report (Level, Confidence, Recommendations)
```

## 🎓 Tech Stack

**Frontend:**
- React 18
- TypeScript
- Tailwind CSS 4
- Vite
- Axios
- Lucide Icons

**Backend:**
- Node.js
- Express
- TypeScript
- Google Generative AI SDK
- Multer (file uploads)

## 🔒 Security Features

- Entropy-based obfuscation detection
- File header validation (magic number matching)
- Suspicious API call detection
- Double extension detection
- AI-powered behavioral analysis
- Explainable threat reasoning

## 📝 License

MIT

## 🙏 Acknowledgments

- Powered by Google Gemini AI
- Built for security professionals and developers

---

**⚠️ Disclaimer**: Sentinel is a security analysis tool for educational and professional use. Always follow responsible disclosure practices and obtain proper authorization before analyzing files.
