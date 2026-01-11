# 🛡️ SENTINEL AI

**The Marathon Security Agent That Never Sleeps — Predicting Threats Before They Execute**

_"Autonomous threat reasoning running 24/7, continuously learning, never stopping."_

[![Gemini API](https://img.shields.io/badge/Powered%20by-Gemini%203%20Flash-blue)](https://ai.google.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-18-61dafb)](https://reactjs.org/)

## 🧠 Judge TL;DR

**Sentinel AI is a long-running autonomous security agent that uses Gemini 3 Flash to predict how files and URLs will behave before execution.**

- **No sandboxing** — predicts behavior without running code
- **No signature matching** — pure reasoning from structure, entropy, and context
- **Runs continuously for days** — learning baselines and self-correcting
- **Marathon Agent** — 6-stage investigation loops with autonomous quarantine decisions

**Demo in under 2 minutes:**
Run `npm run marathon-demo`, drop files into the watch folder, watch the agent reason in real time with live status reports.

---

**Sentinel AI is a Marathon Security Agent built for the Gemini 3 Global Hackathon's "Action Era"** - an autonomous system that continuously monitors, analyzes, and responds to security threats across days and weeks. Unlike traditional one-shot scanners, Sentinel runs multi-day investigation loops, learns from false positives, and maintains threat context across extended operations.

> **Marathon Agent Track**: Demonstrates autonomous multi-day workflows with self-correction, continuous monitoring, and long-running investigation chains using Gemini 3 Flash's advanced reasoning capabilities.

---

## 🎯 What is Sentinel?

Sentinel is a **Marathon Security Agent** - an autonomous system that runs continuously for days/weeks, not seconds. It:

### 🏃 Marathon Capabilities (Action Era)

- **Continuous Monitoring**: Watches directories 24/7, analyzing new threats as they appear
- **Long-Running Investigations**: Multi-stage analysis loops that iterate dozens of times with self-correction
- **Temporal Learning**: Builds threat baselines over days, detecting anomalies based on historical patterns
- **Autonomous Decision-Making**: Quarantines threats, adjusts sensitivity, and self-improves without human intervention

### 🧠 Advanced Threat Detection

- **Zero-Day Malware**: Identifies novel threats through reasoning, not signatures
- **Hidden Payloads**: Detects steganography, polyglots, and embedded executables
- **Malicious URLs**: Analyzes phishing sites and suspicious web content
- **Multi-Agent Debate**: Prosecutor/Defense/Judge system for high-confidence verdicts

Unlike traditional one-shot scanners, Sentinel **never stops** - it's designed for extended autonomous operation with continuous learning and self-correction.

---

## 🚀 Quick Start

### Option 1: Marathon Mode (Recommended for Demo)

Experience autonomous multi-day security monitoring:

```bash
cd backend
npm install
npm run marathon-demo
```

The agent runs continuously, analyzing files as they appear. **Drop test files into `marathon-demo-watch/` and watch it work!**

See [MARATHON_MODE.md](./MARATHON_MODE.md) for full details.

### Option 2: Single File Analysis

```bash
# Backend
cd backend
npm install
npm run dev

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

Visit http://localhost:3000 and upload files or URLs for analysis.

---

## 🧠 Why I Built This

### The Background: From SEAL to Sentinel

This project evolved from my work on **SEAL** (Self-Encrypting Autonomous Layer), a file format with embedded post-breach security. SEAL files can detect unauthorized access and self-destruct after database breaches - they're autonomous and self-protecting.

While building SEAL, I realized something: **we're always fighting threats after they've already gotten in**. Post-breach security is reactive. What if we could predict threats _before_ they execute?

That question led to Sentinel - a pre-breach prediction system that uses AI to reason about file behavior before anything runs.

### The Marathon Mode Evolution

For the Gemini 3 Hackathon's "Action Era" focus, I extended Sentinel into a **Marathon Agent** - transforming one-shot analysis into continuous autonomous monitoring that runs for hours, days, or weeks with self-learning capabilities.

### The Philosophy

- **SEAL**: Files that protect themselves after a breach (reactive)
- **Sentinel Single Mode**: AI that predicts threats before execution (proactive)
- **Sentinel Marathon Mode**: Autonomous agent that never stops learning and protecting (Action Era)

All share the same philosophy: **security should be intelligent and autonomous**, not just reactive rule-matching.

---

## 💡 What I Learned

### 1. **The False Positive Crisis**

Early versions of Sentinel had a major problem: **legitimate HEIC images from iPhones were flagged as CRITICAL threats**.

Why? Because:

- HEIC files have 7.2-7.99 entropy (very high, looks like encryption)
- The magic bytes are at offset 4, not offset 0 (my validator missed them)
- Unknown formats were automatically labeled "SUSPICIOUS"

This taught me that **context matters more than raw metrics**. A JPEG with 7.5 entropy is normal. A Word doc with 7.5 entropy is malware.

**Solution**: Built format-specific entropy baselines and offset-aware magic byte detection. Now Sentinel knows what's normal for each file type.

### 2. **AI Reasoning ≠ AI Summarization**

Initially, Sentinel was just using Gemini to summarize static analysis results. The hackathon feedback was harsh: _"Gemini is window dressing - it's just a fancy text summarizer. 5.6/10."_

They were right. I was feeding Gemini analysis results and asking it to make them sound smart. That's not AI innovation.

**The Fix**: Changed how I use Gemini entirely:

**Before:**

```
"Here's the analysis: entropy=7.8, unknown format, suspicious APIs.
Please summarize this as a threat report."
```

**After:**

```
"Given this file's behavior, what would happen if executed?
Predict: file operations, network activity, registry changes.
Reason through potential attack vectors."
```

Now Gemini **reasons** about threats instead of just summarizing data. That's the difference between a glorified template engine and actual AI security analysis.

### 3. **Multi-Stage Pipelines > Monolithic Analysis**

From my SEAL project, I learned that file security needs multiple specialized layers. You can't just run one "checkForMalware()" function.

Sentinel's **11-stage pipeline** breaks analysis into specialized modules:

1. Magic byte detection
2. Container parsing (ISOBMFF, RIFF)
3. Metadata extraction
4. Entropy baseline analysis
5. Threat scoring with weighted indicators
6. Steganography detection
7. Polyglot detection
8. Payload hunting
9. VirusTotal validation
10. AI threat reasoning
11. Sandbox behavior prediction

Each stage is independent and testable. If one breaks, the others still work.

### 4. **URL Analysis is Harder Than File Analysis**

Adding URL scanning seemed simple: "just fetch the HTML and analyze it." Wrong.

Real-world URLs are chaos:

- **Redirect chains**: Shortened links → CDN → final destination
- **Dynamic JavaScript**: Malicious code loads after page renders
- **Timeouts and failures**: Sites go down, firewalls block you
- **HTML parsing**: Extracting scripts/iframes/forms from malformed HTML

I spent hours debugging redirect loops, timeouts, and CORS issues. Files are deterministic. URLs are not.

### 5. **Speed vs Thoroughness Tradeoff**

I originally built a 3-agent debate system (Prosecutor → Defense → Judge) to show Gemini reasoning. It was cool, but **took 10-15 seconds per file**.

Users don't care about architectural cleverness if it's slow. I simplified to a single AI call with transparent reasoning: **3-5 seconds, same accuracy**.

Lesson: **Shipping beats sophistication.**

### 6. **Marathon Mode ≠ Serverless**

The biggest technical revelation came when designing Marathon Mode for the hackathon's "Action Era" track.

**The Problem**: I wanted continuous multi-day monitoring with learning capabilities. My first instinct was to deploy everything to Vercel (serverless) because it's free and easy.

**Reality Check**:
- Serverless functions have **time limits** (10-900 seconds max, depending on plan)
- Marathon Mode needs to run for **hours or days**
- Serverless filesystems are **ephemeral** - files disappear between invocations
- My learning baselines stored in `Map()` get wiped every request
- `chokidar` file watchers can't run persistent background processes

**The Solution**: Hybrid architecture
- **Web UI on Vercel** (serverless) - Perfect for one-shot file uploads
- **Marathon Mode on VPS** (traditional server) - Needed for continuous operation

This taught me that **not everything belongs in serverless**. Some problems require persistent state, long-running processes, and traditional server architectures. Choose the right tool for the job.

---

## 🔧 Technical Challenges I Faced

### Challenge 1: HEIC Detection at Offset 4

**Problem**: HEIC/HEIF/AVIF files have magic bytes at offset 4 (`ftyp`), not offset 0. My validator only checked offset 0, so all iPhone photos were "unknown format."

**Solution**: Built offset-aware signature matching:

```typescript
const SIGNATURES = [
  { ext: "heic", magic: [0x66, 0x74, 0x79, 0x70], offset: 4 },
  { ext: "jpeg", magic: [0xff, 0xd8, 0xff], offset: 0 },
  // ...
];
```

Then created an ISOBMFF parser to extract the `ftyp` brand (heic, heix, hevc, avif, etc.).

### Challenge 2: TypeScript Buffer Configuration

**Problem**: Node.js buffers don't work in TypeScript without proper config. Got constant errors:

```
Property 'from' does not exist on type 'Buffer'
```

**Solution**: Added to `tsconfig.json`:

```json
{
  "compilerOptions": {
    "types": ["node"],
    "lib": ["ES2022"]
  }
}
```

### Challenge 3: Context-Aware Pattern Matching

**Problem**: Searching for suspicious strings like "CreateProcess" flagged **every PDF** because PDF metadata contains those strings as text.

**Solution**: Built context-aware detection:

- Executables: Flag suspicious API calls in code sections
- PDFs: Ignore text content, only flag embedded executables
- Images: Flag appended executables or embedded scripts

The same string means different things depending on file type.

### Challenge 4: Balancing Speed and Thoroughness

**Problem**: Initial multi-agent AI debate system was thorough but slow (10-15 seconds).

**Solution**: Simplified to single AI call with structured reasoning. Still gets transparent explanations, 3x faster.

### Challenge 5: Marathon Mode Architecture for Serverless

**Problem**: Designed Marathon Mode with continuous file watching, learning baselines, and multi-day operation. Assumed I could deploy everything to Vercel for easy hosting.

**Reality**:

```typescript
// This doesn't work on Vercel
this.watcher = chokidar.watch(watchPath, { persistent: true });
this.threatBaselines = new Map(); // Wiped between requests
maxRuntime: 30 * 60 * 1000; // 30 minutes (Vercel max: 15 min)
```

Serverless platforms:

- Kill functions after 10-900 seconds
- Have ephemeral filesystems (no persistent storage)
- Don't support background processes
- Reset memory between invocations

**Solution**: Hybrid deployment strategy

- **Web UI + single-file API** → Vercel (perfect for one-shot analysis)
- **Marathon Mode** → VPS/traditional server (needed for persistent operation)
- Document both deployment paths clearly

This challenge taught me to **design with deployment constraints in mind from the start**, not as an afterthought.

---

## 🏗️ How It Works: 11-Stage Analysis Pipeline

```
📁 File Upload
    ↓
🔍 Stage 1: Magic Byte Detection
    • Offset-aware signature matching
    • Confidence scoring per match
    ↓
📦 Stage 2: Container Parsing (ISOBMFF, RIFF)
    • Parse ftyp boxes for HEIC/AVIF/MP4
    • Validate structure integrity
    ↓
📋 Stage 3: Metadata Extraction
    • SHA-256 hash, file size, timestamps
    • Permission flags
    ↓
📊 Stage 4: Entropy Baseline Analysis
    • Calculate Shannon entropy (0-8)
    • Compare against format-specific baselines
    • Flag abnormal entropy for file type
    ↓
⚖️ Stage 5: Weighted Threat Scoring
    • Positive indicators: -20 for valid format
    • Negative indicators: +70 for extension mismatch
    • Normalize to 0-100 risk score
    ↓
🖼️ Stage 6: Steganography Detection
    • JPEG LSB analysis
    • PNG text chunk extraction
    • Appended data after EOI/IEND markers
    ↓
🔀 Stage 7: Polyglot Detection
    • Detect files valid as multiple formats
    • Flag dangerous combos (PDF+JS, JPEG+PE)
    ↓
💣 Stage 8: Payload Hunter
    • Shellcode pattern detection
    • Base64 embedded executables
    • PE headers in non-executable files
    ↓
🛡️ Stage 9: VirusTotal Integration
    • Check SHA-256 against 70+ AV engines
    • Return detection count and permalink
    ↓
🤖 Stage 10: AI Threat Reasoning
    • Gemini 3 Flash analyzes all evidence
    • Predicts attack vectors and behaviors
    • Provides explainable threat assessment
    ↓
🧪 Stage 11: Sandbox Behavior Prediction
    • AI predicts file/network/registry operations
    • Simulates execution without running code
    • Risk score 0-100 with behavior summary
    ↓
📊 Threat Report Generated
```

---

## ✨ Key Features

### 🎯 Core Analysis

- **Multi-Layer File Identification**: Magic bytes, container parsing, structure validation
- **Format-Specific Baselines**: Context-aware entropy analysis (knows HEIC ≠ malware)
- **Weighted Threat Scoring**: Evidence-based indicators with confidence levels
- **Explainable AI**: Clear reasoning for every threat assessment

### 🔍 Advanced Detection

- **Steganography Detection**: LSB extraction, hidden chunks, appended data
- **Polyglot Detection**: Files valid as multiple formats simultaneously
- **Payload Hunter**: Shellcode, Base64 executables, embedded PE headers
- **Extension Mismatch**: Catches .jpg.exe and format spoofing

### 🌐 External Validation

- **VirusTotal Integration**: Check files against 70+ antivirus engines
- **URL Analysis**: Fetch, redirect tracking, HTML parsing, script extraction
- **Sandbox Prediction**: AI predicts execution behavior without running code

### 🛠️ User Features

- **Comparison Mode**: Side-by-side analysis of two files
- **Analysis Side Panel**: Detailed technical view with entropy, structure, indicators
- **Real-Time Pipeline**: Visual progress updates during analysis
- **Export Results**: Save analysis reports (JSON format)

---

## 🏗️ Architecture

```
sentinel-AI/
├── frontend/                    # React + TypeScript + Tailwind
│   ├── src/
│   │   ├── components/
│   │   │   ├── FileUpload.tsx          # Drag-drop file input
│   │   │   ├── URLInput.tsx            # URL analysis input
│   │   │   ├── ThreatCard.tsx          # Main results display
│   │   │   ├── AnalysisPipeline.tsx    # Live progress tracker
│   │   │   └── AnalysisSidePanel.tsx   # Technical details panel
│   │   ├── pages/
│   │   │   ├── HomePage.tsx            # Main upload page
│   │   │   ├── ResultsPage.tsx         # Analysis results
│   │   │   └── ComparisonPage.tsx      # Side-by-side comparison
│   │   ├── hooks/
│   │   │   └── useFileAnalysis.ts      # Analysis state management
│   │   ├── api/
│   │   │   └── sentinelApi.ts          # Backend API client
│   │   └── types/
│   │       └── analysis.ts             # TypeScript definitions
│   └── ...
│
├── backend/                     # Node.js + Express + TypeScript
│   ├── src/
│   │   ├── analyzers/
│   │   │   ├── magic-bytes.ts          # Offset-aware signature detection
│   │   │   ├── isobmff-parser.ts       # HEIC/AVIF container parsing
│   │   │   ├── file-identifier.ts      # Multi-layer file type detection
│   │   │   ├── format-baselines.ts     # Expected characteristics per format
│   │   │   ├── threat-scorer.ts        # Weighted evidence scoring
│   │   │   ├── steganography-detector.ts
│   │   │   ├── polyglot-detector.ts
│   │   │   ├── payload-hunter.ts
│   │   │   ├── metadata-extractor.ts
│   │   │   ├── structure-parser.ts
│   │   │   └── header-validator.ts
│   │   ├── services/
│   │   │   ├── file-analyzer.ts        # Main pipeline orchestrator
│   │   │   ├── gemini-client.ts        # AI threat reasoning
│   │   │   ├── virustotal-client.ts    # AV engine integration
│   │   │   ├── sandbox-predictor.ts    # Behavior prediction
│   │   │   └── url-analyzer.ts         # URL fetching and analysis
│   │   ├── config/
│   │   │   └── prompts.ts              # AI system prompts
│   │   ├── types/
│   │   │   └── index.ts                # Shared type definitions
│   │   └── server.ts                   # Express API server
│   └── ...
│
└── package.json                 # Monorepo root
```

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** 18+
- **npm** or **yarn**
- **Google Gemini API key** ([Get one here](https://ai.google.dev/))
- **VirusTotal API key** (optional) ([Get one here](https://www.virustotal.com/gui/join-us))

### Installation

1. **Clone the repository:**

```bash
git clone https://github.com/yourusername/sentinel-AI.git
cd sentinel-AI
```

2. **Install dependencies:**

```bash
npm install
cd frontend && npm install
cd ../backend && npm install
cd ..
```

3. **Set up environment variables:**

Create `backend/.env`:

```env
PORT=5050
GEMINI_API_KEY=your_gemini_api_key_here
NODE_ENV=development
MAX_FILE_SIZE=10485760

# VirusTotal (optional - free tier: 500 requests/day, 4 requests/minute)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

Create `frontend/.env`:

```env
VITE_API_URL=/api
```

### Running the Application

**Development mode (runs both frontend and backend):**

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

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:5050

---

## 📊 Usage

### Analyze a File

1. Drag and drop a file onto the upload zone
2. Click "Analyze File"
3. Watch the real-time pipeline progress
4. View threat report with:
   - Threat level (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
   - Confidence score
   - Attack vector predictions
   - VirusTotal results (if enabled)
   - Sandbox behavior prediction
   - Steganography detection
   - Technical details in side panel

### Analyze a URL

1. Click "Analyze URL" tab
2. Enter a URL (http:// or https://)
3. Sentinel will:
   - Follow redirect chains
   - Download HTML content
   - Extract scripts, iframes, forms
   - Analyze for phishing/malicious patterns

### Compare Two Files

1. Click "Compare Files" in the header
2. Upload two files (File A and File B)
3. Click "Analyze Both Files"
4. View side-by-side comparison with:
   - Threat level differences
   - Confidence comparison
   - Key differences (steganography, VirusTotal, etc.)

---

## 🎓 Tech Stack

### Frontend

- **React** 18 - UI framework
- **TypeScript** - Type safety
- **Tailwind CSS** 4 - Styling
- **Vite** - Build tool
- **React Router** - Navigation
- **Axios** - HTTP client
- **Lucide Icons** - Icons

### Backend

- **Node.js** - Runtime
- **Express** - Web framework
- **TypeScript** - Type safety
- **Google Generative AI SDK** - Gemini API
- **Multer** - File upload handling
- **Axios** - HTTP client (for URL analysis)

### AI & Security

- **Gemini 3 Flash** - Threat reasoning, behavior prediction
- **VirusTotal API** - AV engine validation (optional)
- **Shannon Entropy** - Obfuscation detection
- **Magic Byte Database** - File type identification

---

## 🔒 Security Features Breakdown

### File Analysis

- ✅ Magic byte validation (30+ formats)
- ✅ Offset-aware signature detection (HEIC, AVIF, etc.)
- ✅ Container parsing (ISOBMFF, RIFF)
- ✅ Format-specific entropy baselines
- ✅ Extension/content mismatch detection
- ✅ Suspicious API call detection (CreateProcess, WriteFile, etc.)
- ✅ Double extension pattern detection (.jpg.exe)

### Advanced Threats

- ✅ Steganography detection (LSB, PNG chunks, appended data)
- ✅ Polyglot file detection (valid as multiple formats)
- ✅ Embedded payload detection (shellcode, Base64 executables)
- ✅ PE header detection in non-executables

### External Validation

- ✅ VirusTotal integration (70+ AV engines)
- ✅ URL redirect chain tracking
- ✅ HTML script/iframe extraction
- ✅ Form action analysis

### AI Capabilities

- ✅ Behavioral threat reasoning
- ✅ Attack vector prediction
- ✅ Sandbox simulation (without execution)
- ✅ Zero-day pattern recognition
- ✅ Explainable threat assessment

---

## 🚧 Future Roadmap

### Phase 1: Browser Extension

- **Chrome Extension**: Analyze downloads before they hit disk
- Right-click context menu for files
- Real-time URL scanning before navigation
- Badge notifications for threat levels

### Phase 2: Email Integration

- **Email Attachment Scanner**: Outlook/Gmail plugins
- Inline analysis of attachments before opening
- Phishing link detection in email bodies
- Sender reputation analysis

### Phase 3: Advanced Detection

- **YARA Rule Integration**: Custom pattern matching
- **Machine Learning Model**: Train on malware corpus
- **Behavioral Monitoring**: Track file operations after execution
- **Network Traffic Analysis**: Deep packet inspection

### Phase 4: Enterprise Features

- **API Access**: RESTful API for enterprise integration
- **Batch Analysis**: Scan entire directories
- **Historical Database**: Track threats over time
- **Custom Alerts**: Webhook notifications

---

## 🧪 Testing with Malicious Samples

**⚠️ WARNING**: Only test with authorized malware samples. Use VM environments.

### Safe Test Sources:

- **EICAR Test File**: Standard AV test file (not actual malware)
- **MalwareBazaar**: https://bazaar.abuse.ch/
- **VirusTotal**: https://www.virustotal.com/gui/home/search
- **TheZoo**: Malware repository for researchers (use with caution)

### Test Scenarios:

1. **HEIC Image**: Should be SAFE (not HIGH like early versions)
2. **JPEG Image**: Should be SAFE despite high entropy
3. **Extension Mismatch**: Rename .exe to .jpg → Should be CRITICAL
4. **EICAR Test File**: Should detect as CRITICAL with clear indicators
5. **Polyglot File**: Create PDF+JS → Should flag as polyglot

---

## 📝 API Documentation

### POST `/api/analyze`

Upload and analyze a file.

**Request:**

```bash
curl -X POST http://localhost:5050/api/analyze \
  -F "file=@suspicious.exe"
```

**Response:**

```json
{
  "file": {
    "filename": "suspicious.exe",
    "size": 102400,
    "hash": "a1b2c3d4..."
  },
  "analysis": {
    "entropy": 7.92,
    "headerValid": { "match": true, "suspicious": false }
  },
  "threat": {
    "level": "HIGH",
    "confidence": 87,
    "summary": "Executable with suspicious API calls",
    "indicators": ["CreateProcess", "WriteFile"],
    "virusTotal": {
      "detections": 42,
      "totalEngines": 70
    },
    "sandboxPrediction": {
      "riskScore": 85,
      "fileOperations": ["Create C:\\Windows\\Temp\\payload.dll"],
      "networkActivity": ["Connect to 192.168.1.1:4444"]
    }
  }
}
```

### POST `/api/analyze-url`

Analyze a URL for phishing/malicious content.

**Request:**

```bash
curl -X POST http://localhost:5050/api/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

---

## 🏆 Hackathon Submission Details

**Event**: Gemini 3 Global Hackathon
**Track**: Security & Defense
**Prize Pool**: $100,000
**Team Size**: Solo

**Innovation Highlights**:

1. **AI Threat Reasoning**: Uses Gemini for behavioral prediction, not just text summarization
2. **Sandbox Prediction**: Simulates execution without running code (novel approach)
3. **Context-Aware Analysis**: Format-specific baselines prevent false positives
4. **Multi-Layer Detection**: 11-stage pipeline with specialized modules
5. **Explainable Security**: Clear reasoning for every threat assessment

**Prompt Response**: _"Build a NEW application using the Gemini 3 API... Build a game, a productivity tool, a scientific analyzer..."_

Sentinel AI is a **scientific security analyzer** that uses Gemini's reasoning capabilities to predict threats before execution.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-detection`)
3. Commit changes (`git commit -m 'Add polyglot detection'`)
4. Push to branch (`git push origin feature/amazing-detection`)
5. Open a Pull Request

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- **Google Gemini Team** - For the incredible AI API that makes behavioral reasoning possible
- **VirusTotal** - For the free API tier and malware database
- **Security Researchers** - For open-sourcing detection techniques and malware analysis methodologies

---

## ⚠️ Disclaimer

Sentinel AI is a **security analysis tool for educational and professional use**.

- ✅ **Authorized Use**: Security research, malware analysis, CTF competitions, pentesting
- ❌ **Prohibited Use**: Analyzing files without authorization, distributing malware, bypassing security

**Always follow responsible disclosure practices and obtain proper authorization before analyzing files.**

---

## 📧 Contact

Built by **endga** for the Gemini 3 Global Hackathon.

- **GitHub**: [Your GitHub Profile]
- **Email**: [Your Email]
- **Project Link**: https://github.com/yourusername/sentinel-AI

---

**Made with 🛡️ by a security enthusiast who believes AI should predict threats, not just summarize them.**
