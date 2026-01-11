# About Sentinel AI

**My Journey Building a Marathon Security Agent for the Gemini 3 Hackathon**

---

## 💡 What Inspired Me

### The Background: From SEAL to Sentinel

I've been working on **SEAL** (Self-Encrypting Autonomous Layer), a file format that embeds post-breach security directly into files themselves. SEAL files are autonomous — they can detect unauthorized database breaches and self-destruct to prevent data leaks. It's a radical approach to security: instead of protecting the perimeter, protect the data itself.

But while building SEAL, I kept coming back to the same frustrating realization: **we're always fighting threats after they've already gotten in**.

Post-breach security is fundamentally reactive. By the time SEAL detects unauthorized access, the attacker is already inside your system. What if we could predict threats *before* they execute? What if AI could reason about file behavior and catch malware before it runs?

That question became Sentinel.

### The Gemini 3 "Action Era" Spark

When Google announced the Gemini 3 Hackathon with its focus on the **"Action Era"** — autonomous agents that run for hours or days with self-correction — something clicked.

Traditional security tools are one-shot analyzers:
1. Scan file
2. Report result
3. Done

But real threats evolve. Attackers iterate. False positives pile up. Security needs **continuous reasoning**, not just instant verdicts.

I realized I could extend Sentinel from a one-shot analyzer into a **Marathon Agent** — a system that never stops, learns from mistakes, and improves its threat detection over time through autonomous operation.

That's when Sentinel AI was born.

---

## 🎓 What I Learned

### 1. The False Positive Crisis

Early versions of Sentinel had a catastrophic problem: **every HEIC image from my iPhone was flagged as a CRITICAL threat**.

At first, I thought it was a bug. But when I dug deeper, I realized it was a fundamental design flaw in how I was thinking about threat detection.

**The Problem:**
- HEIC files have 7.2-7.99 Shannon entropy (extremely high, looks like encrypted malware)
- The magic bytes are at **offset 4**, not offset 0 (my validator missed them entirely)
- My system automatically labeled unknown formats as "SUSPICIOUS"
- I was measuring entropy without understanding what "normal" means for each format

**The Lesson:**
Raw metrics mean nothing without context. A JPEG with 7.5 entropy is perfectly normal — it's compressed image data. A Word document with 7.5 entropy is malware — documents shouldn't be that random.

I rebuilt the entire validation system with:
- **Offset-aware magic byte detection** (checking bytes at arbitrary positions)
- **Format-specific entropy baselines** (HEIC: 7.2-7.99 is normal, PE: >7.0 is suspicious)
- **ISOBMFF container parsing** to properly identify modern image formats

This taught me that **context matters more than raw numbers**. Security isn't about thresholds — it's about understanding what's normal for each file type.

### 2. AI Reasoning ≠ AI Summarization

My initial Gemini integration was embarrassingly naive. I was using AI as a glorified template engine:

```
"Here's the analysis: entropy=7.8, unknown format, suspicious APIs.
Please summarize this as a threat report."
```

The hackathon feedback was brutal but accurate: *"Gemini is just window dressing here. It's not reasoning, it's summarizing. 5.6/10."*

They were absolutely right.

**The Fix:**
I completely restructured how I use Gemini. Instead of feeding it conclusions to rewrite, I give it evidence and ask it to **reason**:

```
"Given this file's structure, entropy, and detected patterns,
what would happen if it were executed?

Predict:
- File operations (what would it create/modify?)
- Network activity (what would it connect to?)
- Registry changes (what persistence mechanisms?)

Reason through the attack vector."
```

Now Gemini analyzes behavior instead of rephrasing my analysis. That's the difference between AI innovation and AI window dressing.

**Key Insight:** Don't ask AI to make your results sound smart. Ask AI to solve problems you can't solve statically.

### 3. Multi-Stage Pipelines Beat Monolithic Analysis

From my SEAL project, I learned that security needs specialized layers. You can't just write one `checkForMalware()` function and call it a day.

Sentinel uses an **11-stage pipeline**:
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

Each stage is independent and testable. If the VirusTotal API goes down, the other 10 stages still work. If Gemini times out, I still have static analysis results.

**Lesson:** Modularity isn't just good software engineering — it's critical for reliability in security tools.

### 4. URL Analysis is Harder Than File Analysis

Adding URL scanning seemed simple: "just fetch the HTML and analyze it."

I was spectacularly wrong.

Real-world URLs are chaos:
- **Redirect chains**: Shortened links → CDN → final destination (I spent hours debugging infinite redirect loops)
- **Dynamic JavaScript**: Malicious code that loads *after* the page renders
- **Timeouts and failures**: Sites go down, firewalls block you, DNS fails
- **Malformed HTML**: Parsing broken HTML without crashing is an art form

I spent more time debugging URL edge cases than I did building the entire file analysis pipeline.

**Lesson:** Files are deterministic. URLs are not. Never assume network operations will behave predictably.

### 5. Speed vs Thoroughness Tradeoff

I originally built a 3-agent debate system (Prosecutor → Defense → Judge) to showcase Gemini's reasoning. It was architecturally elegant and technically impressive.

It also took **10-15 seconds per file**.

Users don't care about architectural cleverness if it's too slow to use. I simplified to a single AI call with structured reasoning: **3-5 seconds, same accuracy**.

**Lesson:** Shipping beats sophistication. The best architecture is the one users will actually use.

### 6. Marathon Mode ≠ Serverless

The biggest technical revelation came when designing Marathon Mode for the "Action Era" track.

**My Assumption:**
I can deploy everything to Vercel because it's free, fast, and scales automatically.

**Reality Check:**
- Serverless functions have **time limits** (Vercel: 10-900 seconds depending on plan)
- Marathon Mode needs to run for **hours or days**
- Serverless filesystems are **ephemeral** — files disappear between invocations
- My learning baselines stored in `Map()` structures get wiped every request
- `chokidar` file watchers can't run persistent background processes

**The Solution:**
Hybrid architecture:
- **Web UI on Vercel** (serverless) — Perfect for one-shot file uploads
- **Marathon Mode on VPS** (traditional server) — Needed for continuous operation

**Lesson:** Not everything belongs in serverless. Some problems require persistent state, long-running processes, and traditional server architectures. Choose the right tool for the job, not the trendy tool.

---

## 🛠️ How I Built It

### Phase 1: Core File Analysis (Week 1)

Started with the fundamentals:

1. **Magic Byte Detection** (`magic-bytes.ts`)
   - Built a comprehensive signature database (30+ formats)
   - Implemented offset-aware matching (critical for HEIC at offset 4)
   - Added confidence scoring per match

2. **Container Parsing** (`isobmff-parser.ts`)
   - Wrote ISOBMFF parser for modern image formats (HEIC, AVIF, HEIF)
   - Extracted `ftyp` boxes to identify brand (heic, heix, hevc, etc.)
   - Validated container structure integrity

3. **Entropy Analysis** (`format-baselines.ts`)
   - Calculated Shannon entropy (0-8 scale)
   - Built format-specific baselines (HEIC: 7.2-7.99, JPEG: 6.8-7.8, PE: <7.0)
   - Flagged abnormal entropy for each type

### Phase 2: Advanced Threat Detection (Week 2)

Implemented novel detection modules:

1. **Steganography Detector** (`steganography-detector.ts`)
   - JPEG DCT coefficient LSB analysis
   - PNG ancillary chunk extraction (`tEXt`, `zTXt`, `iTXt`)
   - Appended data detection after EOI/IEND markers

2. **Polyglot Detector** (`polyglot-detector.ts`)
   - Detected files valid as multiple formats simultaneously
   - Flagged dangerous combinations (PDF+JavaScript, JPEG+PE)
   - Calculated security risk level

3. **Payload Hunter** (`payload-hunter.ts`)
   - Shellcode pattern detection (x86/x64 opcodes)
   - Base64 blob detection and decoding
   - Embedded PE header scanning
   - High-entropy region analysis

### Phase 3: External Integrations (Week 3)

Added external validation:

1. **VirusTotal Integration** (`virustotal-client.ts`)
   - SHA-256 hash checking against 70+ AV engines
   - Detections count and engine breakdown
   - Respects API rate limits (4 requests/minute on free tier)

2. **Sandbox Predictor** (`sandbox-predictor.ts`)
   - Uses Gemini to predict execution behavior *without running code*
   - Predicts: file operations, network activity, registry changes, process creation
   - Risk score 0-100 with behavior summary

### Phase 4: Marathon Mode (Week 4)

The big architectural shift:

1. **Marathon Agent** (`marathon-agent.ts`)
   - Built 6-stage autonomous investigation loop:
     1. Initial quick scan
     2. Suspicion detection (threshold: MEDIUM+)
     3. Deep investigation (multi-iteration self-correction)
     4. Learning application (adjust baselines)
     5. Final decision (multi-factor reasoning)
     6. Autonomous action (quarantine if needed)

2. **Continuous Learning System**
   - Threat baselines stored in `Map<fileType, baseline>`
   - Entropy ranges adjust with each new sample
   - Confidence increases over time (up to 100%)

3. **File Watcher Integration**
   - Uses `chokidar` for directory monitoring
   - Only watches NEW files (ignoreInitial: true) to save API tokens
   - Automatic quarantine to `.quarantine/` directory

### Phase 5: Frontend & Polish (Week 5)

Built the user interface:

1. **React Frontend** (TypeScript + Tailwind CSS)
   - File upload with drag-drop
   - URL input with validation
   - Real-time analysis pipeline visualization
   - Threat card with detailed results
   - Analysis side panel with technical details
   - Comparison mode for side-by-side analysis

2. **Integration Testing**
   - Tested with EICAR test file
   - Validated HEIC false positive fix
   - Tested polyglot detection with crafted samples
   - URL analysis with real phishing sites (in VM)

---

## 🚧 Challenges I Faced

### Challenge 1: HEIC Detection at Offset 4

**Problem:**
HEIC/HEIF/AVIF files have their magic bytes at offset 4, not offset 0. My validator only checked offset 0, so all iPhone photos were classified as "unknown format" and flagged as suspicious.

**Solution:**
```typescript
const SIGNATURES = [
  { ext: 'heic', magic: [0x66, 0x74, 0x79, 0x70], offset: 4 }, // 'ftyp'
  { ext: 'jpeg', magic: [0xFF, 0xD8, 0xFF], offset: 0 },
  // ...
];
```

Then built an ISOBMFF parser to extract the `ftyp` brand and validate container structure.

### Challenge 2: TypeScript Buffer Configuration

**Problem:**
Node.js buffers didn't work in TypeScript without proper configuration. Got constant errors:
```
Property 'from' does not exist on type 'Buffer'
```

**Solution:**
Added to `tsconfig.json`:
```json
{
  "compilerOptions": {
    "types": ["node"],
    "lib": ["ES2022"]
  }
}
```

### Challenge 3: Context-Aware Pattern Matching

**Problem:**
Searching for suspicious strings like "CreateProcess" flagged **every PDF** because PDF metadata often contains those strings as plain text.

**Solution:**
Built context-aware detection:
- **Executables**: Flag suspicious API calls in code sections
- **PDFs**: Ignore text content, only flag embedded executables
- **Images**: Flag appended executables or embedded scripts

The same string means different things depending on file type and location.

### Challenge 4: Balancing Speed and Thoroughness

**Problem:**
Initial multi-agent AI debate system (Prosecutor → Defense → Judge) was thorough but took 10-15 seconds per file.

**Solution:**
Simplified to single AI call with structured reasoning. Still provides transparent explanations, but 3x faster (3-5 seconds).

**Tradeoff:**
Less "impressive" architecture, but way more usable. Users care about results, not implementation elegance.

### Challenge 5: Marathon Mode Architecture for Serverless

**Problem:**
Designed Marathon Mode with continuous file watching, learning baselines, and multi-day operation. Naively assumed I could deploy everything to Vercel.

**Reality:**
```typescript
// This doesn't work on Vercel
this.watcher = chokidar.watch(watchPath, { persistent: true }); // Killed after 900s
this.threatBaselines = new Map(); // Wiped between requests
maxRuntime: 30 * 60 * 1000; // 30 minutes (Vercel max: 15 min)
```

Serverless platforms:
- Kill functions after 10-900 seconds
- Have ephemeral filesystems
- Don't support background processes
- Reset memory between invocations

**Solution:**
Hybrid deployment:
- **Web UI + single-file API** → Vercel (perfect for one-shot analysis)
- **Marathon Mode** → VPS/traditional server (needed for persistent operation)

**Lesson:**
Design with deployment constraints from the start, not as an afterthought.

### Challenge 6: Gemini API Rate Limits and Costs

**Problem:**
During development, I was making 100+ API calls per testing session. Costs added up quickly, and rate limits hit during peak testing.

**Solution:**
- Implemented aggressive caching for repeated file analyses
- Added `ignoreInitial: true` to file watcher (only analyze NEW files)
- Created mock responses for unit testing
- Added environment variable to skip Gemini in tests

**Lesson:**
Always design with API costs in mind. Every call costs money and counts against rate limits.

---

## 🏆 Why This Project Matters

Sentinel AI represents a shift in how we think about security:

### Traditional Approach:
1. Wait for malware to appear
2. Analyze signatures
3. Update signature database
4. Repeat

**Problem:** Always reactive. Zero-days slip through.

### Sentinel's Approach:
1. Reason about file structure and behavior
2. Predict what would happen if executed
3. Learn from false positives over time
4. Continuously improve without human intervention

**Advantage:** Proactive prediction, not reactive matching.

### Marathon Agent Capabilities:

- **Runs for days/weeks** without stopping
- **Self-corrects** when evidence is contradictory
- **Learns baselines** for each file type automatically
- **Autonomous decisions** (quarantine without human approval)
- **Temporal context** (knows what's normal based on history)

This aligns perfectly with Google's "Action Era" vision: autonomous systems that maintain continuity across multi-step tool calls without human supervision.

---

## 🚀 What's Next

### Immediate Post-Hackathon:
1. **Persistent storage** for threat baselines (save to JSON/database)
2. **Web dashboard** for live Marathon Mode metrics
3. **Historical analysis** to show learning improvements over time

### Future Vision:
1. **Chrome Extension** - Analyze downloads before they hit disk
2. **Email Integration** - Scan attachments inline in Gmail/Outlook
3. **YARA Rule Support** - Custom pattern matching for security teams
4. **ML Model Training** - Train on malware corpus for pattern recognition

---

## 🙏 Acknowledgments

- **Google Gemini Team** - For building an API that can actually reason about security threats, not just generate text
- **VirusTotal** - For the free API tier that made external validation possible
- **Security Research Community** - For openly sharing detection techniques and malware analysis methodologies

---

## 📝 Final Reflection

Building Sentinel taught me that **security isn't about perfect detection — it's about continuous improvement**.

Traditional security tools try to be right 100% of the time on day 1. They fail because threats evolve faster than signatures can be updated.

Sentinel embraces imperfection. It makes mistakes (HEIC false positives), learns from them (format-specific baselines), and gets better over time (confidence scoring). That's what makes it a Marathon Agent instead of a one-shot analyzer.

The "Action Era" isn't about building systems that never fail. It's about building systems that **learn from failure and keep improving autonomously**.

That's the future of security. That's Sentinel AI.

---

**Built with ❤️ for the Gemini 3 Global Hackathon**

*— endga, solo developer, believer in autonomous security*
