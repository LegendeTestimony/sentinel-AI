# Sentinel AI - Development Journey & Challenges

## Project Overview
Sentinel AI is a competition-entry malware detection system that uses AI (Google Gemini 2.5-flash) combined with advanced static analysis to identify threats in uploaded files. This document chronicles the real challenges I faced, the research that guided solutions, and the architectural decisions that transformed this from a basic scanner into a competition-grade detection system.

---

## The Critical Problem: False Positives Killing Accuracy

### Initial State (The Disaster)
When I first tested the system, **every single HEIC image I uploaded was flagged as CRITICAL/HIGH threat with 95% confidence**. This was catastrophic for a competition where accuracy matters.

**The symptoms:**
- My iPhone photos (HEIC format): "CRITICAL THREAT - 95% confidence"
- Regular JPEG images: "HIGH THREAT - suspicious entropy detected"
- The AI was detecting "iex" (PowerShell's Invoke-Expression) in random binary data

### The Root Causes (After Deep Investigation)

1. **Missing Modern Image Format Support**
   - The system had NO recognition for HEIC, HEIF, or AVIF formats
   - These are Apple's standard photo formats - flagging them as malicious was unacceptable

2. **Naive Binary String Matching**
   - The code was scanning entire binary files for substrings like "iex"
   - Found false positives: Random bytes `0x69 0x65 0x78` spell "iex" in ASCII
   - No contextual awareness - legitimate binary data triggered malware alerts

3. **Extension-Based File Detection (Unreliable)**
   - Used filename extensions to determine file type
   - Easy to bypass: rename `malware.exe` → `photo.jpg`
   - Couldn't handle files with wrong/missing extensions

4. **High Entropy = Suspicious (Wrong for Compressed Files)**
   - Shannon entropy of 7.5-8.0 was flagged as "encrypted/obfuscated"
   - But HEIC/JPEG/PNG naturally have 7-8 entropy due to compression
   - System treated normal compression as malicious encryption

5. **Biased AI Prompts**
   - Sent text like "Header Match: NO - SUSPICIOUS" to Gemini
   - Biased language influenced AI to be overly cautious
   - "Unknown file type" → automatic suspicion

---

## Research Phase: Understanding the Problem Domain

### Question 1: How Do Modern Image Formats Work?

**Research on HEIC/HEIF:**
- HEIC = High Efficiency Image Container (Apple's format since iOS 11)
- Uses HEVC (H.265) compression - extremely efficient
- Built on ISOBMFF (ISO Base Media File Format) container
- **Key finding:** Magic bytes at offset 4, not offset 0 like most formats
- Signature: `ftyp` box containing brand identifiers (`heic`, `heix`, `hevc`, `mif1`)

**Research on AVIF:**
- Next-gen image format using AV1 video compression
- Also ISOBMFF-based with brand `avif` / `avis`
- Even higher compression than HEIC → entropy 7.3-8.0

**Research on Entropy Ranges:**
| Format | Normal Entropy | Why? |
|--------|---------------|------|
| JPEG | 7.0-7.99 | DCT compression |
| PNG | 6.5-7.95 | DEFLATE compression |
| HEIC | 7.2-7.99 | HEVC compression (most efficient) |
| AVIF | 7.3-7.99 | AV1 compression (cutting-edge) |
| BMP | 3.0-7.0 | Uncompressed or light compression |
| PE (unpacked) | 4.0-6.0 | Executable code |
| PE (packed) | 7.0+ | Encrypted/compressed malware |

**Critical insight:** High entropy is NORMAL for media, but ABNORMAL for executables.

### Question 2: How Do Professional Malware Scanners Avoid False Positives?

**Research findings:**
1. **Multi-layer file identification**
   - Don't trust extensions
   - Use magic bytes (file signatures) at various offsets
   - Parse container formats (ZIP, ISOBMFF, RIFF)
   - Validate internal structure

2. **Format-specific baselines**
   - Each file type has expected characteristics
   - Compare observed vs. expected entropy
   - Flag deviations, not absolutes

3. **Context-aware pattern matching**
   - Don't just search for "CreateProcess" anywhere
   - Require surrounding context (function calls, parameters)
   - Exempt known-safe file types from deep scanning

4. **Weighted evidence scoring**
   - No single indicator = verdict
   - Combine multiple weak signals into strong confidence
   - Benign indicators reduce threat score

### Question 3: What Novel Features Win Competitions?

**Research on advanced detection techniques:**

1. **Steganography Detection**
   - Hidden data in images (LSB manipulation, appended data)
   - Chi-square statistical analysis for LSB steganography
   - Detect data after image EOF markers (JPEG EOI, PNG IEND)

2. **Polyglot File Detection**
   - Files valid as multiple formats simultaneously
   - Example: PDF that's also JavaScript (dangerous!)
   - JPEG with embedded PE executable

3. **Embedded Payload Detection**
   - Shellcode patterns (NOP sleds, x86/x64 prologues)
   - Base64-encoded executables
   - PE headers hidden in non-executable files

---

## The Solution: Multi-Stage Analysis Pipeline

### Architecture Decision: Replace Naive Checks with Intelligent Layers

**Before (Simplistic):**
```
File Upload → Check Extension → Calculate Entropy → Send to AI → Result
```

**After (Competition-Grade):**
```
File Upload
  ↓
1. Multi-Layer File Identification (magic bytes, container parsing)
  ↓
2. Metadata Extraction (hash, size, timestamps)
  ↓
3. Baseline-Aware Entropy Analysis (compare to expected ranges)
  ↓
4. Structure Parsing (use validated type, not extension)
  ↓
5. Novel Detection (steganography, polyglot, payloads)
  ↓
6. Local Threat Scoring (weighted indicators)
  ↓
7. AI Analysis (structured data, neutral prompts)
  ↓
8. Final Verdict with Recommendations
```

---

## Implementation: Step-by-Step Thought Process

### Challenge 1: Detecting HEIC Files at Offset 4

**Problem:** Most file formats have magic bytes at offset 0. HEIC is at offset 4.

**Thought process:**
```
Standard approach (offset 0):
FFD8FF = JPEG ✓
89504E47 = PNG ✓

HEIC problem:
Offset 0: Random data
Offset 4: 66747970 (hex for "ftyp") ← The signature!
```

**Solution:**
```typescript
// magic-bytes.ts
export interface MagicSignature {
  signature: string;
  offset: number;  // ← Support arbitrary offsets
  fileType: string;
}

const MAGIC_SIGNATURES: MagicSignature[] = [
  { signature: 'FFD8FF', offset: 0, fileType: 'jpeg' },
  { signature: '66747970', offset: 4, fileType: 'isobmff' }, // ← HEIC!
];

// Check at each signature's specified offset
const segment = buffer.slice(sig.offset, sig.offset + sigBytes.length);
if (segment.equals(sigBytes)) {
  // Match found!
}
```

### Challenge 2: Parsing ISOBMFF Containers

**Problem:** Detecting `ftyp` at offset 4 tells us it's ISOBMFF, but is it HEIC, AVIF, or MP4?

**Thought process:**
```
ISOBMFF structure:
[4 bytes: box size] [4 bytes: box type "ftyp"] [4 bytes: major brand] [brands...]

Example HEIC:
00 00 00 18  ← Box size (24 bytes)
66 74 79 70  ← "ftyp"
68 65 69 63  ← Major brand "heic" ← This tells us it's HEIC!
```

**Solution:**
```typescript
// isobmff-parser.ts
export function parseISOBMFF(buffer: Buffer): ISOBMFFResult {
  // Read ftyp box
  const boxSize = buffer.readUInt32BE(4);
  const majorBrand = buffer.slice(12, 16).toString('ascii');

  // Database of brands
  const brandDatabase = {
    'heic': { type: 'heic', category: 'image' },
    'avif': { type: 'avif', category: 'image' },
    'isom': { type: 'mp4', category: 'video' },
  };

  return brandDatabase[majorBrand];
}
```

### Challenge 3: Format-Specific Entropy Baselines

**Problem:** Need to know what's "normal" for each file type.

**Thought process:**
```
Question: Is entropy 7.8 suspicious?
Answer: It depends!

HEIC file with entropy 7.8 → NORMAL (compression expected)
BMP file with entropy 7.8 → SUSPICIOUS (should be ~5.0)
PE file with entropy 7.8 → SUSPICIOUS (likely packed malware)
```

**Solution:**
```typescript
// format-baselines.ts
export const FORMAT_BASELINES: Record<string, FormatBaseline> = {
  heic: {
    entropy: {
      min: 7.2,
      max: 7.99,
      typical: 7.7,
      explanation: 'HEIC uses HEVC compression which produces very high entropy...'
    },
    riskProfile: {
      canContainExecutable: false,  // Images can't run code
      steganographyRisk: 'medium'   // But can hide data
    }
  },
  pe: {
    entropy: {
      min: 4.0,
      max: 7.8,
      typical: 5.5,
      explanation: 'Unpacked: 4-6, Packed: 7+. High entropy MAY indicate packing.'
    },
    riskProfile: {
      canContainExecutable: true,
      commonAttackVector: true
    }
  }
};
```

### Challenge 4: Weighted Threat Scoring

**Problem:** How to combine multiple indicators into a single, accurate score?

**Thought process:**
```
Example: HEIC photo from iPhone

Positive indicators (reduce threat):
✓ High confidence format match (HEIC, 95%) → -20 points
✓ Entropy within expected range (7.7) → -15 points
✓ Extension matches content (.heic) → -10 points
✓ Known safe format (can't execute code) → -15 points
  Total: -60 points

Negative indicators (increase threat):
(none for legitimate HEIC)
  Total: 0 points

Final score: 50 + (-60 * 0.5) = 20/100 → SAFE ✓
```

**Solution:**
```typescript
// threat-scorer.ts
export function calculateThreatScore(analysis: ComprehensiveAnalysis): ThreatScore {
  const indicators: ThreatIndicator[] = [];

  // Benign indicators
  if (analysis.entropyAnalysis.status === 'normal') {
    indicators.push({
      weight: -15,  // Negative = reduces threat
      confidence: 95,
      description: 'Entropy within expected range'
    });
  }

  // Threat indicators
  if (analysis.fileIdentification.mismatchSeverity === 'critical') {
    indicators.push({
      weight: +80,  // Positive = increases threat
      confidence: 95,
      description: 'Executable disguised as image'
    });
  }

  // Calculate weighted score
  const rawScore = indicators.reduce((sum, ind) =>
    sum + (ind.weight * ind.confidence / 100), 0
  );

  // Normalize to 0-100
  const normalizedScore = 50 + (rawScore * 0.5);

  return { normalizedScore, indicators };
}
```

### Challenge 5: Context-Aware API Detection

**Problem:** "iex" was being found in random binary data.

**Thought process:**
```
False positive example:
Binary data: [0x69, 0x65, 0x78, ...]
As ASCII: "iex..."
Alert: "PowerShell Invoke-Expression detected!" ← WRONG!

True positive example:
Text: "iex (New-Object Net.WebClient).DownloadString(...)"
Context: Full PowerShell command
Alert: "PowerShell Invoke-Expression detected!" ← CORRECT!
```

**Solution:**
```typescript
// structure-parser.ts
const contextualPatterns: { pattern: string; context: RegExp }[] = [
  // Require PowerShell context around 'iex'
  {
    pattern: 'iex',
    context: /\b(iex|Invoke-Expression)\s+[\(\$\-]/  // Must have (, $, or - after
  },
];

// Only alert if context matches
for (const { pattern, context } of contextualPatterns) {
  if (strings.some(str => context.test(str))) {
    found.push(pattern);  // Real threat
  }
}

// Also: Skip deep scanning for media files entirely
if (fileType === 'heic' || fileType === 'jpeg' || ...) {
  return { apis: undefined };  // Don't scan images for code
}
```

### Challenge 6: Structured Data for AI (Not Biased Text)

**Problem:** AI was influenced by biased prompts.

**Before:**
```
Header Match: NO - SUSPICIOUS
Entropy: 7.8 (HIGH - may indicate encryption)
```

**After:**
```json
{
  "typeIdentification": {
    "detectedType": "heic",
    "confidence": "95%",
    "extensionMatchesContent": true,
    "mismatchSeverity": "none"
  },
  "entropyAnalysis": {
    "measured": "7.80",
    "status": "normal",
    "suspicious": false,
    "explanation": "Entropy 7.80 is within expected range (7.2-7.99) for heic..."
  },
  "localThreatScore": {
    "normalizedScore": "18/100",
    "riskLevel": "safe",
    "benignIndicators": ["High Confidence Format Match", "Normal Entropy", ...]
  }
}
```

**Thought process:**
```
Neutral, fact-based presentation:
- No "NO - SUSPICIOUS" language
- Present data, let AI interpret
- Include format-specific context
- Show local threat score as reference
- Emphasize "accuracy over caution"
```

### Challenge 7: Novel Detection Features (Competition Edge)

**Why these matter:**
- Basic scanners check files individually
- Advanced scanners look for *hidden* or *disguised* threats
- These features demonstrate technical depth

**1. Steganography Detection**
```typescript
// Detect hidden data in JPEG
const eoiMarker = buffer.indexOf(Buffer.from([0xFF, 0xD9]));
if (eoiMarker !== -1 && eoiMarker < buffer.length - 2) {
  // Data exists AFTER the end-of-image marker!
  const hiddenData = buffer.slice(eoiMarker + 2);
  return { detected: true, technique: 'JPEG Appended Data' };
}
```

**2. Polyglot Detection**
```typescript
// File that's valid as BOTH PDF and JavaScript
if (isValidPDF(buffer) && isValidJavaScript(buffer)) {
  return {
    isPolyglot: true,
    validFormats: ['PDF', 'JavaScript'],
    securityRisk: 'critical'  // Can bypass filters
  };
}
```

**3. Embedded Payload Detection**
```typescript
// Detect shellcode patterns
const NOP_SLED = Buffer.from([0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
if (buffer.includes(NOP_SLED)) {
  return { type: 'shellcode', confidence: 75 };
}
```

---

## Technical Challenges & Solutions

### Challenge: TypeScript Buffer Type Errors

**Problem:**
```
error TS2591: Cannot find name 'Buffer'. Do you need to install type definitions for node?
```

**Why this happened:**
- Created new TypeScript files without Node.js type definitions
- `tsconfig.json` had `moduleResolution: "bundler"` (incompatible with `types` field)

**Solution:**
```json
// tsconfig.json
{
  "compilerOptions": {
    "types": ["node"],  // Include Node.js types
    "module": "Node16",
    "moduleResolution": "node16"
  }
}
```

### Challenge: Frontend Not Rendering Correctly

**Problem:** Tailwind CSS classes (padding, flex) not working.

**Root cause:**
```css
/* index.css - Global reset was too aggressive */
* {
  margin: 0;
  padding: 0;  /* ← This overrides Tailwind's padding! */
}

body {
  display: flex;
  place-items: center;  /* ← This breaks layout */
}
```

**Solution:** Remove conflicting CSS, let Tailwind handle styling.

---

## Key Architectural Decisions

### Decision 1: Local Threat Scoring + AI (Hybrid Approach)

**Why not AI-only?**
- AI can be biased by prompt wording
- AI has no format-specific knowledge (doesn't know HEIC entropy ranges)
- AI is slow and costs money per request

**Why not rules-only?**
- Rules can't catch novel/zero-day threats
- Rules require constant updating
- Rules can't understand context like AI

**Hybrid solution:**
```
Local Analysis (fast, precise, format-aware)
  ↓ Produces structured data
AI Analysis (contextual, adaptable, catches novel threats)
  ↓
Combined verdict (best of both worlds)
```

### Decision 2: Validate File Type, Don't Trust Extension

**Why this matters:**
```
Attack scenario:
1. Attacker creates malware.exe
2. Renames to vacation_photo.jpg
3. Email filters see .jpg → allowed through
4. User opens → system runs .exe → infected

Defense:
1. Sentinel reads magic bytes → detects PE executable
2. Extension says .jpg, content says .exe
3. Mismatch severity: CRITICAL
4. Alert: "Executable disguised as image"
```

### Decision 3: Multi-Stage Pipeline (Not Monolithic)

**Benefits:**
- Each stage logs its results (debugging visibility)
- Stages can run conditionally (skip media scanning for PDFs)
- Easy to add new stages (e.g., YARA rules, sandbox execution)
- Modular = testable

**Example log output:**
```
🔍 Starting multi-stage analysis for: IMG_7391.HEIC
📋 Stage 1: Multi-layer file identification...
   ✓ Detected type: heic (95% confidence)
   ✓ Category: image
🎲 Stage 3: Baseline-aware entropy analysis...
   ✓ Entropy: 7.75/8.0
   ✓ Status: normal
⚖️  Stage 7: Evidence-based threat scoring...
   ✓ Local Score: 18/100 (SAFE)
   ✓ Benign indicators: 4
   ✓ Risk indicators: 0
🤖 Stage 8: Gemini AI analysis...
   ✓ Gemini Threat Level: SAFE (99% confidence)
✅ Analysis complete
```

---

## Lessons Learned

### 1. **Understand Your Data Before Building Rules**
- I initially flagged high entropy without understanding compression
- Research first, code second

### 2. **Context Matters More Than Patterns**
- Finding "iex" in a binary doesn't mean malware
- Finding "iex (New-Object..." in a script *does*

### 3. **Accuracy > Speed for Competitions**
- Better to take 5 seconds and be correct
- Than 1 second with 50% false positives

### 4. **Weighted Evidence > Binary Rules**
- No single indicator = verdict
- Combine weak signals into strong conclusions

### 5. **Modern Formats Need Modern Detection**
- HEIC/AVIF are standard now (iPhone, Android)
- Systems that don't recognize them will fail

---

## Competition Strategy: Standing Out

### What Makes Sentinel AI Competition-Grade?

1. **Accuracy on Real-World Files**
   - Handles modern formats (HEIC, AVIF, WebP)
   - Low false positive rate
   - Format-specific intelligence

2. **Novel Detection Features**
   - Steganography detection (hidden data)
   - Polyglot detection (multi-format files)
   - Embedded payload hunting (shellcode, Base64 PE)

3. **Explainable AI**
   - Shows *why* a verdict was reached
   - Lists benign vs. risk indicators
   - Transparent scoring system

4. **Professional Architecture**
   - Multi-stage pipeline
   - Modular design
   - Comprehensive logging

---

## Future Enhancements (Post-Competition)

1. **Dynamic Analysis**
   - Sandbox execution (run suspicious files in VM)
   - Monitor behavior (file writes, network calls)

2. **YARA Rule Integration**
   - Community malware signatures
   - Custom rule creation

3. **Machine Learning Model**
   - Train on malware datasets
   - Complement AI with specialized model

4. **Threat Intelligence Integration**
   - Check file hashes against known malware databases
   - VirusTotal API integration

---

## Conclusion

Building Sentinel AI taught me that **effective malware detection isn't about checking boxes—it's about understanding file formats at a deep level, recognizing that context matters, and combining multiple weak signals into strong conclusions**.

The journey from "flags every HEIC as malware" to "accurately detects real threats while recognizing legitimate files" required:
- Deep research into file formats
- Understanding entropy and compression
- Learning from professional security tools
- Iterative refinement based on real failures

The result: A competition-grade system that demonstrates technical depth, novel features, and real-world accuracy.

---

**Project Status:** ✅ Core detection pipeline complete, TypeScript compilation issues being resolved, frontend visualization components pending.

**Time Investment:** ~15 hours of development + research

**Technologies:** TypeScript, Node.js, Express, Google Gemini AI, React, Tailwind CSS
