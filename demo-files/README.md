# 🧪 Sentinel AI Demo Test Files

This folder contains **safe test files** specifically designed to demonstrate Sentinel AI's malware detection capabilities. All files are **completely harmless** but contain patterns that appear suspicious to security analysis systems.

## 📁 File Descriptions

### 1. `suspicious-script.ps1`
**Purpose**: Demonstrates PowerShell script analysis
**Triggers**:
- ✅ Base64 encoding detection
- ✅ Suspicious API calls (Invoke-WebRequest, Invoke-Expression, etc.)
- ✅ Registry modification patterns
- ✅ File operation patterns
- ✅ Obfuscation-like variable names
- ✅ Multiple encoding layers

**Expected Verdict**: HIGH or CRITICAL threat (due to multiple suspicious patterns)
**Actual Behavior**: Just prints safe messages to console

---

### 2. `eicar-test.txt`
**Purpose**: Industry-standard antivirus test file
**Triggers**:
- ✅ VirusTotal detection (70+ engines flag it)
- ✅ Known malware signature pattern

**Expected Verdict**: CRITICAL threat (VirusTotal will detect it)
**Actual Behavior**: Completely harmless, recognized test file (EICAR standard)

**Note**: This is the **official** test file used by the antivirus industry. See: https://www.eicar.org/

---

### 3. `high-entropy-test.bin`
**Purpose**: Tests entropy analysis and encryption detection
**Triggers**:
- ✅ Very high Shannon entropy (7.5+)
- ✅ Random-looking data pattern
- ✅ Appears encrypted/compressed

**Expected Verdict**: MEDIUM to HIGH (depending on context awareness)
**Actual Behavior**: Just contains Unicode characters arranged in patterns

---

### 4. `obfuscated-script.js`
**Purpose**: Demonstrates JavaScript obfuscation detection
**Triggers**:
- ✅ Hexadecimal string encoding (\x48\x65...)
- ✅ String.fromCharCode patterns
- ✅ Base64-like encoding
- ✅ Suspicious function names (_0xExecute, _0xDownload, _0xInject)
- ✅ Eval-like patterns
- ✅ Dynamic property access
- ✅ Suspicious comments (C2, payload, exfiltration)

**Expected Verdict**: HIGH threat (heavy obfuscation)
**Actual Behavior**: Just prints "Hello World" and "Demo" to console

---

## 🎬 Demo Usage

### Quick Test
```bash
# Start backend
cd backend
npm run dev

# In browser, go to http://localhost:5173
# Upload files from demo-files/ folder
```

### Recommended Demo Order

1. **Start with EICAR** (`eicar-test.txt`)
   - Shows VirusTotal integration
   - Instant CRITICAL verdict
   - Establishes credibility

2. **Then suspicious PowerShell** (`suspicious-script.ps1`)
   - Shows full 11-stage pipeline
   - Demonstrates AI behavioral reasoning
   - Multiple detection stages trigger

3. **Show context awareness** (upload a real HEIC photo)
   - High entropy but marked SAFE
   - Proves Sentinel understands context
   - Not just flagging everything

4. **Obfuscated JavaScript** (`obfuscated-script.js`)
   - Shows pattern detection capabilities
   - May trigger multi-agent debate
   - Demonstrates sophistication

5. **High entropy binary** (`high-entropy-test.bin`)
   - Tests entropy baseline analysis
   - Shows statistical detection
   - Good for technical audience

---

## ⚠️ Safety Notes

- ✅ **All files are 100% safe**
- ✅ **No actual malicious code**
- ✅ **Safe to run/execute** (though no need to)
- ✅ **Only contain patterns that LOOK suspicious**

These files will:
- ❌ NOT harm your computer
- ❌ NOT download anything
- ❌ NOT modify system files
- ❌ NOT connect to networks
- ✅ Only trigger detection patterns in security tools

---

## 🔬 Technical Details

### How They Work

1. **Pattern Matching**: Files contain keywords like "Invoke-WebRequest", "registry", "download" that pattern matchers flag
2. **Entropy Analysis**: Some files have high randomness that appears encrypted
3. **Encoding Detection**: Base64 and hex encoding trigger obfuscation alerts
4. **Behavioral Keywords**: Function names and comments suggest malicious intent
5. **API Detection**: References to suspicious APIs (even in comments) get flagged

### What Sentinel Detects

- **Stage 1-3**: File type, metadata, entropy
- **Stage 4**: Patterns (shellcode, Base64, APIs)
- **Stage 5**: Threat scoring (combines all indicators)
- **Stage 6**: AI behavioral prediction (what WOULD happen if executed)
- **Stage 6.5**: Multi-agent debate (for uncertain cases)
- **Stage 7-11**: Advanced detection (steganography, polyglot, VirusTotal, sandbox prediction)

---

## 📊 Expected Results

| File | Threat Level | Confidence | Triggers |
|------|--------------|------------|----------|
| `suspicious-script.ps1` | HIGH/CRITICAL | 85-95% | Base64, APIs, Registry, Obfuscation |
| `eicar-test.txt` | CRITICAL | 100% | VirusTotal (70+ engines) |
| `high-entropy-test.bin` | MEDIUM/HIGH | 70-80% | Very high entropy (7.5+) |
| `obfuscated-script.js` | HIGH | 80-90% | Hex encoding, eval, suspicious names |

---

## 🎯 Demo Tips

### Talking Points

**When showing suspicious-script.ps1:**
> "Notice it detected Base64 encoding, suspicious API calls, and registry operations. But here's the key - Gemini doesn't just list these. Watch the reasoning: 'If executed, this would decode data, contact a remote server, and modify system settings.' It's predicting behavior, not just pattern matching."

**When showing EICAR:**
> "This is the industry standard test file. VirusTotal's 70+ antivirus engines all flag it. But they rely on signatures - they KNOW this exact string. Our AI reasoning works on never-before-seen threats too."

**When showing high entropy:**
> "Entropy of 7.8 - that's usually encrypted malware. But context matters. If this were a HEIC photo, Sentinel would mark it SAFE because it knows HEIC normally has high entropy. That's format-aware analysis."

**When showing obfuscated JS:**
> "Heavy obfuscation - hex encoding, base64, suspicious function names like '_0xExecute' and '_0xDownload'. The AI predicts this would execute dynamic code and make network requests. This is exactly how real malware obfuscates."

---

## 🚨 Important

**These files are for DEMONSTRATION PURPOSES ONLY.**

- Created specifically for Sentinel AI demos
- Designed to trigger detection systems safely
- All patterns are harmless implementations
- Perfect for security research and testing

**Do NOT:**
- Use these patterns in production code
- Combine with actual malicious logic
- Distribute without this README

**When presenting:**
- Always disclose these are demo files
- Explain they're safe but appear suspicious
- Show the actual code to prove harmlessness
- Use to demonstrate detection capabilities

---

## 📝 Credits

Created for **Sentinel AI** - Gemini 3 Global Hackathon
Demo files designed to showcase AI-powered threat detection
All files are original creations for educational purposes

---

Built with ❤️ by **Legend Testimony**
