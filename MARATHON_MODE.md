# 🏃 Marathon Mode - Autonomous Continuous Security Monitoring

**Built for the Gemini 3 Hackathon - Marathon Agent Track**

Sentinel's Marathon Mode transforms it from a one-shot analyzer into an **autonomous security agent that runs for hours, days, or weeks** - continuously monitoring, learning, and responding to threats without human intervention.

---

## 🎯 What is Marathon Mode?

Marathon Mode is Sentinel's implementation of the "Marathon Agent" track requirements:

### Action Era Capabilities

- ✅ **Multi-day autonomous operation** - Runs continuously without stopping
- ✅ **Self-correction loops** - Iterative analysis with multiple investigation stages
- ✅ **Continuous learning** - Adjusts threat baselines based on historical patterns
- ✅ **Long-running workflows** - Each file goes through 6+ investigation stages
- ✅ **No human supervision** - Fully autonomous decision-making and quarantining

### Unlike Traditional Scanners

| Traditional AV    | Sentinel Marathon Mode                            |
| ----------------- | ------------------------------------------------- |
| Scan → Done       | Scan → Investigate → Learn → Act → Repeat Forever |
| One-shot analysis | Multi-stage investigation loops                   |
| Static signatures | Dynamic learning baselines                        |
| Manual quarantine | Autonomous threat response                        |
| No memory         | Historical context awareness                      |

---

## 🚀 Quick Start

### Option 1: Demo Mode (Standalone)

```bash
cd backend
npm install
npm run marathon-demo
```

The agent will:

1. Create a `marathon-demo-watch/` directory
2. Monitor it continuously
3. Analyze any files you drop in
4. Auto-quarantine suspicious files to `.quarantine/`
5. Generate status reports every minute
6. Learn and adjust baselines over time

**Drop test files** into `marathon-demo-watch/` and watch the agent work!

### Option 2: API Mode (With Frontend)

**Start backend:**

```bash
cd backend
npm run dev
```

**Start marathon via API:**

```bash
curl -X POST http://localhost:5050/api/marathon/start \
  -H "Content-Type: application/json" \
  -d '{
    "watchPath": "/path/to/monitor",
    "duration": 3600000
  }'
```

**Check status:**

```bash
curl http://localhost:5050/api/marathon/status
```

**Stop marathon:**

```bash
curl -X POST http://localhost:5050/api/marathon/stop
```

---

## 🧠 How It Works - The Investigation Loop

When a file appears, Sentinel runs a **6-stage autonomous investigation**:

### Stage 1: Initial Quick Scan

- File type identification
- Magic byte validation
- Entropy measurement
- Quick threat assessment

### Stage 2: Suspicion Detection

```
IF (threat_level >= MEDIUM):
    → Proceed to deep investigation
ELSE:
    → Mark as benign, log and continue
```

### Stage 3: Deep Investigation (Self-Correction Loop)

Runs multiple analysis iterations:

- **Iteration 1**: Check for false positive indicators
- **Iteration 2**: Cross-reference with learned baselines
- **Iteration 3**: Validate with external sources (VirusTotal if enabled)
- **Iteration 4+**: Additional passes if evidence is contradictory

### Stage 4: Learning Application

- Compares result with historical baseline for this file type
- Adjusts expected entropy ranges
- Updates suspicious pattern database
- Increases confidence in baseline predictions
- **Tracks learning iterations** (shows autonomous improvement)

Example:

```
Before:  PNG expected entropy: 6.5-7.8
After:   PNG expected entropy: 6.4-7.9 (adjusted after 47 samples)
Confidence: 92%
```

### Stage 5: Final Decision with Reasoning

Multi-factor decision making:

```javascript
shouldQuarantine =
  (threatLevel === 'CRITICAL' && confidence > 70%) ||
  (threatLevel === 'HIGH' && confidence > 85%) ||
  (baseline_deviation > 2.0 && historical_false_positive_rate < 10%)
```

### Stage 6: Autonomous Action

If quarantine threshold met:

- Move file to `.quarantine/` directory
- Generate detailed investigation report
- Update metrics
- Log decision reasoning
- Continue monitoring without interruption

---

## 📊 Real-Time Metrics & Reporting

The agent generates status reports at configurable intervals:

```
📊 ===== MARATHON AGENT STATUS REPORT =====
⏱️  Uptime: 14h 37m
📁 Files Analyzed: 1,247
⚠️  Threats Detected: 23
🔒 Quarantined: 18
🧠 Learning Iterations: 891
📈 Threat Baselines: 47 file types tracked
==========================================
```

### Metrics Tracked

- **Uptime** - Total runtime in hours/minutes
- **Files Analyzed** - Total files processed
- **Threats Detected** - Files flagged as HIGH/CRITICAL
- **Quarantined** - Files autonomously isolated
- **Learning Iterations** - Number of baseline adjustments
- **Threat Baselines** - File types with learned patterns
- **False Positive Rate** - Tracks accuracy over time

---

## 🎓 Learning & Self-Improvement

Marathon Mode implements **continuous learning** without human feedback:

### Baseline Learning Algorithm

1. **Initial State**: No baselines, conservative defaults
2. **Observation**: Analyze file, record entropy and patterns
3. **Baseline Creation**: If file type unknown, create initial baseline
4. **Baseline Refinement**: Each new sample adjusts expected ranges
5. **Confidence Growth**: Baseline confidence increases with sample size

### Example Learning Session

```
File: image_001.heic
Initial: Unknown format, entropy 7.8 → SUSPICIOUS (60% confidence)

[10 more HEIC files analyzed...]

File: image_012.heic
Learned: HEIC format, entropy 7.75 → NORMAL (89% confidence)
Baseline: 7.2-7.99 expected (based on 12 samples)
```

### Self-Correction in Action

```
File: document.pdf (entropy: 4.2)
Stage 1: LOW threat (entropy seems normal)
Stage 2: Deep investigation triggered (unusual for PDF)
Stage 3: Cross-reference → PDF average entropy is 5.8
Stage 4: ADJUST → File likely compressed legitimately
Final: SAFE with note "Below baseline but validated"
```

---

## 🔧 Configuration Options

```typescript
const marathonAgent = new MarathonAgent({
  watchPath: "/path/to/monitor", // Directory to watch
  checkInterval: 5000, // Check frequency (ms)
  maxRuntime: undefined, // Run forever if undefined
  learningEnabled: true, // Enable baseline learning
  autoQuarantine: true, // Autonomous threat isolation
  reportInterval: 60000, // Status report frequency (ms)
});
```

### For Hackathon Demo

```javascript
{
  watchPath: './demo-files',
  maxRuntime: 3600000,  // 1 hour demo
  reportInterval: 30000  // Report every 30s for visibility
}
```

### For Production

```javascript
{
  watchPath: '/var/monitor',
  maxRuntime: undefined,  // Never stop
  reportInterval: 3600000  // Report hourly
}
```

---

## 🎬 Demo Scenarios

### Scenario 1: Malware Sample Testing

```bash
# Start marathon
npm run marathon-demo

# In another terminal, drop malware samples
cp ~/malware-samples/*.exe backend/marathon-demo-watch/

# Watch the agent:
# - Analyze each file (Stage 1)
# - Trigger deep investigation (Stage 2-3)
# - Quarantine threats (Stage 6)
# - Generate reports
```

### Scenario 2: False Positive Learning

```bash
# Drop 50 legitimate HEIC photos
cp ~/iPhone-photos/*.heic backend/marathon-demo-watch/

# Watch the agent learn:
# Iteration 1: Some flagged as SUSPICIOUS
# Iteration 5: HEIC baseline established
# Iteration 10: 95% confidence, all marked SAFE
```

### Scenario 3: Extended Operation

```bash
# Run for 24 hours
MARATHON_DURATION=86400000 npm run marathon-demo

# Check metrics periodically
curl http://localhost:5050/api/marathon/status

# Observe:
# - Files analyzed over 24h
# - Learning improvements
# - Threat detection patterns
# - Uptime stability
```

---

## 📈 Why This Fits "Marathon Agent" Track

### ✅ Requirements Met

**1. Autonomous Multi-Day Operation**

- Runs indefinitely or for configured duration
- No human intervention required
- Continuous monitoring without pause

**2. Self-Correction Loops**

- 6-stage investigation per file
- Iterative analysis with contradiction handling
- Baseline adjustments based on new data

**3. Long-Running Workflows**

- Each file: 6 stages × multiple iterations = dozens of AI calls
- Learning loops that span hours/days
- Historical context maintained across sessions

**4. Complex Tool Orchestration**

- File system monitoring (chokidar)
- Static analysis (magic bytes, entropy, structure)
- Multi-agent AI debate (Gemini 3 Flash)
- External validation (VirusTotal)
- Autonomous actions (quarantine, reporting)

**5. No "Single Prompt" Solutions**

- Not a wrapper around one Gemini call
- Complex orchestration of multiple subsystems
- State management across investigation loops

---

## 🎯 Hackathon Demo Tips

### What to Show Judges

1. **Start Marathon Mode** - Show autonomous startup
2. **Drop Malware Samples** - Demonstrate threat detection
3. **Show Status Reports** - Real-time metrics
4. **Demonstrate Learning** - Drop similar files, show baseline growth
5. **Check Quarantine** - Show autonomous threat isolation
6. **Long Runtime** - Emphasize it runs for days, not seconds

### Key Talking Points

- "Unlike one-shot analyzers, Sentinel runs continuously"
- "Each file goes through a 6-stage investigation loop"
- "It learns from every file, improving accuracy over time"
- "Fully autonomous - no human decisions needed"
- "Can run for days/weeks, maintaining context"
- "Self-corrects when evidence is contradictory"

### Metrics to Highlight

- **Uptime**: Show it's been running for hours/days
- **Learning Iterations**: Proof of continuous improvement
- **Baseline Count**: Number of file types learned
- **Threat Detection**: Successful quarantines
- **False Positive Reduction**: Show learning effectiveness

---

## 🚀 Next Steps for Production

Current demo is a **proof of concept**. For production:

1. **Persistent Storage**: Save baselines to database
2. **Distributed Monitoring**: Watch multiple directories
3. **Advanced Learning**: ML-based threat prediction
4. **Human Feedback Loop**: Analyst can mark false positives
5. **Cloud Integration**: S3/Drive monitoring
6. **Real-time Alerts**: Slack/email notifications
7. **Web Dashboard**: Live metrics visualization

---

## 📝 Code Example: Starting Marathon Mode

```typescript
import { MarathonAgent } from "./services/marathon-agent";

const agent = new MarathonAgent({
  watchPath: "/var/sentinel/monitor",
  checkInterval: 5000,
  learningEnabled: true,
  autoQuarantine: true,
  reportInterval: 60000,
});

// Start continuous monitoring
await agent.start();

// Agent now runs autonomously, will:
// - Monitor directory continuously
// - Analyze new/modified files
// - Run multi-stage investigations
// - Learn from patterns
// - Quarantine threats
// - Generate periodic reports
// - Self-correct when needed

// Runs until manually stopped or max runtime reached
```

---

## 🏆 Marathon Mode = Action Era

This is what the hackathon asked for:

> "Build autonomous systems for tasks spanning hours or days. Use Thought Signatures and Thinking Levels to maintain continuity and self-correct across multi-step tool calls without human supervision."

**Sentinel Marathon Mode delivers exactly that.** ✅

---

Built with ❤️ for the Gemini 3 Global Hackathon
