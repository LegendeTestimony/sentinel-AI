#!/usr/bin/env node
/**
 * Marathon Mode Demo Script
 * Demonstrates continuous autonomous monitoring
 *
 * Usage: npm run marathon-demo
 */

import { MarathonAgent } from "./src/services/marathon-agent.js";
import * as path from "path";
import { fileURLToPath } from "url";
import * as fs from "fs/promises";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function setupDemoEnvironment() {
  const watchPath = path.join(__dirname, "marathon-demo-watch");

  // Create watch directory
  await fs.mkdir(watchPath, { recursive: true });

  console.log("📁 Demo environment created at:", watchPath);
  console.log("");
  console.log("To test the marathon agent:");
  console.log("1. Drop files into the marathon-demo-watch/ directory");
  console.log("2. Watch as the agent automatically analyzes them");
  console.log("3. Suspicious files will be moved to .quarantine/");
  console.log("");

  return watchPath;
}

async function main() {
  console.log("🏃 ===== SENTINEL MARATHON MODE DEMO =====\n");

  // Setup demo environment
  const watchPath = await setupDemoEnvironment();

  // Create marathon agent
  const agent = new MarathonAgent({
    watchPath,
    checkInterval: 5000, // Check every 5 seconds
    maxRuntime: 30 * 60 * 1000, // Run for 30 minutes (demo duration)
    learningEnabled: true,
    autoQuarantine: true,
    reportInterval: 60 * 1000, // Report every minute
  });

  // Handle graceful shutdown
  process.on("SIGINT", async () => {
    console.log("\n\n⚠️  Received shutdown signal...");
    await agent.stop();
    process.exit(0);
  });

  // Start marathon
  await agent.start();

  console.log("💡 TIP: Press Ctrl+C to stop the marathon agent");
}

main().catch((error) => {
  console.error("❌ Demo failed:", error);
  process.exit(1);
});
