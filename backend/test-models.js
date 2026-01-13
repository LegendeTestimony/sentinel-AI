/**
 * Test which Gemini models are available with your API key
 */

import { GoogleGenerativeAI } from "@google/generative-ai";
import dotenv from "dotenv";

dotenv.config();

const API_KEY = process.env.GEMINI_API_KEY;

if (!API_KEY) {
  console.error("❌ No GEMINI_API_KEY found in .env");
  process.exit(1);
}

const genAI = new GoogleGenerativeAI(API_KEY);

const modelsToTest = [
  "gemini-1.5-flash",
  "gemini-1.5-pro",
  "gemini-2.0-flash-exp",
  "gemini-pro",
  "gemini-pro-vision",
];

console.log("🔍 Testing Gemini API models...\n");
console.log(`API Key: ${API_KEY.substring(0, 20)}...\n`);

async function testModel(modelName) {
  try {
    const model = genAI.getGenerativeModel({ model: modelName });

    const result = await model.generateContent('Say "OK" if you work');
    const response = await result.response;
    const text = response.text();

    console.log(`✅ ${modelName}: WORKING`);
    console.log(`   Response: ${text}\n`);
    return true;
  } catch (error) {
    if (error.status === 429) {
      console.log(`⏱️  ${modelName}: QUOTA EXCEEDED (429)`);
      console.log(`   Message: ${error.message.split("\n")[0]}\n`);
    } else if (error.status === 404) {
      console.log(`❌ ${modelName}: NOT FOUND (404)\n`);
    } else if (error.status === 400) {
      console.log(`⚠️  ${modelName}: BAD REQUEST (400)`);
      console.log(`   Message: ${error.message.split("\n")[0]}\n`);
    } else {
      console.log(`❌ ${modelName}: ERROR (${error.status || "unknown"})`);
      console.log(`   Message: ${error.message.split("\n")[0]}\n`);
    }
    return false;
  }
}

async function listAvailableModels() {
  console.log("📋 Attempting to list all available models...\n");
  try {
    const models = await genAI.listModels();
    console.log("✅ Available models:");
    models.forEach((model) => {
      console.log(`   - ${model.name}`);
      console.log(
        `     Support: ${model.supportedGenerationMethods.join(", ")}`
      );
      console.log(`     Input token limit: ${model.inputTokenLimit}`);
      console.log(`     Output token limit: ${model.outputTokenLimit}\n`);
    });
  } catch (error) {
    console.log(`❌ Could not list models: ${error.message}\n`);
  }
}

async function main() {
  // Test specific models
  console.log("═══════════════════════════════════════════\n");
  console.log("Testing specific models:\n");
  console.log("═══════════════════════════════════════════\n");

  const workingModels = [];

  for (const modelName of modelsToTest) {
    const works = await testModel(modelName);
    if (works) workingModels.push(modelName);
    await new Promise((resolve) => setTimeout(resolve, 1000)); // Wait 1s between tests
  }

  console.log("═══════════════════════════════════════════\n");
  await listAvailableModels();
  console.log("═══════════════════════════════════════════\n");

  // Summary
  console.log("📊 SUMMARY:\n");
  if (workingModels.length > 0) {
    console.log(`✅ Working models (${workingModels.length}):`);
    workingModels.forEach((model) => console.log(`   - ${model}`));
    console.log(
      `\n💡 Recommendation: Use "${workingModels[0]}" in your config\n`
    );
  } else {
    console.log("❌ No working models found. Possible issues:");
    console.log("   1. API key is invalid");
    console.log("   2. All quotas exceeded (wait 24 hours)");
    console.log("   3. API key doesn't have access to these models\n");
  }

  console.log("═══════════════════════════════════════════\n");
  console.log(
    "📈 Check your quota at: https://aistudio.google.com/app/apikey\n"
  );
  console.log(
    "📚 Rate limits: https://ai.google.dev/gemini-api/docs/rate-limits\n"
  );
}

main().catch(console.error);
