import { GoogleGenerativeAI } from '@google/generative-ai';
import dotenv from 'dotenv';

dotenv.config();

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

async function listAllModels() {
  try {
    console.log('📋 Trying different model names...\n');
    
    const modelsToTest = [
      'gemini-pro',
      'gemini-1.5-pro',
      'gemini-1.5-flash',
      'gemini-1.5-flash-8b',
      'gemini-2.0-flash-exp',
      'models/gemini-pro',
      'models/gemini-1.5-pro',
      'models/gemini-1.5-flash',
      'models/gemini-1.5-flash-8b',
      'models/gemini-2.0-flash-exp',
    ];
    
    for (const modelName of modelsToTest) {
      try {
        console.log(`Testing: ${modelName}...`);
        const model = genAI.getGenerativeModel({ model: modelName });
        const result = await model.generateContent('Say "OK"');
        const response = await result.response;
        console.log(`  ✅ ${modelName} - WORKS! Response: ${response.text()}`);
      } catch (error) {
        console.log(`  ❌ ${modelName} - ${error.message.split('\n')[0]}`);
      }
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  }
}

listAllModels();
