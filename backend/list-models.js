import { GoogleGenerativeAI } from '@google/generative-ai';
import dotenv from 'dotenv';
import https from 'https';

dotenv.config();

const API_KEY = process.env.GEMINI_API_KEY;

console.log('🔑 API Key:', API_KEY ? `${API_KEY.substring(0, 15)}...` : 'NOT FOUND');
console.log('');

// Try direct API call to list models
async function listModelsDirectly() {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'generativelanguage.googleapis.com',
      path: `/v1/models?key=${API_KEY}`,
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    };

    const req = https.request(options, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        if (res.statusCode === 200) {
          resolve(JSON.parse(data));
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.end();
  });
}

async function testModels() {
  try {
    console.log('🔍 Fetching models via direct API call...\n');

    const response = await listModelsDirectly();

    if (response.models) {
      console.log('✅ Available models:\n');

      const textModels = response.models.filter(m =>
        m.supportedGenerationMethods?.includes('generateContent')
      );

      textModels.forEach(model => {
        console.log(`📦 ${model.name}`);
        console.log(`   Display: ${model.displayName}`);
        console.log(`   Methods: ${model.supportedGenerationMethods?.join(', ')}`);
        console.log('');
      });

      // Try the first available model
      if (textModels.length > 0) {
        const modelName = textModels[0].name.replace('models/', '');
        console.log(`\n🧪 Testing model: ${modelName}\n`);

        const genAI = new GoogleGenerativeAI(API_KEY);
        const model = genAI.getGenerativeModel({ model: modelName });

        const result = await model.generateContent('Say hello');
        const text = result.response.text();

        console.log(`✅ Success! Response: ${text.substring(0, 50)}...`);
        console.log(`\n✨ Use this model name: "${modelName}"`);
      }
    }
  } catch (error) {
    console.error('❌ Error:', error.message);

    if (error.message.includes('403') || error.message.includes('API key')) {
      console.log('\n⚠️  API Key issue detected!');
      console.log('   1. Make sure the API key is valid');
      console.log('   2. Enable "Generative Language API" in Google Cloud Console');
      console.log('   3. Visit: https://aistudio.google.com/app/apikey');
    }
  }
}

testModels();
