# 🚀 Quick Setup Guide

This guide will get Sentinel up and running in minutes.

## Step 1: Install Dependencies

```bash
# Install root dependencies
npm install

# Install frontend dependencies
cd frontend
npm install

# Install backend dependencies
cd ../backend
npm install
cd ..
```

## Step 2: Set Up Environment Variables

### Backend Configuration

1. Navigate to the backend directory:
```bash
cd backend
```

2. Copy the example environment file:
```bash
cp .env.example .env
```

3. Edit the `.env` file and add your Gemini API key:
```env
PORT=5000
GEMINI_API_KEY=YOUR_ACTUAL_API_KEY_HERE
NODE_ENV=development
MAX_FILE_SIZE=10485760
```

**Get your Gemini API key from:** https://aistudio.google.com/app/apikey

### Frontend Configuration (Optional)

The frontend is pre-configured to work with the backend. If needed, create `frontend/.env`:

```env
VITE_API_URL=/api
```

## Step 3: Run the Application

### Option 1: Run Both (Recommended)

From the root directory:
```bash
npm run dev
```

This starts both frontend and backend simultaneously.

### Option 2: Run Separately

**Terminal 1 - Backend:**
```bash
cd backend
npm run dev
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

## Step 4: Access the Application

- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:5000
- **Health Check:** http://localhost:5000/api/health

## 🧪 Testing the Setup

1. Open http://localhost:3000 in your browser
2. You should see the Sentinel interface
3. Upload a test file (any file type works)
4. Click "Analyze Threat"
5. Watch the analysis pipeline run
6. View the threat analysis results

## 🐛 Troubleshooting

### Backend won't start

- **Error: GEMINI_API_KEY not set**
  - Make sure you created `backend/.env` and added your API key

- **Port 5000 already in use**
  - Change the PORT in `backend/.env` to another port (e.g., 5001)
  - Update the frontend proxy in `frontend/vite.config.ts`

### Frontend won't start

- **Port 3000 already in use**
  - The frontend will automatically use port 3001 or next available

### Dependencies won't install

- Make sure you're using Node.js 18 or higher:
  ```bash
  node --version
  ```

## 📂 Project Structure

```
sentinel-AI/
├── frontend/
│   ├── src/
│   │   ├── components/      # React components
│   │   ├── hooks/           # Custom React hooks
│   │   ├── types/           # TypeScript types
│   │   └── api/             # API client
│   └── package.json
│
├── backend/
│   ├── src/
│   │   ├── analyzers/       # File analysis modules
│   │   ├── services/        # Gemini AI integration
│   │   ├── config/          # Prompts and config
│   │   └── server.ts        # Express server
│   └── package.json
│
└── package.json            # Monorepo root
```

## 🔑 API Endpoints

- `GET /api/health` - Health check
- `POST /api/analyze` - Analyze file (multipart/form-data)

## 🎯 Next Steps

1. ✅ Get your Gemini API key
2. ✅ Install dependencies
3. ✅ Set up `.env` file
4. ✅ Run the application
5. 🎨 Customize the UI (optional)
6. 🧪 Create demo files for testing
7. 📹 Record your demo video

## 💡 Tips

- Use legitimate files for SAFE analysis
- Create suspicious files (double extensions, obfuscated scripts) for demo
- The AI will explain its reasoning - use this to showcase explainability
- High entropy files (encrypted/packed) trigger more detailed analysis

---

**Need help?** Check the main [README.md](README.md) for detailed documentation.
