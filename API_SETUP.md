# API Communication Setup

## How Frontend & Backend Communicate

### Architecture Overview

```
Frontend (React)          Backend (Express)
Port: 3000               Port: 5050
│                        │
├─ .env                  ├─ .env
│  VITE_API_URL=...     │  PORT=5050
│                        │  GEMINI_API_KEY=...
├─ sentinelApi.ts       ├─ server.ts
│  (Axios client)       │  (Express routes)
└─ Components           └─ API endpoints
   └─ MarathonPage.tsx     ├─ /api/analyze
                           ├─ /api/analyze-url
                           ├─ /api/marathon/start
                           ├─ /api/marathon/stop
                           └─ /api/marathon/status
```

## Environment Variables

### Frontend (.env)

```env
VITE_API_URL=http://localhost:5050/api
```

### Backend (.env)

```env
PORT=5050
GEMINI_API_KEY=your_gemini_api_key
NODE_ENV=development
MAX_FILE_SIZE=10485760
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

## API Endpoints

### File Analysis

- **POST** `/api/analyze` - Upload file for analysis
- **POST** `/api/analyze-url` - Analyze URL

### Marathon Mode

- **POST** `/api/marathon/start` - Start continuous monitoring

  ```json
  {
    "watchPath": "C:/Users/YourName/Downloads",
    "duration": 3600000
  }
  ```

- **POST** `/api/marathon/stop` - Stop monitoring
- **GET** `/api/marathon/status` - Get real-time metrics
  ```json
  {
    "running": true,
    "metrics": {
      "filesAnalyzed": 5,
      "threatsDetected": 2,
      "quarantined": 1,
      "uptime": 120,
      "recentAnalyses": [...]
    }
  }
  ```

## How It Works

### 1. Frontend API Client (sentinelApi.ts)

```typescript
const API_BASE_URL = import.meta.env.VITE_API_URL || "/api";

const api = axios.create({
  baseURL: API_BASE_URL, // http://localhost:5050/api
  headers: {
    "Content-Type": "application/json",
  },
});
```

### 2. Components Use the API

```typescript
import sentinelApi from "../api/sentinelApi";

// Start Marathon Mode
const data = await sentinelApi.startMarathon(path, duration);

// Get status (polls every 2 seconds)
const status = await sentinelApi.getMarathonStatus();
```

### 3. Backend Receives Requests

```typescript
// server.ts
app.post("/api/marathon/start", async (req, res) => {
  const { watchPath, duration } = req.body;
  // Start marathon agent...
});
```

## Testing the Connection

### 1. Start Backend

```bash
cd backend
npm run dev
```

Should see: `✅ Server running on http://localhost:5050`

### 2. Start Frontend

```bash
cd frontend
npm run dev
```

Should see: `Local: http://localhost:3000`

### 3. Check Network Tab

- Open browser DevTools → Network tab
- Start Marathon Mode
- Look for: `http://localhost:5050/api/marathon/start`
- Response should be: `{ success: true, message: "..." }`

## Common Issues

### CORS Errors

Backend has CORS enabled for localhost:

```typescript
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);
```

### Port Conflicts

- Backend: `PORT=5050` in `backend/.env`
- Frontend: `VITE_API_URL=http://localhost:5050/api` in `frontend/.env`

### Environment Variables Not Loading

**Frontend:** Restart dev server after changing `.env`

- Vite only reads env vars on startup
- Must prefix with `VITE_` to expose to browser

**Backend:** Restart server after changing `.env`

## Production Deployment

For production, update frontend `.env`:

```env
VITE_API_URL=https://your-backend.com/api
```

Backend should set proper CORS origins:

```typescript
app.use(
  cors({
    origin: "https://your-frontend.com",
    credentials: true,
  })
);
```
