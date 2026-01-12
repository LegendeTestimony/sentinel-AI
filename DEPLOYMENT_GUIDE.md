# Backend Deployment Guide (Render)

## Why You Need This

Your frontend is on Vercel, but the BACKEND must be deployed separately because:
- Vercel is for **static sites/serverless** (frontend)
- Your backend needs **persistent processes** (Marathon Mode runs for hours)
- Backend has file system access, background processes, etc.

## Deploy Backend to Render

### 1. Create render.yaml (for easy deployment)

Create this file in the **backend** folder:

```yaml
# render.yaml
services:
  - type: web
    name: sentinel-ai-backend
    env: node
    region: oregon
    plan: free
    buildCommand: npm install && npm run build
    startCommand: npm start
    envVars:
      - key: NODE_ENV
        value: production
      - key: PORT
        value: 10000
      - key: GEMINI_API_KEY
        sync: false
      - key: VIRUSTOTAL_API_KEY
        sync: false
      - key: FRONTEND_URL
        sync: false
```

### 2. Push to GitHub

```bash
git add backend/render.yaml
git commit -m "Add Render deployment config"
git push
```

### 3. Deploy on Render

1. Go to https://render.com (sign up/login)
2. Click "New +" → "Web Service"
3. Connect your GitHub repo: `LegendeTestimony/sentinel-AI`
4. Configure:
   - **Name**: sentinel-ai-backend
   - **Root Directory**: `backend`
   - **Environment**: Node
   - **Build Command**: `npm install && npm run build`
   - **Start Command**: `npm start`

5. Add Environment Variables:
   ```
   GEMINI_API_KEY=your_key_here
   VIRUSTOTAL_API_KEY=your_key_here
   FRONTEND_URL=https://sentinel-ai-by-legend.vercel.app
   NODE_ENV=production
   PORT=10000
   ```

6. Click "Create Web Service"

### 4. Get Your Backend URL

After deployment, Render gives you a URL like:
```
https://sentinel-ai-backend-xxxx.onrender.com
```

### 5. Update Frontend .env

Create `frontend/.env.production`:
```env
VITE_API_URL=https://sentinel-ai-backend-xxxx.onrender.com/api
```

Update `frontend/.env` for local dev:
```env
VITE_API_URL=http://localhost:5050/api
```

### 6. Redeploy Frontend on Vercel

```bash
cd frontend
git add .env.production
git commit -m "Add production API URL"
git push
```

Vercel will auto-redeploy and use the production URL.

## Testing

1. **Backend health check**: Visit `https://sentinel-ai-backend-xxxx.onrender.com/api/health`
   - Should return: `{"status":"ok","timestamp":...}`

2. **Frontend**: Visit `https://sentinel-ai-by-legend.vercel.app`
   - Upload a file
   - Should work now! ✅

## Free Tier Limitations

Render Free Tier:
- ⚠️ Spins down after 15 minutes of inactivity
- First request after sleep takes ~30 seconds
- Good for demos/testing
- For production, upgrade to paid plan ($7/month)

## Alternative: Railway

If Render is slow, try Railway:
1. Go to https://railway.app
2. "New Project" → "Deploy from GitHub"
3. Select your repo, set root directory to `backend`
4. Add same environment variables
5. Deploy!

## Troubleshooting

### CORS Error After Deployment
Update backend `.env`:
```env
FRONTEND_URL=https://sentinel-ai-by-legend.vercel.app
```

### 502 Bad Gateway
- Backend is starting up (wait 30 seconds)
- Check Render logs for errors

### Still Getting 404
Check Network tab:
- Request URL should be: `https://your-backend.onrender.com/api/analyze`
- NOT: `https://sentinel-ai-by-legend.vercel.app/api/analyze`
