# How Frontend & Backend Connect (CORS Explained)

## The Connection Flow

```
Browser (localhost:3000)          Backend Server (localhost:5050)
         │                                    │
         │  1. User uploads file              │
         ├──────────────────────────────────> │
         │  POST /api/analyze                 │
         │  Origin: http://localhost:3000     │
         │                                    │
         │  2. Backend checks CORS            │
         │     Is origin allowed? ✓           │
         │                                    │
         │  3. Response with CORS headers     │
         │ <────────────────────────────────  │
         │  Access-Control-Allow-Origin: ...  │
         │  {analysis results}                │
         │                                    │
```

## What is CORS?

**CORS (Cross-Origin Resource Sharing)** is a security feature that prevents malicious websites from making unauthorized requests to your API.

### Without CORS:

```
❌ Browser blocks the request
   Error: "CORS policy: No 'Access-Control-Allow-Origin' header"
```

### With CORS:

```
✅ Backend says "I allow requests from http://localhost:3000"
   Browser allows the connection
```

## Your Current Setup

### Backend (server.ts)

```typescript
const corsOptions = {
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
```

### Environment Variable (.env)

```env
FRONTEND_URL=http://localhost:3000
```

## How It Works

1. **Frontend makes request:**

   ```typescript
   // Frontend: sentinelApi.ts
   const response = await api.post("/analyze", formData);
   ```

2. **Browser adds Origin header:**

   ```
   POST http://localhost:5050/api/analyze
   Origin: http://localhost:3000
   ```

3. **Backend checks CORS:**

   ```typescript
   // Backend checks if Origin matches corsOptions.origin
   if (origin === "http://localhost:3000") {
     // ✅ Allow the request
   }
   ```

4. **Backend responds with CORS headers:**

   ```
   Access-Control-Allow-Origin: http://localhost:3000
   Access-Control-Allow-Credentials: true
   Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
   ```

5. **Browser allows the response through**

## Different Environments

### Development (what you're using now)

```env
# Backend .env
FRONTEND_URL=http://localhost:3000

# Frontend .env
VITE_API_URL=http://localhost:5050/api
```

### Production Example

```env
# Backend .env
FRONTEND_URL=https://sentinel-ai.vercel.app

# Frontend .env
VITE_API_URL=https://sentinel-api.yourdomain.com/api
```

## Why You Need CORS

### Security Example:

**Without CORS:**

```
❌ Evil website (malicious.com) could:
   1. Trick user into visiting their site
   2. Make requests to YOUR backend
   3. Steal data or perform actions
```

**With CORS:**

```
✅ Your backend only accepts requests from:
   - http://localhost:3000 (development)
   - https://your-frontend.com (production)

   Requests from malicious.com → BLOCKED
```

## Testing CORS

### Test in Browser Console

```javascript
// Open DevTools → Console on http://localhost:3000
fetch("http://localhost:5050/api/health")
  .then((r) => r.json())
  .then(console.log)
  .catch(console.error);

// ✅ Should work (same origin in CORS config)
```

```javascript
// Try from a different origin (e.g., github.com console)
fetch("http://localhost:5050/api/health")
  .then((r) => r.json())
  .then(console.log)
  .catch(console.error);

// ❌ Should fail (blocked by CORS)
// Error: No 'Access-Control-Allow-Origin' header
```

## Common CORS Issues

### Issue 1: CORS error after changing frontend URL

**Problem:** Frontend deployed to new URL, backend still allows old URL

**Solution:**

```env
# Update backend/.env
FRONTEND_URL=https://new-frontend-url.com
```

### Issue 2: Preflight requests failing

**Problem:** Browser sends OPTIONS request before POST

**Solution:** Already handled in your config:

```typescript
methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
```

### Issue 3: Credentials not working

**Problem:** Cookies/auth headers not sent

**Solution:** Already configured:

```typescript
credentials: true,  // Allows cookies/auth headers
```

## Network Tab Inspection

Open DevTools → Network tab when making a request:

### Request Headers:

```
Origin: http://localhost:3000
Content-Type: multipart/form-data
```

### Response Headers (from backend):

```
Access-Control-Allow-Origin: http://localhost:3000
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
```

If you DON'T see these headers, CORS is not configured!

## Multiple Frontend Origins (Advanced)

If you need to allow multiple frontends:

```typescript
const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = [
      "http://localhost:3000",
      "http://localhost:5173", // Vite default
      "https://sentinel-ai.vercel.app",
      "https://staging.sentinel-ai.vercel.app",
    ];

    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
};
```

## Summary

**Your backend DOES have CORS configured!**

✅ **Location:** `backend/src/server.ts` line 26-34  
✅ **Allows:** `http://localhost:3000` (from FRONTEND_URL env var)  
✅ **Configured for:** Development and production

The backend "knows" to connect to the frontend because:

1. Frontend makes HTTP requests to `http://localhost:5050/api`
2. Backend checks the `Origin` header in each request
3. If origin matches `FRONTEND_URL`, request is allowed
4. Backend sends back CORS headers to permit the response

**No explicit "connection" is needed** - it's HTTP request/response with CORS validation!
