@echo off
echo ========================================
echo Installing Sentinel AI Dependencies
echo ========================================
echo.

echo [1/4] Installing root dependencies...
call npm install
if %ERRORLEVEL% NEQ 0 (
    echo Error installing root dependencies
    pause
    exit /b 1
)
echo.

echo [2/4] Installing frontend dependencies...
cd frontend
call npm install
if %ERRORLEVEL% NEQ 0 (
    echo Error installing frontend dependencies
    cd ..
    pause
    exit /b 1
)
cd ..
echo.

echo [3/4] Installing backend dependencies...
cd backend
call npm install
if %ERRORLEVEL% NEQ 0 (
    echo Error installing backend dependencies
    cd ..
    pause
    exit /b 1
)
cd ..
echo.

echo [4/4] Setting up environment files...
if not exist "backend\.env" (
    copy "backend\.env.example" "backend\.env"
    echo Created backend\.env - PLEASE ADD YOUR GEMINI_API_KEY
) else (
    echo backend\.env already exists, skipping...
)

if not exist "frontend\.env" (
    copy "frontend\.env.example" "frontend\.env"
    echo Created frontend\.env
) else (
    echo frontend\.env already exists, skipping...
)
echo.

echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo IMPORTANT: Edit backend\.env and add your Gemini API key
echo Get your API key from: https://aistudio.google.com/app/apikey
echo.
echo To start the application:
echo   npm run dev
echo.
pause
