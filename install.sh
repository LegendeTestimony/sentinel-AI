#!/bin/bash

echo "========================================"
echo "Installing Sentinel AI Dependencies"
echo "========================================"
echo ""

echo "[1/4] Installing root dependencies..."
npm install || { echo "Error installing root dependencies"; exit 1; }
echo ""

echo "[2/4] Installing frontend dependencies..."
cd frontend
npm install || { echo "Error installing frontend dependencies"; cd ..; exit 1; }
cd ..
echo ""

echo "[3/4] Installing backend dependencies..."
cd backend
npm install || { echo "Error installing backend dependencies"; cd ..; exit 1; }
cd ..
echo ""

echo "[4/4] Setting up environment files..."
if [ ! -f "backend/.env" ]; then
    cp backend/.env.example backend/.env
    echo "Created backend/.env - PLEASE ADD YOUR GEMINI_API_KEY"
else
    echo "backend/.env already exists, skipping..."
fi

if [ ! -f "frontend/.env" ]; then
    cp frontend/.env.example frontend/.env
    echo "Created frontend/.env"
else
    echo "frontend/.env already exists, skipping..."
fi
echo ""

echo "========================================"
echo "Installation Complete!"
echo "========================================"
echo ""
echo "IMPORTANT: Edit backend/.env and add your Gemini API key"
echo "Get your API key from: https://aistudio.google.com/app/apikey"
echo ""
echo "To start the application:"
echo "  npm run dev"
echo ""
