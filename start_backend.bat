@echo off
title AI Phishing Detective - Backend

echo ================================
echo Starting MongoDB Server...
echo ================================

start cmd /k "C:\Program Files\MongoDB\Server\7.0\bin\mongod.exe"

timeout /t 5

echo ================================
echo Starting FastAPI Backend...
echo ================================

cd /d E:\ai-phishing-backend
start cmd /k uvicorn app:app --reload

echo ================================
echo Backend Started Successfully
echo ================================

pause
