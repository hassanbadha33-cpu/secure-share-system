@echo off
cd /d "%~dp0"
echo Starting Secure Share System...
echo.
if not exist node_modules (
  echo Installing required packages...
  npm install
)
node server.js
pause
