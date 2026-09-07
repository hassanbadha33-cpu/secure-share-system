@echo off
cd /d "%~dp0"
echo Secure Share Email OTP Setup
echo.
if not exist node_modules (
  echo Installing required packages...
  npm install
)
npm run setup:email
pause
