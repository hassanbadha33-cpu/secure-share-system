@echo off
cd /d "%~dp0"
echo Testing Secure Share email OTP settings...
echo.
npm run check:email
pause
