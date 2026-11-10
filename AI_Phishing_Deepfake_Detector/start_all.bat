@echo off
setlocal
cd /d "%~dp0"

if not defined CHAT_PORT set "CHAT_PORT=5001"
if not defined DETECTOR_PORT set "DETECTOR_PORT=8502"
set "PORTAL_CHAT_URL=http://127.0.0.1:%CHAT_PORT%"
set "DETECTOR_URL=http://127.0.0.1:%DETECTOR_PORT%/"

start "Local threat analysis sign-in and chat" "%ComSpec%" /k ""%~dp0e2ee_chat\start_server.bat""
start "Local phishing and deepfake detector" "%ComSpec%" /k ""%~dp0start_detector.bat""

timeout /t 3 /nobreak >nul
start "" "%PORTAL_CHAT_URL%/"
