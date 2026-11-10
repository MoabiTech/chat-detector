@echo off
setlocal
cd /d "%~dp0"

set "PYTHON=.venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=..\.venv\Scripts\python.exe"
if not exist "%PYTHON%" (
    echo Missing virtual environment. Create one and install requirements.txt first.
    exit /b 1
)

if exist ".venv\Scripts\python.exe" if exist "..\.venv\Scripts\python.exe" (
    "..\.venv\Scripts\python.exe" -c "import streamlit" >nul 2>&1
    if not errorlevel 1 set "PYTHON=..\.venv\Scripts\python.exe"
)
"%PYTHON%" -c "import streamlit" >nul 2>&1
if errorlevel 1 (
    echo Streamlit is missing from "%PYTHON%". Install requirements.txt in this environment first.
    exit /b 1
)

if not defined DETECTOR_AUDIO_MODEL_CACHE if exist "D:\" set "DETECTOR_AUDIO_MODEL_CACHE=D:\detector\hf-cache"
if defined DETECTOR_AUDIO_MODEL_CACHE if not defined HF_XET_CACHE set "HF_XET_CACHE=%DETECTOR_AUDIO_MODEL_CACHE%\xet"
if defined DETECTOR_AUDIO_MODEL_CACHE if not exist "%DETECTOR_AUDIO_MODEL_CACHE%" (
    mkdir "%DETECTOR_AUDIO_MODEL_CACHE%"
    if errorlevel 1 (
        echo Could not create the configured audio model cache directory.
        exit /b 1
    )
)
if defined HF_XET_CACHE if not exist "%HF_XET_CACHE%" (
    mkdir "%HF_XET_CACHE%"
    if errorlevel 1 (
        echo Could not create the configured Xet cache directory.
        exit /b 1
    )
)
if not defined DETECTOR_AUDIO_TEMP_DIR if exist "D:\" set "DETECTOR_AUDIO_TEMP_DIR=D:\detector\tmp"
if defined DETECTOR_AUDIO_TEMP_DIR if not exist "%DETECTOR_AUDIO_TEMP_DIR%" (
    mkdir "%DETECTOR_AUDIO_TEMP_DIR%"
    if errorlevel 1 (
        echo Could not create the configured audio temporary directory.
        exit /b 1
    )
)

if not defined DETECTOR_FFMPEG_RUNTIME if exist "D:\detector\ffmpeg-runtime\imageio_ffmpeg" set "DETECTOR_FFMPEG_RUNTIME=D:\detector\ffmpeg-runtime"
if defined DETECTOR_FFMPEG_RUNTIME if exist "%DETECTOR_FFMPEG_RUNTIME%\imageio_ffmpeg" (
    if defined PYTHONPATH (
        set "PYTHONPATH=%DETECTOR_FFMPEG_RUNTIME%;%PYTHONPATH%"
    ) else (
        set "PYTHONPATH=%DETECTOR_FFMPEG_RUNTIME%"
    )
)

if not defined DETECTOR_PORT set "DETECTOR_PORT=8502"
set "PORT_ARGS=--server.port %DETECTOR_PORT%"
"%PYTHON%" -m streamlit run app.py --server.address 127.0.0.1 --server.maxUploadSize 50 --server.headless true %PORT_ARGS%
if errorlevel 1 pause
