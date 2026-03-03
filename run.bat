@echo off
echo ============================================
echo   Packet Analyzer Web UI
echo ============================================
echo.

:: Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

:: Install Flask if not already installed
echo Checking dependencies...
pip show flask >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing Flask...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo ERROR: Failed to install Flask.
        pause
        exit /b 1
    )
)

echo.
echo Starting server at http://127.0.0.1:5000
echo Press Ctrl+C to stop.
echo.
start "" http://127.0.0.1:5000
python server.py
pause
