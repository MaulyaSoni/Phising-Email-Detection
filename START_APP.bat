@echo off
echo ============================================================
echo PHISHING DETECTION SYSTEM - DARK MODE EDITION
echo ============================================================
echo.

cd /d "%~dp0phishing_detector\web"

echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python and try again
    pause
    exit /b 1
)

echo Checking required packages...
python -c "import flask, sklearn, pandas, numpy, joblib" >nul 2>&1
if errorlevel 1 (
    echo Installing required packages...
    pip install flask scikit-learn pandas numpy joblib
)

echo.
echo Starting Phishing Detection System...
echo Web interface will be available at: http://localhost:5000
echo.
echo Press Ctrl+C to stop the server
echo ============================================================
echo.

python ultimate_app.py

pause
