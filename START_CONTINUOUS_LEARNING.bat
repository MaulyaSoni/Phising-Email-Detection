@echo off
echo ============================================================
echo ULTIMATE PHISHING DETECTION SYSTEM WITH CONTINUOUS LEARNING
echo ============================================================
echo.
echo Features:
echo - Advanced phishing detection (96.35%% accuracy)
echo - Mathematical consistency fixes applied
echo - Continuous learning from user feedback
echo - Automatic model retraining
echo - Real-time performance monitoring
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
echo Creating data directory for continuous learning...
if not exist "data" mkdir data

echo.
echo Starting Ultimate Phishing Detection System...
echo.
echo ============================================================
echo CONTINUOUS LEARNING FEATURES:
echo - User feedback collection: Correct/Incorrect buttons
echo - Automatic retraining every 50 examples
echo - Model versioning and performance tracking
echo - Training statistics dashboard
echo - Manual retraining triggers
echo ============================================================
echo.
echo Web interface: http://localhost:5000
echo API endpoints:
echo   /predict        - Analyze emails
echo   /feedback       - Submit user corrections
echo   /training_stats - View learning statistics
echo   /manual_retrain - Trigger retraining
echo   /model_info     - Model information
echo.
echo Press Ctrl+C to stop the server
echo ============================================================
echo.

python ultimate_app.py

pause
