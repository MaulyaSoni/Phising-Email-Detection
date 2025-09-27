@echo off
echo ============================================================
echo FINAL PROJECT CLEANUP - REMOVING UNNECESSARY FILES
echo ============================================================
echo This will delete duplicate and unused files to optimize the project
echo.
pause

echo Removing duplicate templates...
if exist "templates\" rmdir /s /q "templates\"

echo Removing old startup scripts...
if exist "START.bat" del "START.bat"
if exist "START_ENHANCED.bat" del "START_ENHANCED.bat"
if exist "phishing_detector\start.bat" del "phishing_detector\start.bat"

echo Removing Python cache files...
if exist "phishing_detector\src\__pycache__\" rmdir /s /q "phishing_detector\src\__pycache__\"

echo Removing duplicate documentation...
if exist "README.md" del "README.md"
if exist "phishing_detector\README.md" del "phishing_detector\README.md"
if exist "FINAL_SUMMARY.md" del "FINAL_SUMMARY.md"

echo Removing analysis files...
if exist "eda_analysis.png" del "eda_analysis.png"

echo Removing empty folders...
if exist "phishing_detector\data\" rmdir /q "phishing_detector\data\" 2>nul
if exist "phishing_detector\static\" rmdir /q "phishing_detector\static\" 2>nul
if exist "phishing_detector\tests\" rmdir /q "phishing_detector\tests\" 2>nul

echo.
echo ============================================================
echo CLEANUP COMPLETE!
echo ============================================================
echo.
echo FINAL OPTIMIZED STRUCTURE:
echo phishing_detector/
echo ├── src/ultimate_model.py          # Best ML model
echo ├── web/ultimate_app.py            # Web application  
echo ├── scripts/train_ultimate_model.py # Training script
echo ├── models/ultimate_phishing_model.pkl # Trained model
echo ├── templates/index.html           # Web interface
echo ├── test_model.py                  # Testing script
echo └── requirements.txt               # Dependencies
echo.
echo Root files:
echo ├── START_ULTIMATE.bat             # Startup script
echo ├── FINAL_PROJECT_SUMMARY.md       # Documentation
echo ├── requirements.txt               # Main dependencies
echo └── FINAL_CLEANUP.bat              # This cleanup script
echo.
echo Project is now fully optimized for production use!
echo.
pause
