@echo off
echo Installing dependencies...

:: Check if npm is available
where npm >nul 2>nul
if errorlevel 1 (
    echo "npm is not installed or not added to PATH. Please install Node.js first."
    pause
    exit /b
)

:: Install npm dependencies
npm install

if errorlevel 1 (
    echo "An error occurred during npm install. Please check the logs above for more details."
    pause
    exit /b
)

echo Dependencies installed successfully!
echo.
echo To load the extension in Chrome:
echo 1. Open Chrome and go to chrome://extensions/
echo 2. Enable Developer Mode (toggle in the top-right corner).
echo 3. Click Load Unpacked and select this folder.
pause
exit /b

