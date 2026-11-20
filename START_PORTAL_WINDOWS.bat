
@echo off
setlocal
cd /d "%~dp0"

echo.
echo ================================================
echo          VulnScope - Employee Portal
echo ================================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo Creating Python virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 goto :fail
)

".venv\Scripts\python.exe" -c "import flask,requests" >nul 2>&1

if errorlevel 1 (
    echo Installing Python dependencies...
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 goto :fail
)

for /f "delims=" %%A in ('.venv\Scripts\python.exe -c "import secrets;print(secrets.token_hex(32))"') do set "VULNSCOPE_SECRET_KEY=%%A"

if not defined VULNSCOPE_SECRET_KEY goto :fail

echo Opening VulnScope at http://127.0.0.1:5000/
echo Keep this window open while using the portal.
echo.

".venv\Scripts\python.exe" "app\app.py"

echo.
echo Flask stopped.
pause
exit /b 0

:fail
echo.
echo Setup failed. Please review the error above.
pause
exit /b 1
