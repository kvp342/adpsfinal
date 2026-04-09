@echo off
setlocal EnableExtensions
set "ROOT=%~dp0"
echo Checking environment...

where /q npm.cmd
if errorlevel 1 goto :no_node

echo Starting Frontend...
cd /d "%ROOT%frontend"
if errorlevel 1 goto :no_frontend_dir

call npm.cmd install
if errorlevel 1 goto :npm_failed

call npm.cmd run dev -- --host 0.0.0.0 --port 5173
if not "%~1"=="--no-pause" pause
exit /b 0

:no_node
echo Error: Node.js (npm) is not installed or not in your PATH.
echo Install Node.js from https://nodejs.org/
pause
exit /b 1

:no_frontend_dir
echo Error: Could not find the 'frontend' folder.
pause
exit /b 1

:npm_failed
echo Error: npm install failed.
pause
exit /b 1

