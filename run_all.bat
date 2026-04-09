@echo off
set "ROOT=%~dp0"
echo Starting backend and frontend in separate windows...
start "Backend" cmd /k call "%ROOT%run_backend.bat"
start "Frontend" cmd /k call "%ROOT%run_frontend.bat"
