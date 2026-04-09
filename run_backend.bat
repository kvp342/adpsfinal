@echo off
setlocal EnableExtensions
set "ROOT=%~dp0"
set "TOOLS=%ROOT%.tools"
set "MAVEN_VERSION=3.9.6"
set "MAVEN_DIR=%TOOLS%\apache-maven-%MAVEN_VERSION%"

echo Preparing backend...

if exist "%MAVEN_DIR%\bin\mvn.cmd" goto :have_maven

echo Maven not found. Downloading Maven %MAVEN_VERSION%...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "$tools='%TOOLS%';" ^
  "New-Item -ItemType Directory -Force -Path $tools | Out-Null;" ^
  "$zip=Join-Path $tools 'apache-maven-%MAVEN_VERSION%-bin.zip';" ^
  "Invoke-WebRequest -Uri 'https://archive.apache.org/dist/maven/maven-3/%MAVEN_VERSION%/binaries/apache-maven-%MAVEN_VERSION%-bin.zip' -OutFile $zip;" ^
  "Write-Host ('Downloaded: ' + $zip);"
if errorlevel 1 goto :download_failed

echo Extracting Maven...
pushd "%TOOLS%"
where /q jar.exe
if errorlevel 1 goto :jar_missing
jar xf "apache-maven-%MAVEN_VERSION%-bin.zip"
if errorlevel 1 goto :extract_failed
del /q "apache-maven-%MAVEN_VERSION%-bin.zip" >nul 2>nul
popd

:have_maven

cd /d "%ROOT%backend"

if "%~1"=="--check" (
  call "%MAVEN_DIR%\bin\mvn.cmd" -version
  exit /b %ERRORLEVEL%
)

echo Starting Backend (using H2 Database)...
if not exist "%ROOT%backend\logs" mkdir "%ROOT%backend\logs" >nul 2>nul
echo Writing backend logs to: %ROOT%backend\logs\backend-startup.log
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "& '%MAVEN_DIR%\bin\mvn.cmd' -U clean spring-boot:run -e 2>&1 | Tee-Object -FilePath '%ROOT%backend\logs\backend-startup.log'" 
set "RC=%ERRORLEVEL%"
IF NOT "%~1"=="--no-pause" pause
exit /b %RC%

:download_failed
echo Failed to download Maven. Please check your internet connection.
pause
exit /b 1

:jar_missing
popd
echo Error: jar.exe not found. Please ensure Java JDK is installed and on PATH.
pause
exit /b 1

:extract_failed
popd
echo Failed to extract Maven zip.
pause
exit /b 1
